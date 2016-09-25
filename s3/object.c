/*
 * ProFTPD - mod_aws S3 Object API
 * Copyright (c) 2016 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 */

#include "mod_aws.h"
#include "utils.h"
#include "http.h"
#include "s3/conn.h"
#include "s3/error.h"
#include "s3/object.h"

static const char *trace_channel = "aws.s3.object";

struct object_reader {
  pool *pool;
  const char *bucket_name;
  const char *object_key;
  off_t offset;
  int (*consume_data)(pool *, void *, off_t, off_t);
};

static size_t object_body(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct object_reader *reader;
  size_t datasz;
  int res;

  reader = user_data;

  datasz = item_sz * item_count;
  if (datasz == 0) {
    return 0;
  }

  pr_trace_msg(trace_channel, 15,
    "downloaded %lu bytes of object %s from bucket %s", (unsigned long) datasz,
    reader->object_key, reader->bucket_name);

  res = (reader->consume_data)(reader->pool, data, reader->offset, datasz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 4,
      "download of object %s from bucket %s aborted: %s", reader->object_key,
      reader->bucket_name, strerror(errno));

    /* Note: If consuming of this data does fail, curl will close the
     * connection.  This, in turn, means that we might need to have some
     * way of opening a new one, if/when needed.
     *
     * Since we don't consume the whole response body, there isn't a good
     * way for libcurl to continue reading (and ignoring) the rest of that
     * data, which means that there isn't a good way to keep the connection
     * in a known good state.  Sigh.
     */

    return 0;
  }

  reader->offset += datasz;
  return datasz;
}

static int copy_object_metadata(pool *p, const char *object_key,
    pr_table_t *object_metadata, pr_table_t *resp_headers) {
  const void *k;

  if (object_metadata == NULL) {
    return 0;
  }

  (void) pr_table_rewind(resp_headers);

  k = pr_table_next(resp_headers);
  while (k != NULL) {
    const void *v;
    size_t vlen;

    pr_signals_handle();

    if (strcasecmp(k, AWS_S3_OBJECT_METADATA_SIZE) == 0 ||
        strcasecmp(k, AWS_S3_OBJECT_METADATA_MTIME) == 0 ||
        strcasecmp(k, AWS_S3_OBJECT_METADATA_STORAGE_CLASS) == 0) {
      v = pr_table_get(resp_headers, k, &vlen);
      if (v != NULL) {
        pr_trace_msg(trace_channel, 9, "object %s metadata: %s = %.*s",
          object_key, k, (int) vlen, v);
        pr_table_add(object_metadata, pstrdup(p, k),
          pstrndup(p, v, vlen), 0);
      }

    } else if (strncasecmp(k, AWS_S3_OBJECT_METADATA_PREFIX,
        AWS_S3_OBJECT_METADATA_PREFIX_LEN) == 0) {
      v = pr_table_get(resp_headers, k, &vlen);
      if (v != NULL) {
        /* Skip past the key prefix, for legibility. */
        k = ((char *) k) + AWS_S3_OBJECT_METADATA_PREFIX_LEN;
        pr_trace_msg(trace_channel, 9, "object %s metadata: %s = %.*s",
          object_key, k, (int) vlen, v);
        pr_table_add(object_metadata, pstrdup(p, k),
          pstrndup(p, v, vlen), 0);
      }
    }

    k = pr_table_next(resp_headers);
  }

  return 0;
}

int aws_s3_object_get(pool *p, struct s3_conn *s3, const char *bucket_name,
    const char *object_key, off_t object_offset, off_t object_len,
    pr_table_t *object_metadata,
    int (*consume_data)(pool *p, void *data, off_t data_offset, off_t data_len)) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *req_headers, *resp_headers = NULL;
  struct object_reader *reader;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_key == NULL ||
      consume_data == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  req_headers = pr_table_alloc(s3->req_pool, 0);
  if (object_offset > 0 ||
      object_len > 0) {
    char *range = NULL;

    if (object_offset > 0) {
      if (object_len > 0) {
        /* Range: bytes=off-(off+len-1) */
        range = pstrcat(s3->req_pool, "bytes=",
          aws_utils_str_off2s(s3->req_pool, object_offset), "-",
          aws_utils_str_off2s(s3->req_pool, object_offset + object_len - 1),
          NULL);

      } else {
        /* Range: bytes=off- */
        range = pstrcat(s3->req_pool, "bytes=",
          aws_utils_str_off2s(s3->req_pool, object_offset), "-", NULL);
      }

    } else {
      /* Range: bytes=0-(len-1) */
      range = pstrcat(s3->req_pool, "bytes=0-",
        aws_utils_str_off2s(s3->req_pool, object_len-1), NULL);
    }

    pr_table_add(req_headers, pstrdup(s3->req_pool, AWS_HTTP_HEADER_RANGE),
      range, 0);
  }

  path = pstrcat(req_pool,
    "/", aws_http_urlencode(req_pool, s3->http, bucket_name, 0),
    "/", aws_http_urlencode(req_pool, s3->http, object_key, 0), NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  if (object_metadata != NULL) {
    resp_headers = pr_table_alloc(s3->req_pool, 0);
  }

  reader = pcalloc(req_pool, sizeof(struct object_reader));
  reader->pool = s3->req_pool;
  reader->bucket_name = bucket_name;
  reader->object_key = object_key;
  reader->offset = object_offset;
  reader->consume_data = consume_data;

  res = aws_s3_get(p, s3->http, req_headers, path, query_params, resp_headers,
    object_body, reader, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully downloaded object %s from bucket %s", object_key,
      bucket_name);

    if (resp_headers != NULL) {
      if (pr_trace_get_level(trace_channel) >= 17) {
        pr_trace_msg(trace_channel, 17, "object %s response header count: %d",
          object_key, pr_table_count(resp_headers));
      }
    }

    copy_object_metadata(p, object_key, object_metadata, resp_headers);
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}

int aws_s3_object_stat(pool *p, struct s3_conn *s3, const char *bucket_name,
    const char *object_key, pr_table_t *object_metadata) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *resp_headers = NULL;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_key == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  path = pstrcat(req_pool,
    "/", aws_http_urlencode(req_pool, s3->http, bucket_name, 0),
    "/", aws_http_urlencode(req_pool, s3->http, object_key, 0), NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  if (object_metadata != NULL) {
    resp_headers = pr_table_alloc(s3->req_pool, 0);
  }

  res = aws_s3_head(p, s3->http, NULL, path, query_params, resp_headers, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully checked object %s in bucket %s", object_key, bucket_name);

    if (resp_headers != NULL) {
      if (pr_trace_get_level(trace_channel) >= 17) {
        pr_trace_msg(trace_channel, 17, "object %s response header count: %d",
          object_key, pr_table_count(resp_headers));
      }
    }

    copy_object_metadata(p, object_key, object_metadata, resp_headers);
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}

int aws_s3_object_delete(pool *p, struct s3_conn *s3, const char *bucket_name,
    const char *object_key) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_key == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  path = pstrcat(req_pool,
    "/", aws_http_urlencode(req_pool, s3->http, bucket_name, 0),
    "/", aws_http_urlencode(req_pool, s3->http, object_key, 0), NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = aws_s3_delete(p, s3->http, NULL, path, query_params, NULL, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully deleted object %s from bucket %s", object_key, bucket_name);
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}
