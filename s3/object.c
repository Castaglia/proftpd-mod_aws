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
#include "xml.h"
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

/* Tells the metadata copying function to skip any S3 system attributes. */
#define AWS_S3_OBJECT_COPY_METADATA_FL_IGNORE_SYSTEM_ATTRS	0x001

static int copy_object_metadata(pool *p, const char *object_key,
    pr_table_t *dst_object_metadata, pr_table_t *src_object_metadata,
    int flags) {
  const void *k;

  if (dst_object_metadata == NULL) {
    return 0;
  }

  (void) pr_table_rewind(src_object_metadata);

  k = pr_table_next(src_object_metadata);
  while (k != NULL) {
    const void *v;
    size_t vlen;

    pr_signals_handle();

    if (!(flags & AWS_S3_OBJECT_COPY_METADATA_FL_IGNORE_SYSTEM_ATTRS) &&
        (strcasecmp(k, AWS_S3_OBJECT_METADATA_SIZE) == 0 ||
         strcasecmp(k, AWS_S3_OBJECT_METADATA_MTIME) == 0 ||
         strcasecmp(k, AWS_S3_OBJECT_METADATA_STORAGE_CLASS) == 0)) {
      v = pr_table_get(src_object_metadata, k, &vlen);
      if (v != NULL) {
        pr_trace_msg(trace_channel, 9, "object %s metadata: %s = %.*s",
          object_key, (char *) k, (int) vlen, (char *) v);
        pr_table_add(dst_object_metadata, pstrdup(p, k),
          pstrndup(p, v, vlen), 0);
      }

    } else if (strncasecmp(k, AWS_S3_OBJECT_METADATA_PREFIX,
        AWS_S3_OBJECT_METADATA_PREFIX_LEN) == 0) {
      v = pr_table_get(src_object_metadata, k, &vlen);
      if (v != NULL) {
        /* Skip past the key prefix, for legibility. */
        k = ((char *) k) + AWS_S3_OBJECT_METADATA_PREFIX_LEN;
        pr_trace_msg(trace_channel, 9, "object %s metadata: %s = %.*s",
          object_key, (char *) k, (int) vlen, (char *) v);
        pr_table_add(dst_object_metadata, pstrdup(p, k),
          pstrndup(p, v, vlen), 0);
      }
    }

    k = pr_table_next(src_object_metadata);
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

    copy_object_metadata(p, object_key, object_metadata, resp_headers, 0);
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

    copy_object_metadata(p, object_key, object_metadata, resp_headers, 0);
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

static size_t copy_object_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct s3_conn *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->respsz == 0) {
    info->respsz = datasz;
    ptr = info->resp = palloc(info->req_pool, info->respsz);

  } else {
    ptr = info->resp;
    info->resp = palloc(info->req_pool, info->respsz + datasz);
    memcpy(info->resp, ptr, info->respsz);

    ptr = info->resp + info->respsz;
    info->respsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int parse_copy_object(pool *p, const char *data, size_t datasz,
    time_t *last_modified, const char **etag) {
  void *doc, *root, *elt;
  const char *elt_name;
  size_t elt_namelen;

  doc = aws_xml_doc_parse(p, data, (int) datasz);
  if (doc == NULL) {
    errno = EINVAL;
    return -1;
  }

  root = aws_xml_doc_get_root_elt(p, doc);
  if (root == NULL) {
    /* Malformed XML. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return -1;
  }

  elt_name = aws_xml_elt_get_name(p, root, &elt_namelen);
  if (elt_namelen != 16 ||
      strncmp(elt_name, "CopyObjectResult", elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return -1;
  }

  elt = aws_xml_elt_get_child(p, root, "LastModified", 12);
  if (elt != NULL) {
    *last_modified = aws_http_date2unix(p, aws_xml_elt_get_text(p, elt));
  }

  elt = aws_xml_elt_get_child(p, root, "ETag", 4);
  if (elt != NULL) {
    *etag = aws_xml_elt_get_text(p, elt);
  }

  return 0;
}

int aws_s3_object_copy(pool *p, struct s3_conn *s3,
    const char *src_bucket_name, const char *src_object_key,
    const char *dst_bucket_name, const char *dst_object_key,
    pr_table_t *dst_object_metadata) {
  int res, xerrno;
  const char *src_path, *dst_path, *metadata_directive;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *req_headers;

  if (p == NULL ||
      s3 == NULL ||
      src_bucket_name == NULL ||
      src_object_key == NULL ||
      dst_bucket_name == NULL ||
      dst_object_key == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  req_headers = pr_table_alloc(s3->req_pool, 0);

  src_path = pstrcat(req_pool,
    "/", aws_http_urlencode(req_pool, s3->http, src_bucket_name, 0),
    "/", aws_http_urlencode(req_pool, s3->http, src_object_key, 0), NULL);
  pr_table_add(req_headers,
    pstrdup(s3->req_pool, AWS_S3_OBJECT_COPY_SOURCE_KEY), src_path, 0);

  if (dst_object_metadata != NULL) {
    pr_table_t *src_object_metadata;
    int metadata_flags = AWS_S3_OBJECT_COPY_METADATA_FL_IGNORE_SYSTEM_ATTRS;

    /* If the caller provided metadata for the destination/copy object, we
     * need to get the existing metadata for the source object, so that we
     * preserve its existing metadata.
     */
    src_object_metadata = pr_table_alloc(req_pool, 0);
    if (aws_s3_object_stat(p, s3, src_bucket_name, src_object_key,
        src_object_metadata) == 0) {
      (void) copy_object_metadata(req_pool, src_object_key,
        dst_object_metadata, src_object_metadata, metadata_flags);
    }

    metadata_directive = pstrdup(req_pool, "REPLACE");

    pr_table_add(req_headers,
      pstrdup(s3->req_pool, AWS_S3_OBJECT_COPY_SOURCE_METADATA),
      metadata_directive, 0);

    (void) copy_object_metadata(req_pool, dst_object_key,
      req_headers, dst_object_metadata, metadata_flags);
  }

  dst_path = pstrcat(req_pool,
    "/", aws_http_urlencode(req_pool, s3->http, dst_bucket_name, 0),
    "/", aws_http_urlencode(req_pool, s3->http, dst_object_key, 0), NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = aws_s3_put(p, s3->http, req_headers, dst_path, query_params, "", 0,
    NULL, copy_object_cb, (void *) s3, s3);
  xerrno = errno;

  if (res == 0) {
    time_t last_modified = 0;
    const char *etag = NULL;

    pr_trace_msg(trace_channel, 19,
      "successfully copied object %s from bucket %s to object %s in bucket %s",
        src_object_key, src_bucket_name, dst_object_key, dst_bucket_name);

    pr_trace_msg(trace_channel, 19,
      "copy object response: '%.*s'", (int) s3->respsz, s3->resp);
    if (parse_copy_object(p, s3->resp, s3->respsz, &last_modified, &etag) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing S3 copy object XML response: %s", strerror(errno));

    } else {
      if (last_modified != 0) {
        pr_trace_msg(trace_channel, 15, "received Last-Modified = %lu",
          (unsigned long) last_modified);
      }

      if (etag != NULL) {
        pr_trace_msg(trace_channel, 15, "received ETag = %s", etag);
      }
    }
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}
