/*
 * ProFTPD - mod_aws S3 API
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

static size_t object_body_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
#if 0
  struct s3_obj_reader *reader;
#endif
  size_t datasz;

/* XXX Need:
 *
 *  req_pool
 *  data
 *  data_offset (calculated from object_offset)
 *  data_len (datasaz)
 */

#if 0
  reader = user_data;
#endif

  datasz = item_sz * item_count;
  if (datasz == 0) {
    return 0;
  }

#if 0
  pr_trace_msg(trace_channel, 5, "downloaded %lu bytes of object %s from bucket %s", (unsigned long) datasz, reader->object_key, reader->bucket_name);
#endif
  pr_trace_msg(trace_channel, 5, "downloaded %lu bytes of object from bucket", (unsigned long) datasz);

  /* XXX Invoke reader->consume(...) */
  return datasz;
}

int aws_s3_object_get(pool *p, struct s3_conn *s3, const char *bucket_name,
    const char *object_key, off_t object_offset, off_t object_len,
    pr_table_t *object_metadata,
    int (*consumer)(pool *p, void *data, off_t data_offset, off_t data_len)) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *req_headers, *resp_headers = NULL;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_key == NULL ||
      consumer == NULL) {
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

  res = aws_s3_get(p, s3->http, req_headers, path, query_params, resp_headers,
    object_body_cb, NULL, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully downloaded object %s from bucket %s", object_key,
      bucket_name);

    if (object_metadata != NULL) {
      const void *k;

      if (pr_trace_get_level(trace_channel) >= 17) {
        pr_trace_msg(trace_channel, 17, "object %s response header count: %d",
          object_key, pr_table_count(resp_headers));
      }

      (void) pr_table_rewind(resp_headers);

      k = pr_table_next(resp_headers);
      while (k != NULL) {
        pr_signals_handle();

        /* XXX TODO: We also need to copy the following system metadata:
         *  Content-Length (size)
         *  Last-Modified (mtime)
         *  x-amz-storage-class
         */

        if (strncasecmp(k, AWS_S3_OBJECT_METADATA_PREFIX,
            AWS_S3_OBJECT_METADATA_PREFIX_LEN) == 0) {
          const void *v;
          size_t vlen;

          v = pr_table_get(resp_headers, k, &vlen);
          if (v != NULL) {
            pr_trace_msg(trace_channel, 9, "object %s metadata: %s = %.*s",
              object_key, k, (int) vlen, v);
            pr_table_add(object_metadata, pstrdup(p, k),
              pstrndup(p, v, vlen), 0);
          }
        }

        k = pr_table_next(resp_headers);
      }
    }
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}
