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
#include "../utils.h"
#include "s3/conn.h"
#include "s3/error.h"
#include "s3/object.h"

static const char *trace_channel = "aws.s3.object";

/* S3 object downloads */

struct object_reader {
  pool *pool;
  const char *bucket_name;
  const char *object_key;
  off_t offset;
  int (*consume_data)(pool *, void *, off_t, off_t);
};

/* S3 multipart object uploads */

struct s3_object_part {
  const char *part_number;
  const char *part_etag;
};

struct s3_object_multipart {
  pool *pool;

  const char *bucket_name;
  const char *object_key;
  pr_table_t *object_metadata;
  const char *upload_id;

  /* Counter to be used as the next part number. */
  unsigned int partno;

  /* List tracking part numbers and their respective ETags. */
  array_header *parts;
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
    "downloaded %lu bytes of object '%s' from bucket '%s'",
    (unsigned long) datasz, reader->object_key, reader->bucket_name);

  res = (reader->consume_data)(reader->pool, data, reader->offset, datasz);
  if (res < 0) {
    pr_trace_msg(trace_channel, 4,
      "download of object '%s' from bucket '%s' aborted: %s",
      reader->object_key, reader->bucket_name, strerror(errno));

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
#define AWS_S3_OBJECT_COPY_METADATA_FL_KEEP_PREFIX		0x002

static int copy_object_metadata(pool *p, const char *object_key,
    pr_table_t *dst_object_metadata, pr_table_t *src_object_metadata,
    int flags) {
  const void *k;

  if (dst_object_metadata == NULL ||
      src_object_metadata == NULL) {
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
        pr_trace_msg(trace_channel, 9, "object '%s' metadata: %s = %.*s",
          object_key, (char *) k, (int) vlen, (char *) v);
        pr_table_add(dst_object_metadata, pstrdup(p, k),
          pstrndup(p, v, vlen), 0);
      }

    } else if (strncasecmp(k, AWS_S3_OBJECT_METADATA_PREFIX,
        AWS_S3_OBJECT_METADATA_PREFIX_LEN) == 0) {
      v = pr_table_get(src_object_metadata, k, &vlen);
      if (v != NULL) {
        const char *dup_key, *log_key;

        if (flags & AWS_S3_OBJECT_COPY_METADATA_FL_KEEP_PREFIX) {
          dup_key = k;
          log_key = ((char *) k) + AWS_S3_OBJECT_METADATA_PREFIX_LEN;

        } else {
          /* Skip past the key prefix, for legibility. */
          dup_key = ((char *) k) + AWS_S3_OBJECT_METADATA_PREFIX_LEN;
          log_key = dup_key;
        }

        pr_trace_msg(trace_channel, 9, "object '%s' metadata: %s = %.*s",
          object_key, (char *) log_key, (int) vlen, (char *) v);

        pr_table_add(dst_object_metadata, pstrdup(p, dup_key),
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

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), "/",
    object_key, NULL);

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
      "successfully downloaded object '%s' from bucket '%s'", object_key,
      bucket_name);

    if (resp_headers != NULL) {
      if (pr_trace_get_level(trace_channel) >= 17) {
        pr_trace_msg(trace_channel, 17, "object '%s' response header count: %d",
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

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), "/",
    object_key, NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  if (object_metadata != NULL) {
    resp_headers = pr_table_alloc(s3->req_pool, 0);
  }

  res = aws_s3_head(p, s3->http, NULL, path, query_params, resp_headers, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully checked object '%s' in bucket '%s'", object_key,
      bucket_name);

    if (resp_headers != NULL) {
      if (pr_trace_get_level(trace_channel) >= 17) {
        pr_trace_msg(trace_channel, 17, "object '%s' response header count: %d",
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

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), "/",
    object_key, NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = aws_s3_delete(p, s3->http, NULL, path, query_params, NULL, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully deleted object '%s' from bucket '%s'", object_key,
      bucket_name);
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}

static size_t s3_response_cb(char *data, size_t item_sz, size_t item_count,
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
    *last_modified = aws_s3_utils_lastmod2unix(p, aws_xml_elt_get_text(p, elt));
  }

  elt = aws_xml_elt_get_child(p, root, "ETag", 4);
  if (elt != NULL) {
    *etag = aws_xml_elt_get_text(p, elt);
  }

  aws_xml_doc_free(p, doc);
  return 0;
}

int aws_s3_object_copy(pool *p, struct s3_conn *s3,
    const char *src_bucket_name, const char *src_object_key,
    const char *dst_bucket_name, const char *dst_object_key,
    pr_table_t *dst_object_metadata) {
  int res, xerrno;
  const char *src_path, *dst_path;
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

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  src_path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, src_bucket_name, 0), "/",
    src_object_key, NULL);

  pr_table_add(req_headers,
    pstrdup(s3->req_pool, AWS_S3_OBJECT_COPY_SOURCE_KEY), src_path, 0);

  if (dst_object_metadata != NULL) {
    pr_table_t *src_object_metadata;
    const char *metadata_directive;
    int metadata_flags = AWS_S3_OBJECT_COPY_METADATA_FL_IGNORE_SYSTEM_ATTRS|
      AWS_S3_OBJECT_COPY_METADATA_FL_KEEP_PREFIX;

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

    /* Restore our request pool pointer, which would have been cleared out
     * by object_stat().
     */
    s3->req_pool = req_pool;

    (void) copy_object_metadata(req_pool, dst_object_key,
      req_headers, dst_object_metadata, metadata_flags);

    metadata_directive = pstrdup(req_pool, "REPLACE");

    pr_table_add(req_headers,
      pstrdup(s3->req_pool, AWS_S3_OBJECT_COPY_SOURCE_METADATA),
      metadata_directive, 0);
  }

  dst_path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, dst_bucket_name, 0), "/",
    dst_object_key, NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = aws_s3_put(p, s3->http, req_headers, dst_path, query_params, "", 0,
    NULL, s3_response_cb, (void *) s3, s3);
  xerrno = errno;

  if (res == 0) {
    time_t last_modified = 0;
    const char *etag = NULL;

    pr_trace_msg(trace_channel, 19,
      "successfully copied object '%s' from bucket '%s' to object '%s' in "
      "bucket '%s'", src_object_key, src_bucket_name, dst_object_key,
      dst_bucket_name);

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

int aws_s3_object_put(pool *p, struct s3_conn *s3, const char *bucket_name,
    const char *object_key, pr_table_t *object_metadata, char *object_data,
    off_t object_datasz) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *req_headers = NULL;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_key == NULL ||
      object_data == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (object_datasz > AWS_S3_OBJECT_PUT_MAX_SIZE) {
    errno = E2BIG;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), "/",
    object_key, NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  if (object_metadata != NULL) {
    int metadata_flags = AWS_S3_OBJECT_COPY_METADATA_FL_IGNORE_SYSTEM_ATTRS|
      AWS_S3_OBJECT_COPY_METADATA_FL_KEEP_PREFIX;

    req_headers = pr_table_alloc(s3->req_pool, 0);

    (void) copy_object_metadata(req_pool, object_key,
      req_headers, object_metadata, metadata_flags);
  }

  res = aws_s3_put(p, s3->http, req_headers, path, query_params, object_data,
    object_datasz, NULL, s3_response_cb, (void *) s3, s3);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "successfully put object '%s' in bucket '%s'", object_key, bucket_name);
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}

static int parse_init_multipart(pool *p, const char *data, size_t datasz,
    const char **upload_id) {
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
  if (elt_namelen != 29 ||
      strncmp(elt_name, "InitiateMultipartUploadResult", elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return -1;
  }

  elt = aws_xml_elt_get_child(p, root, "UploadId", 8);
  if (elt == NULL) {
    pr_trace_msg(trace_channel, 5, "missing required <UploadId> element");
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return -1;
  }

  *upload_id = aws_xml_elt_get_text(p, elt);

  aws_xml_doc_free(p, doc);
  return 0;
}

struct s3_object_multipart *aws_s3_object_multipart_open(pool *p,
    struct s3_conn *s3, const char *bucket_name, const char *object_key,
    pr_table_t *object_metadata) {
  int res, xerrno, default_content_type = TRUE;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *req_headers = NULL;
  struct s3_object_multipart *multipart = NULL;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      object_key == NULL) {
    errno = EINVAL;
    return NULL;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), "/", object_key,
    NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  /* Note: The AWS docs, on the format of this query string, are out-of-date.
   * IFF you are using AWS signature V4, then this query string MUST have
   * a trailing '='; this is NOT mentioned in the AWS docs for this request.
   * Grr.  I had to search the s3fs source code to find this tidbit.
   */
  *((char **) push_array(query_params)) = pstrdup(req_pool, "uploads=");

  req_headers = pr_table_alloc(s3->req_pool, 0);

  if (object_metadata != NULL) {
    int metadata_flags = AWS_S3_OBJECT_COPY_METADATA_FL_IGNORE_SYSTEM_ATTRS|
      AWS_S3_OBJECT_COPY_METADATA_FL_KEEP_PREFIX;
    (void) copy_object_metadata(req_pool, object_key,
      req_headers, object_metadata, metadata_flags);

    if (pr_table_get(object_metadata, AWS_HTTP_HEADER_CONTENT_TYPE,
        NULL) != NULL) {
      default_content_type = FALSE;
    }
  }

  if (default_content_type == TRUE) {
    (void) pr_table_add(req_headers,
      pstrdup(req_pool, AWS_HTTP_HEADER_CONTENT_TYPE),
      pstrdup(req_pool, AWS_HTTP_CONTENT_TYPE_BINARY), 0);
  }

  res = aws_s3_post(p, s3->http, req_headers, path, query_params, "", 0,
    NULL, s3_response_cb, (void *) s3, s3);
  xerrno = errno;

  if (res == 0) {
    const char *upload_id = NULL;

    pr_trace_msg(trace_channel, 19,
      "multipart object upload response: '%.*s'", (int) s3->respsz, s3->resp);

    if (parse_init_multipart(req_pool, s3->resp, s3->respsz, &upload_id) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing S3 init multipart XML response: %s",
        strerror(errno));
      errno = EINVAL;

    } else {
      pool *sub_pool;

      sub_pool = make_sub_pool(p);
      pr_pool_tag(sub_pool, "S3 Multipart Object Pool");

      multipart = pcalloc(sub_pool, sizeof(struct s3_object_multipart));
      multipart->pool = sub_pool;
      multipart->bucket_name = pstrdup(multipart->pool, bucket_name);
      multipart->object_key = pstrdup(multipart->pool, object_key);
      multipart->object_metadata = aws_utils_table_dup(multipart->pool,
        object_metadata);
      multipart->upload_id = pstrdup(multipart->pool, upload_id);
      multipart->parts = make_array(multipart->pool, 0,
        sizeof(struct s3_object_part *));

      pr_trace_msg(trace_channel, 15,
        "obtained upload ID '%s' for object '%s', bucket '%s'",
        multipart->upload_id, multipart->object_key, multipart->bucket_name);
    }
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return multipart;
}

int aws_s3_object_multipart_append(pool *p, struct s3_conn *s3,
    struct s3_object_multipart *multipart, char *part_data,
    off_t part_datasz) {
  int res, xerrno, partno;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  pr_table_t *resp_headers;
  char *part_number;

  if (p == NULL ||
      s3 == NULL ||
      multipart == NULL ||
      part_data == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* Note: We could, in theory, reject calls if the part_datasz is less
   * then AWS_S3_OBJECT_MULTIPART_MIN_SIZE here.  Except that we DO need
   * to allow for a smaller "last" part.  Thus any buffering necessary for
   * ensuring the appended part size is large enough will happen at the
   * FSIO layer, not here.
   */

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, multipart->bucket_name, 0), "/",
    multipart->object_key, NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrcat(req_pool, "uploadId=",
    aws_http_urlencode(req_pool, s3->http, multipart->upload_id, 0), NULL);

  partno = (int) (multipart->partno + 1);
  if (partno > AWS_S3_OBJECT_MULTIPART_MAX_COUNT) {
    pr_trace_msg(trace_channel, 5,
      "maximum part count for multipart upload of object '%s' in bucket '%s' "
      "exceeded: %d > %d", multipart->object_key, multipart->bucket_name,
      partno, (int) AWS_S3_OBJECT_MULTIPART_MAX_COUNT);
    errno = EINVAL;
    return -1;
  }

  part_number = aws_utils_str_n2s(req_pool, partno);
  *((char **) push_array(query_params)) = pstrcat(req_pool, "partNumber=",
    part_number, 0);

  resp_headers = pr_table_alloc(req_pool, 0);

  res = aws_s3_put(p, s3->http, NULL, path, query_params, part_data,
    part_datasz, resp_headers, s3_response_cb, (void *) s3, s3);
  xerrno = errno;

  if (res == 0) {
    const char *part_etag;

    multipart->partno++;

    part_etag = pr_table_get(resp_headers, AWS_HTTP_HEADER_ETAG, NULL);
    if (part_etag == NULL) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "missing expected %s response header for S3 multipart object upload",
        AWS_HTTP_HEADER_ETAG);
      errno = EINVAL;
      res = -1;

    } else {
      struct s3_object_part *part;

      part = palloc(multipart->pool, sizeof(struct s3_object_part));
      part->part_number = pstrdup(multipart->pool, part_number);
      part->part_etag = pstrdup(multipart->pool, part_etag);
      *((struct s3_object_part **) push_array(multipart->parts)) = part;

      pr_trace_msg(trace_channel, 19,
        "appended multipart data to object '%s' in bucket '%s': "
        "part %s = ETag %s", multipart->object_key, multipart->bucket_name,
        part_number, part_etag);
    }
  }

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}

static int parse_complete_multipart(pool *p, const char *data, size_t datasz) {
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
  if (elt_namelen != 29 ||
      strncmp(elt_name, "CompleteMultipartUploadResult", elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return -1;
  }

  elt = aws_xml_elt_get_child(p, root, "Bucket", 6);
  if (elt != NULL) {
    pr_trace_msg(trace_channel, 15,
      "completed multipart object upload: bucket = %s",
      aws_xml_elt_get_text(p, elt));
  }

  elt = aws_xml_elt_get_child(p, root, "Key", 3);
  if (elt != NULL) {
    pr_trace_msg(trace_channel, 15,
      "completed multipart object upload: key = %s",
      aws_xml_elt_get_text(p, elt));
  }

  elt = aws_xml_elt_get_child(p, root, "ETag", 4);
  if (elt != NULL) {
    pr_trace_msg(trace_channel, 15,
      "completed multipart object upload: etag = %s",
      aws_xml_elt_get_text(p, elt));
  }

  elt = aws_xml_elt_get_child(p, root, "Location", 8);
  if (elt != NULL) {
    pr_trace_msg(trace_channel, 15,
      "completed multipart object upload: location = %s",
      aws_xml_elt_get_text(p, elt));
  }

  aws_xml_doc_free(p, doc);
  return 0;
}

int aws_s3_object_multipart_close(pool *p, struct s3_conn *s3,
    struct s3_object_multipart *multipart, int flags) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;

  if (p == NULL ||
      s3 == NULL ||
      multipart == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (flags != AWS_S3_OBJECT_MULTIPART_FL_SUCCESS &&
      flags != AWS_S3_OBJECT_MULTIPART_FL_FAILURE) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Object Request Pool");
  s3->req_pool = req_pool;

  /* Note: Ideally we would URL-encode both the bucket name and the object
   * key.  However, we will often have object keys which contain "/", and those
   * slashes are legitimately part of the URL.
   */
  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, multipart->bucket_name, 0), "/",
    multipart->object_key, NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrcat(req_pool, "uploadId=",
    aws_http_urlencode(req_pool, s3->http, multipart->upload_id, 0), NULL);

  if (flags == AWS_S3_OBJECT_MULTIPART_FL_FAILURE) {
    res = aws_s3_delete(p, s3->http, NULL, path, query_params, NULL, s3);
    xerrno = errno;

    if (res == 0) {
      pr_trace_msg(trace_channel, 19,
        "successfully aborted multipart object '%s' in bucket '%s'",
        multipart->object_key, multipart->bucket_name);
      destroy_pool(multipart->pool);
    }

  } else {
    register unsigned int i;
    pr_table_t *req_headers;
    void *text;
    const char *xml;
    size_t xmlsz;

    /* Note: If no parts have been appended/uploaded for this object, then
     * we cannot complete the multipart upload as is.  The AWS S3 Multipart
     * Upload API requires one or more parts.
     *
     * Instead, when we detect this case, we will fall back to simply using
     * PUT for the zero-length object.
     */
    if (multipart->parts->nelts == 0) {
      pr_trace_msg(trace_channel, 17,
        "empty length multipart upload of '%s' to bucket '%s' detected, "
        "using PUT", multipart->object_key, multipart->bucket_name);
      destroy_pool(req_pool);

      res = aws_s3_object_put(p, s3, multipart->bucket_name,
        multipart->object_key, multipart->object_metadata, "", 0);
      xerrno = errno;

      if (res == 0) {
        destroy_pool(multipart->pool);
      }

      errno = xerrno;
      return res;
    }

    text = aws_xml_text_alloc(req_pool);

    aws_xml_text_elt_start(p, text, "CompleteMultipartUpload");

    for (i = 0; i < multipart->parts->nelts; i++) {
      struct s3_object_part *part;

      part = ((struct s3_object_part **) multipart->parts->elts)[i];

      aws_xml_text_elt_start(p, text, "Part");
      aws_xml_text_elt_add_child(p, text, "PartNumber", part->part_number);
      aws_xml_text_elt_add_child(p, text, "ETag", part->part_etag);
      aws_xml_text_elt_end(p, text);
    }

    aws_xml_text_elt_end(p, text);

    xml = aws_xml_text_content(req_pool, text);
    xmlsz = strlen(xml);

    aws_xml_text_free(req_pool, text);

    pr_trace_msg(trace_channel, 15,
      "closing multipart upload of '%s' to bucket '%s' using XML: '%.*s'",
      multipart->object_key, multipart->bucket_name, (int) xmlsz, xml);

    req_headers = pr_table_alloc(req_pool, 0);

    (void) pr_table_add(req_headers,
      pstrdup(req_pool, AWS_HTTP_HEADER_CONTENT_TYPE),
      pstrdup(req_pool, AWS_HTTP_CONTENT_TYPE_XML), 0);

    res = aws_s3_post(p, s3->http, req_headers, path, query_params,
      (char *) xml, xmlsz, NULL, s3_response_cb, (void *) s3, s3);
    xerrno = errno;

    if (res == 0) {
      pr_trace_msg(trace_channel, 19,
        "successfully completed multipart object '%s' in bucket '%s': '%.*s'",
        multipart->object_key, multipart->bucket_name, (int) s3->respsz,
        s3->resp);

      if (parse_complete_multipart(req_pool, s3->resp, s3->respsz) < 0) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error parsing S3 complete multipart XML response: %s",
          strerror(errno));
      }

      destroy_pool(multipart->pool);
    }
  }

  /* Destroy the multipart object; we don't need it anymore. */
  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}
