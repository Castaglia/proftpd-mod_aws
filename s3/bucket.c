/*
 * ProFTPD - mod_aws S3 Bucket API
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
#include "http.h"
#include "xml.h"
#include "utils.h"
#include "../utils.h"
#include "s3/error.h"
#include "s3/bucket.h"

static const char *trace_channel = "aws.s3.bucket";

static size_t bucket_resp_cb(char *data, size_t item_sz, size_t item_count,
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

static array_header *parse_buckets(pool *p, const char *data,
    size_t datasz, const char **owner_id, const char **owner_name) {
  void *doc, *root, *info, *kid, *elt;
  array_header *buckets = NULL;
  unsigned long count;
  const char *elt_name;
  size_t elt_namelen;

  doc = aws_xml_doc_parse(p, data, (int) datasz);
  if (doc == NULL) {
    errno = EINVAL;
    return NULL;
  }

  root = aws_xml_doc_get_root_elt(p, doc);
  if (root == NULL) {
    /* Malformed XML. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  elt_name = aws_xml_elt_get_name(p, root, &elt_namelen);
  if (elt_namelen != 22 ||
      strncmp(elt_name, "ListAllMyBucketsResult", elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  info = aws_xml_elt_get_child(p, root, "Owner", 5);
  if (info == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  (void) aws_xml_elt_get_child_count(p, info, &count);
  if (count != 2) {
    pr_trace_msg(trace_channel, 5,
      "expected 2 owner elements, found %lu", count);
  }

  elt = aws_xml_elt_get_child(p, info, "ID", 2);
  if (elt == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  if (owner_id != NULL) {
    *owner_id = aws_xml_elt_get_text(p, elt);
  }

  elt = aws_xml_elt_get_child(p, info, "DisplayName", 11);
  if (elt == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  if (owner_name != NULL) {
    *owner_name = aws_xml_elt_get_text(p, elt);
  }

  info = aws_xml_elt_get_child(p, root, "Buckets", 7);
  if (info == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  (void) aws_xml_elt_get_child_count(p, info, &count);
  pr_trace_msg(trace_channel, 5, "found %lu %s", count,
    count != 1 ? "buckets" : "bucket");

  buckets = make_array(p, count, sizeof(const char *));

  kid = aws_xml_elt_get_child(p, info, "Bucket", 6);
  while (kid != NULL) {
    pr_signals_handle();

    elt = aws_xml_elt_get_child(p, kid, "Name", 4);
    if (elt != NULL) {
      *((const char **) push_array(buckets)) = aws_xml_elt_get_text(p, elt);
    }

    kid = aws_xml_elt_get_next(p, kid);
  }

  aws_xml_doc_free(p, doc);
  return buckets;
}

array_header *aws_s3_bucket_get_names(pool *p, struct s3_conn *s3,
    const char **owner_id, const char **owner_name) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *buckets = NULL, *query_params;

  if (p == NULL ||
      s3 == NULL) {
    errno = EINVAL;
    return NULL;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Request Pool");
  s3->req_pool = req_pool;

  path = "/";

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = aws_s3_get(p, s3->http, NULL, path, query_params, NULL, bucket_resp_cb,
    (void *) s3, s3);
  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "get bucket names response: '%.*s'", (int) s3->respsz, s3->resp);
    buckets = parse_buckets(p, s3->resp, s3->respsz, owner_id, owner_name);
    if (buckets == NULL) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing S3 bucket names list XML response: %s", strerror(errno));
    }
  }

  aws_s3_conn_clear_response(s3);

  if (buckets != NULL) {
    register unsigned int i;

    if (owner_id != NULL) {
      pr_trace_msg(trace_channel, 15, "received owner ID = %s", *owner_id);
    }

    if (owner_name != NULL) {
      pr_trace_msg(trace_channel, 15, "received owner name = %s", *owner_name);
    }

    for (i = 0; i < buckets->nelts; i++) {
      const char *name;

      name = ((char **) buckets->elts)[i];
      pr_trace_msg(trace_channel, 15, "received bucket name = %s", name);
    }
  }

  return buckets;
}

int aws_s3_bucket_access(pool *p, struct s3_conn *s3, const char *bucket_name) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Request Pool");
  s3->req_pool = req_pool;

  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = aws_s3_head(p, s3->http, NULL, path, query_params, NULL, s3);
  xerrno = errno;

  aws_s3_conn_clear_response(s3);

  errno = xerrno;
  return res;
}

static const char *parse_bucket_content(pool *p, void *content,
    struct s3_object_attrs **object_attrs) {
  void *elt;
  const char *key = NULL;

  elt = aws_xml_elt_get_child(p, content, "Key", 3);
  if (elt == NULL) {
    errno = ENOENT;
    return NULL;
  }

  key = aws_xml_elt_get_text(p, elt);

  *object_attrs = pcalloc(p, sizeof(struct s3_object_attrs));

  elt = aws_xml_elt_get_child(p, content, "Size", 4);
  if (elt != NULL) {
    int res;
    off_t sz;

    res = aws_utils_str_s2off(p, aws_xml_elt_get_text(p, elt), &sz);
    if (res == 0) {
      (*object_attrs)->size = sz;
      pr_trace_msg(trace_channel, 12, " object %s size = %" PR_LU, key,
        (pr_off_t) sz);
    }
  }

  elt = aws_xml_elt_get_child(p, content, "StorageClass", 12);
  if (elt != NULL) {
    (*object_attrs)->storage_class = aws_xml_elt_get_text(p, elt);
    pr_trace_msg(trace_channel, 12, " object %s storage class = %s", key,
      (*object_attrs)->storage_class);
  }

  elt = aws_xml_elt_get_child(p, content, "LastModified", 12);
  if (elt != NULL) {
    (*object_attrs)->last_modified = aws_s3_utils_lastmod2unix(p,
      aws_xml_elt_get_text(p, elt));
    pr_trace_msg(trace_channel, 12, " object %s last-modified = %lu", key,
      (unsigned long) (*object_attrs)->last_modified);
  }

  elt = aws_xml_elt_get_child(p, content, "ETag", 4);
  if (elt != NULL) {
    (*object_attrs)->etag = aws_xml_elt_get_text(p, elt);
    pr_trace_msg(trace_channel, 12, " object %s etag = %s", key,
      (*object_attrs)->etag);
  }

  return key;
}

static int parse_bucket_contents(pool *p, const char *data, size_t datasz,
    pr_table_t *keys, char **continuation_token) {
  void *doc, *root, *kid, *elt;
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
      strncmp(elt_name, "ListBucketResult", elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return -1;
  }

  if (pr_trace_get_level(trace_channel) >= 12) {
    elt = aws_xml_elt_get_child(p, root, "KeyCount", 8);
    if (elt != NULL) {
      pr_trace_msg(trace_channel, 12, "bucket key count: %s",
        aws_xml_elt_get_text(p, elt));
    }

    elt = aws_xml_elt_get_child(p, root, "MaxKeys", 7);
    if (elt != NULL) {
      pr_trace_msg(trace_channel, 12, "bucket max keys: %s",
        aws_xml_elt_get_text(p, elt));
    }

    elt = aws_xml_elt_get_child(p, root, "IsTruncated", 11);
    if (elt != NULL) {
      int truncated = FALSE;

      truncated = pr_str_is_boolean(aws_xml_elt_get_text(p, elt));
      pr_trace_msg(trace_channel, 12, "bucket keys are truncated: %s",
        truncated ? "true" : "false");

      if (truncated == TRUE) {
        elt = aws_xml_elt_get_child(p, root, "NextContinuationToken", 21);
        if (elt != NULL) {
          *continuation_token = aws_xml_elt_get_text(p, elt);
          pr_trace_msg(trace_channel, 12, "bucket keys continuation token: %s",
            *continuation_token);
        }
      }
    }
  }

  /* Contrary to the AWS S3 documentation for List Objects (v2), the
   * actual response does NOT contain a <Contents> element which contains
   * a set of <Content> elements.  Instead, there is a set of <Contents>
   * elements, each one of which is for a given object.
   */
  kid = aws_xml_elt_get_child(p, root, "Contents", 8);
  if (kid == NULL) {
    /* No objects found in the bucket. */
    aws_xml_doc_free(p, doc);
    return 0;
  }

  while (kid != NULL) {
    const char *key;
    struct s3_object_attrs *object_attrs = NULL;

    pr_signals_handle();

    key = parse_bucket_content(p, kid, &object_attrs);
    if (key != NULL) {
      size_t keysz;

      keysz = strlen(key) + 1;
      (void) pr_table_kadd(keys, key, keysz, object_attrs, sizeof(void *));
    }

    kid = aws_xml_elt_get_next(p, kid);
  }

  aws_xml_doc_free(p, doc);
  return 0;
}

int aws_s3_bucket_get_keys(pool *p, struct s3_conn *s3,
    const char *bucket_name, const char *prefix, pr_table_t *keys,
    const char *continuation_token) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params;

  if (p == NULL ||
      s3 == NULL ||
      bucket_name == NULL ||
      keys == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Request Pool");
  s3->req_pool = req_pool;

  path = pstrcat(req_pool, "/",
    aws_http_urlencode(req_pool, s3->http, bucket_name, 0), NULL);

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrdup(req_pool, "list-type=2");

  if (prefix != NULL) {
    *((char **) push_array(query_params)) = pstrcat(req_pool, "prefix=",
      aws_http_urlencode(req_pool, s3->http, prefix, 0), NULL);
  }

  if (continuation_token != NULL) {
    *((char **) push_array(query_params)) = pstrcat(req_pool,
      "continuation-token=",
      aws_http_urlencode(req_pool, s3->http, continuation_token, 0), NULL);
  }

  res = aws_s3_get(p, s3->http, NULL, path, query_params, NULL,
    bucket_resp_cb, (void *) s3, s3);
  if (res == 0) {
    char *next_token = NULL;

    pr_trace_msg(trace_channel, 19,
      "get bucket contents response: '%.*s'", (int) s3->respsz, s3->resp);
    if (parse_bucket_contents(p, s3->resp, s3->respsz, keys,
        &next_token) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing S3 bucket contents list XML response: %s",
        strerror(errno));

    } else {
        pr_trace_msg(trace_channel, 1,
          "using continuation token %s to get next page of keys for bucket %s",
          next_token ? next_token : "(NONE)", bucket_name);
      if (next_token != NULL) {
        pr_trace_msg(trace_channel, 17,
          "using continuation token %s to get next page of keys for bucket %s",
          next_token, bucket_name);

        aws_s3_conn_reset_response(s3);
        return aws_s3_bucket_get_keys(p, s3, bucket_name, prefix, keys,
          next_token);
      }
    }
  }

  aws_s3_conn_clear_response(s3);

  if (keys != NULL) {
    const void *key;

    pr_trace_msg(trace_channel, 15, "received %d keys for bucket %s:",
      pr_table_count(keys), bucket_name);

    (void) pr_table_rewind(keys);

    key = pr_table_next(keys);
    while (key != NULL) {
      pr_signals_handle();

      pr_trace_msg(trace_channel, 15, "  received object key = %s",
        (char *) key);
      key = pr_table_next(keys);
    }

    (void) pr_table_rewind(keys);
  }

  return 0;
}
