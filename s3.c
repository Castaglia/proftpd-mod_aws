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
#include "error.h"
#include "sign.h"
#include "xml.h"
#include "s3.h"

#include <openssl/sha.h>

/* The AWS service name */
static const char *aws_service = "s3";

/* The version of the S3 API which we want to use. */
static const char *s3_api_version = "2006-03-01";

static const char *trace_channel = "aws.s3";

static void clear_response(struct s3_conn *s3) {
  if (s3->req_pool != NULL) {
    destroy_pool(s3->req_pool);
    s3->req_pool = NULL;
  }

  s3->resp = NULL;
  s3->respsz = 0;
}

struct s3_conn *aws_s3_conn_alloc(pool *p, unsigned long max_connect_secs,
    unsigned long max_request_secs, const char *cacerts, const char *region,
    const char *domain, const char *access_key_id,
    const char *secret_access_key, const char *session_token) {
  pool *s3_pool;
  struct s3_conn *s3;
  void *http;

  http = aws_http_alloc(p, max_connect_secs, max_request_secs, cacerts);
  if (http == NULL) {
    return NULL;
  }

  s3_pool = make_sub_pool(p);
  pr_pool_tag(s3_pool, "S3 Connection Pool");

  s3 = pcalloc(s3_pool, sizeof(struct s3_conn));
  s3->pool = s3_pool;
  s3->http = http;
  s3->region = pstrdup(s3->pool, region);
  s3->domain = pstrdup(s3->pool, domain);
  s3->access_key_id = pstrdup(s3->pool, access_key_id);
  s3->secret_access_key = pstrdup(s3->pool, secret_access_key);
  s3->session_token = pstrdup(s3->pool, session_token);

  return s3;
}

int aws_s3_conn_destroy(pool *p, struct s3_conn *s3) {
  int res, xerrno;

  if (s3 == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = aws_http_destroy(p, s3->http);
  xerrno = errno;

  destroy_pool(s3->pool);

  errno = xerrno;
  return res;
}

static int s3_perform(pool *p, void *http, int http_method, const char *path,
    array_header *query_params, pr_table_t *http_headers, char *request_body,
    time_t request_time, size_t (*resp_body)(char *, size_t, size_t, void *),
    struct s3_conn *s3) {
  int res;
  long resp_code;
  unsigned char request_digest[SHA256_DIGEST_LENGTH];
  const char *content_type = NULL, *method_name;
  char *base_url, *host = NULL, *url = NULL;

  switch (http_method) {
    case AWS_HTTP_METHOD_GET:
      method_name = "GET";
      break;

    case AWS_HTTP_METHOD_POST:
      method_name = "POST";
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  /* Note that for S3, there is a special case for the "us-east-1" region
   * (probably due to it being the first AWS region).
   */
  if (strcmp(s3->region, "us-east-1") == 0) {
    host = pstrcat(p, aws_service, ".", s3->domain, NULL);

  } else {
    host = pstrcat(p, aws_service, ".", s3->region, ".", s3->domain, NULL);
  }

  /* Since we will be using path-style requests (due to our use of HTTPS),
   * we must always use "s3.amazonaws.com" as the Host header.
   */
  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_HOST),
    pstrdup(p, "s3.amazonaws.com"), 0);

  /* And, since we are using signature version 4, we ALSO need to provide
   * the SHA256 digest of the payload/content.
   */

  if (request_body != NULL) {
    size_t request_bodylen;

    request_bodylen = strlen(request_body);
    if (SHA256((unsigned char *) request_body, request_bodylen,
        request_digest) == NULL) {
      pr_trace_msg(trace_channel, 2,
        "error calculating SHA256 digest of request payload (%lu bytes)",
        (unsigned long) request_bodylen);
      errno = EINVAL;
      return -1;
    }

  } else {
    if (SHA256((unsigned char *) "", 0, request_digest) == NULL) {
      pr_trace_msg(trace_channel, 2,
        "error calculating SHA256 digest of request payload (0 bytes)");
      errno = EINVAL;
      return -1;
    }
  }

  (void) pr_table_add(http_headers,
    pstrdup(p, AWS_HTTP_HEADER_X_AMZ_CONTENT_SHA256),
    pr_str_bin2hex(p, request_digest, sizeof(request_digest),
    PR_STR_FL_HEX_USE_LC), 0);

  base_url = pstrcat(p, "https://", host, NULL);

  if (query_params->nelts > 0) {
    register unsigned int i;
    char **elts;

    url = pstrcat(p, base_url, path, "?", NULL);

    elts = query_params->elts;
    for (i = 0; i < query_params->nelts; i++) {
      url = pstrcat(p, url, i != 0 ? "&" : "", elts[i], NULL);
    }

  } else {
    url = pstrcat(p, base_url, path, NULL);
  }

  res = aws_sign_v4_generate(p, s3->access_key_id, s3->secret_access_key,
    s3->session_token, s3->region, aws_service, http, method_name, path,
    query_params, http_headers, request_body, request_time);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 2, "error calculating request signature: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

/* XXX NOTE: there are multiple conditions where we might want to retry
 * these requests: connection reset by peer, stale credentials (refetch from
 * instance API), etc.
 */

  switch (http_method) {
    case AWS_HTTP_METHOD_GET:
      res = aws_http_get(p, http, url, http_headers, resp_body, (void *) s3,
        &resp_code, &content_type);
      break;

    case AWS_HTTP_METHOD_POST:
      res = aws_http_post(p, http, url, http_headers, resp_body, (void *) s3,
        request_body, &resp_code, &content_type);
      break;
  }

  if (res < 0) {
    return -1;
  }

  if (resp_code != AWS_HTTP_RESPONSE_CODE_OK) {
    pr_trace_msg(trace_channel, 2,
      "received %ld response code for '%s' request", resp_code, url);

    if (resp_code >= 400L) {
      /* If we received an error, AND no Content-Type, then ASSUME that
       * the response is XML.  (Thanks, AWS.)
       */
      if (content_type == NULL ||
          strstr(content_type, AWS_HTTP_CONTENT_TYPE_XML) != NULL) {
        struct aws_error *err;

        pr_trace_msg(trace_channel, 1, "XML error response: %.*s", (int) s3->respsz, s3->resp);
        err = aws_error_parse_xml(p, s3->resp, s3->respsz);
        if (err == NULL) {
          pr_trace_msg(trace_channel, 3,
            "unable to parse XML error response: %s", strerror(errno));

        } else {
          if (err->err_code == AWS_ERROR_CODE_UNKNOWN) {
            pr_trace_msg(trace_channel, 9,
              "received error response: '%.*s'", (int) s3->respsz, s3->resp);
          }

          (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
            "received error: code = %s (%u), msg = %s, request_id = %s",
            aws_error_get_name(err->err_code), err->err_code, err->err_msg,
            err->req_id);
        }
      }
    }

  } else {
    /* Note: If we receive a 200 OK, BUT the content type is HTML, then it's
     * an unexpected error.
     */
    if (content_type != NULL &&
        strstr(content_type, AWS_HTTP_CONTENT_TYPE_HTML) != NULL) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "received unexpected HTML response for '%s'", url);
      errno = EINVAL;
      return -1;
    }
  }

  /* Note: should we handle other response codes? */
  switch (resp_code) {
    case AWS_HTTP_RESPONSE_CODE_OK:
      break;

    case AWS_HTTP_RESPONSE_CODE_BAD_REQUEST:
      errno = EINVAL;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_UNAUTHORIZED:
      errno = EACCES;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_FORBIDDEN:
    case AWS_HTTP_RESPONSE_CODE_PRECONDITION_FAILED:
      errno = EPERM;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_NOT_FOUND:
      errno = ENOENT;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR:
    case AWS_HTTP_RESPONSE_CODE_BAD_GATEWAY:
      errno = EINVAL;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_SERVICE_UNAVAIL:
      errno = EAGAIN;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT:
      errno = ETIMEDOUT;
      return -1;

    default:
      errno = EPERM;
      return -1;
  }

  return 0;
}

static int s3_get(pool *p, void *http, const char *path,
    array_header *query_params,
    size_t (*resp_body)(char *, size_t, size_t, void *), struct s3_conn *s3) {
  int res;
  pr_table_t *http_headers;
  time_t request_time;
  struct tm *gmt_tm;

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  http_headers = aws_http_default_headers(p, gmt_tm);

  res = s3_perform(p, http, AWS_HTTP_METHOD_GET, path, query_params,
    http_headers, NULL, request_time, resp_body, s3);
  return res;
}

static int s3_post(pool *p, void *http, const char *path,
    array_header *query_params, char *request_body,
    size_t (*resp_body)(char *, size_t, size_t, void *), struct s3_conn *s3) {
  int res;
  pr_table_t *http_headers;
  time_t request_time;
  struct tm *gmt_tm;
  char *content_len;

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  http_headers = aws_http_default_headers(p, gmt_tm);
  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_TYPE),
    pstrdup(p, "application/x-www-form-urlencoded; charset=utf-8"), 0);

  if (request_body == NULL) {
    content_len = pstrdup(p, "0");

  } else {
    size_t request_bodysz;

    request_bodysz = strlen(request_body);
    content_len = aws_utils_str_ul2s(p, (unsigned long) request_bodysz);
  }

  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_LEN),
    content_len, 0);

  res = s3_perform(p, http, AWS_HTTP_METHOD_POST, path, query_params,
    http_headers, request_body, request_time, resp_body, s3);
  return res;
}


static size_t s3_resp_cb(char *data, size_t item_sz, size_t item_count,
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

static array_header *parse_bucket_list(pool *p, const char *data,
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

array_header *aws_s3_get_buckets(pool *p, struct s3_conn *s3,
    const char **owner_id, const char **owner_name) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *buckets = NULL, *query_params;

  req_pool = make_sub_pool(s3->pool);
  pr_pool_tag(req_pool, "S3 Request Pool");
  s3->req_pool = req_pool;

  path = "/";

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = s3_get(p, s3->http, path, query_params, s3_resp_cb, s3);
  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "get buckets response: '%.*s'", (int) s3->respsz, s3->resp);
    buckets = parse_bucket_list(p, s3->resp, s3->respsz, owner_id, owner_name);
    if (buckets == NULL) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing S3 bucket list XML response: %s", strerror(errno));
    }
  }

  clear_response(s3);

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
