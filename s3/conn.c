/*
 * ProFTPD - mod_aws S3 Connection API
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
#include "error.h"
#include "sign.h"
#include "xml.h"
#include "../utils.h"
#include "s3/conn.h"
#include "s3/error.h"

#include <openssl/sha.h>

/* The AWS service name */
static const char *aws_service = "s3";

static const char *trace_channel = "aws.s3.conn";

struct s3_conn *aws_s3_conn_alloc(pool *p, unsigned long max_connect_secs,
    unsigned long max_request_secs, const char *cacerts, const char *region,
    const char *domain, const char *access_key_id,
    const char *secret_access_key, const char *session_token) {
  pool *s3_pool;
  struct s3_conn *s3;
  void *http;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

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

void aws_s3_conn_clear_response(struct s3_conn *s3) {
  if (s3 == NULL) {
    return;
  }

  if (s3->req_pool != NULL) {
    destroy_pool(s3->req_pool);
    s3->req_pool = NULL;
  }

  s3->resp = NULL;
  s3->respsz = 0;
}

void aws_s3_conn_reset_response(struct s3_conn *s3) {
  if (s3 == NULL) {
    return;
  }

  s3->resp = NULL;
  s3->respsz = 0;
}

static pr_table_t *s3_http_headers(pool *p, struct tm *gmt_tm,
    pr_table_t *http_headers) {
  pr_table_t *req_headers;

  req_headers = aws_http_default_headers(p, gmt_tm);

  if (http_headers != NULL) {
    const void *k;

    (void) pr_table_rewind(http_headers);
    k = pr_table_next(http_headers);
    while (k != NULL) {
      const void *v;
      size_t vlen;

      pr_signals_handle();

      v = pr_table_get(http_headers, k, &vlen);
      if (v != NULL) {
        pr_table_add(req_headers, pstrdup(p, k), pstrndup(p, v, vlen), 0);
      }

      k = pr_table_next(http_headers);
    }
  }

  return req_headers;
}

static int s3_http_error(long resp_code) {
  int res = TRUE;

  switch (resp_code) {
    case AWS_HTTP_RESPONSE_CODE_OK:
    case AWS_HTTP_RESPONSE_CODE_NO_CONTENT:
    case AWS_HTTP_RESPONSE_CODE_PARTIAL_CONTENT:
      res = FALSE;
      break;

    default:
      res = TRUE;
  }

  return res;
}

static int s3_perform(pool *p, void *http, int http_method, const char *path,
    array_header *query_params, pr_table_t *req_headers, char *request_body,
    off_t request_bodysz, time_t request_time, pr_table_t *resp_headers,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    struct s3_conn *s3) {
  int res;
  long resp_code;
  unsigned char request_digest[SHA256_DIGEST_LENGTH];
  const char *content_type = NULL, *method_name, *host;
  char *base_url, *url = NULL;

  switch (http_method) {
    case AWS_HTTP_METHOD_GET:
      method_name = "GET";
      break;

    case AWS_HTTP_METHOD_HEAD:
      method_name = "HEAD";
      break;

    case AWS_HTTP_METHOD_POST:
      method_name = "POST";
      break;

    case AWS_HTTP_METHOD_PUT:
      method_name = "PUT";
      break;

    case AWS_HTTP_METHOD_DELETE:
      method_name = "DELETE";
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
    host = pstrcat(p, aws_service, "-", s3->region, ".", s3->domain, NULL);
  }

  (void) pr_table_add(req_headers, pstrdup(p, AWS_HTTP_HEADER_HOST), host, 0);

  /* And, since we are using signature version 4, we ALSO need to provide
   * the SHA256 digest of the payload/content.
   */

  if (request_body != NULL) {
    request_bodysz = (off_t) strlen(request_body);
    if (SHA256((unsigned char *) request_body, (size_t) request_bodysz,
        request_digest) == NULL) {
      pr_trace_msg(trace_channel, 2,
        "error calculating SHA256 digest of request payload (%lu bytes)",
        (unsigned long) request_bodysz);
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

  (void) pr_table_add(req_headers,
    pstrdup(p, AWS_HTTP_HEADER_X_AMZ_CONTENT_SHA256),
    pr_str_bin2hex(p, request_digest, sizeof(request_digest),
    PR_STR_FL_HEX_USE_LC), 0);

  if (s3->session_token != NULL) {
    (void) pr_table_add(req_headers,
      pstrdup(p, AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN),
      pstrdup(p, s3->session_token), 0);
  }

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
    query_params, req_headers, request_body, request_bodysz, request_time);
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
      res = aws_http_get(p, http, url, req_headers, resp_body, user_data,
        &resp_code, &content_type, resp_headers);
      break;

    case AWS_HTTP_METHOD_HEAD:
      res = aws_http_head(p, http, url, req_headers, &resp_code, &content_type,
        resp_headers);
      break;

    case AWS_HTTP_METHOD_POST:
      res = aws_http_post(p, http, url, req_headers, resp_body, user_data,
        request_body, &resp_code, &content_type, resp_headers);
      break;

    case AWS_HTTP_METHOD_PUT:
      res = aws_http_put(p, http, url, req_headers, resp_body, user_data,
        request_body, request_bodysz, &resp_code, &content_type, resp_headers);
      break;

    case AWS_HTTP_METHOD_DELETE:
      res = aws_http_delete(p, http, url, req_headers, &resp_code,
        resp_headers);
      break;
  }

  if (res < 0) {
    return -1;
  }

  if (s3_http_error(resp_code) == TRUE) {
    pr_trace_msg(trace_channel, 2,
      "received %ld response code for '%s %s' request", resp_code, method_name,
      url);

    if (resp_code >= 400L) {
      /* If we received an error, AND no Content-Type, then ASSUME that
       * the response is XML.  (Thanks, AWS.)
       */
      if (content_type == NULL ||
          strstr(content_type, AWS_HTTP_CONTENT_TYPE_XML) != NULL) {
        struct aws_error *err;

        err = aws_s3_error_parse_xml(p, s3->resp, s3->respsz);
        if (err == NULL) {
          if (errno == EINVAL) {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response with unexpected elements:\n"
              "%.*s", (int) s3->respsz, s3->resp);

          } else {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response: %s", strerror(errno));
          }

        } else {
          if (err->err_code == AWS_ERROR_CODE_UNKNOWN) {
            pr_trace_msg(trace_channel, 9,
              "received error response: '%.*s'", (int) s3->respsz, s3->resp);
          }

          if (err->err_extra != NULL) {
            (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
              "received error: code = %s (%u), msg = %s, resource = %s, "
              "request_id = %s", aws_s3_error_get_name(err->err_code),
              err->err_code, err->err_msg, err->err_extra, err->req_id);

          } else {
            (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
              "received error: code = %s (%u), msg = %s, request_id = %s",
              aws_s3_error_get_name(err->err_code), err->err_code, err->err_msg,
              err->req_id);
          }
        }
      }
    }

  } else {
    /* Note: If we receive a 200 OK, BUT the content type is HTML, then it's
     * an unexpected error.
     */
    if (resp_code == AWS_HTTP_RESPONSE_CODE_OK &&
        content_type != NULL &&
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
    case AWS_HTTP_RESPONSE_CODE_PARTIAL_CONTENT:
      break;

    case AWS_HTTP_RESPONSE_CODE_NO_CONTENT:
      /* In some cases, a 204 No Content may be success, OR we may want to
       * treat it as a different error.
       *
       * In the case of an S3 object delete, 204 No Content is returned when
       * the named bucket or object do not exist.  Unfortunately, the same
       * response is issued for a delete of an S3 object which DOES exist.
       * Sigh.
       */
      break;

    case AWS_HTTP_RESPONSE_CODE_BAD_REQUEST:
      errno = EINVAL;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_UNAUTHORIZED:
      errno = EACCES;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_FORBIDDEN:
    case AWS_HTTP_RESPONSE_CODE_METHOD_NOT_ALLOWED:
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

int aws_s3_delete(pool *p, void *http, pr_table_t *http_headers,
    const char *path, array_header *query_params, pr_table_t *resp_headers,
    struct s3_conn *s3) {
  int res;
  pr_table_t *req_headers;
  time_t request_time;
  struct tm *gmt_tm;

  if (p == NULL ||
      http == NULL ||
      path == NULL ||
      query_params == NULL ||
      s3 == NULL) {
    errno = EINVAL;
    return -1;
  }

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  req_headers = s3_http_headers(p, gmt_tm, http_headers);
  res = s3_perform(p, http, AWS_HTTP_METHOD_DELETE, path, query_params,
    req_headers, NULL, 0, request_time, resp_headers, NULL, NULL, s3);
  return res;
}

int aws_s3_get(pool *p, void *http, pr_table_t *http_headers, const char *path,
    array_header *query_params, pr_table_t *resp_headers,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    struct s3_conn *s3) {
  int res;
  pr_table_t *req_headers;
  time_t request_time;
  struct tm *gmt_tm;

  if (p == NULL ||
      http == NULL ||
      path == NULL || 
      query_params == NULL ||
      resp_body == NULL ||
      s3 == NULL) {
    errno = EINVAL;
    return -1;
  }

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  req_headers = s3_http_headers(p, gmt_tm, http_headers);
  res = s3_perform(p, http, AWS_HTTP_METHOD_GET, path, query_params,
    req_headers, NULL, 0, request_time, resp_headers, resp_body, user_data, s3);
  return res;
}

int aws_s3_head(pool *p, void *http, pr_table_t *http_headers, const char *path,
    array_header *query_params, pr_table_t *resp_headers, struct s3_conn *s3) {
  int res;
  pr_table_t *req_headers;
  time_t request_time;
  struct tm *gmt_tm;

  if (p == NULL ||
      http == NULL ||
      path == NULL ||
      query_params == NULL ||
      s3 == NULL) {
    errno = EINVAL;
    return -1;
  }

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  req_headers = s3_http_headers(p, gmt_tm, http_headers);
  res = s3_perform(p, http, AWS_HTTP_METHOD_HEAD, path, query_params,
    req_headers, NULL, 0, request_time, resp_headers, NULL, NULL, s3);
  return res;
}

int aws_s3_post(pool *p, void *http, pr_table_t *http_headers, const char *path,
    array_header *query_params, char *req_body, off_t req_bodysz,
    pr_table_t *resp_headers,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    struct s3_conn *s3) {
  int res;
  pr_table_t *req_headers;
  time_t request_time;
  struct tm *gmt_tm;
  char *content_len;

  if (p == NULL ||
      http == NULL ||
      path == NULL ||
      query_params == NULL ||
      resp_body == NULL ||
      s3 == NULL) {
    errno = EINVAL;
    return -1;
  }

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  req_headers = s3_http_headers(p, gmt_tm, http_headers);
  (void) pr_table_add(req_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_TYPE),
    pstrdup(p, "application/x-www-form-urlencoded; charset=utf-8"), 0);

  if (req_body == NULL) {
    content_len = pstrdup(p, "0");
    req_bodysz = 0;

  } else {
    if (req_bodysz == 0) {
      req_bodysz = (off_t) strlen(req_body);
    }

    content_len = aws_utils_str_off2s(p, req_bodysz);
  }

  (void) pr_table_add(req_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_LEN),
    content_len, 0);

  res = s3_perform(p, http, AWS_HTTP_METHOD_POST, path, query_params,
    req_headers, req_body, req_bodysz, request_time, resp_headers, resp_body,
    user_data, s3);
  return res;
}

int aws_s3_put(pool *p, void *http, pr_table_t *http_headers, const char *path,
    array_header *query_params, char *req_body, off_t req_bodysz,
    pr_table_t *resp_headers,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    struct s3_conn *s3) {
  int res;
  pr_table_t *req_headers;
  time_t request_time;
  struct tm *gmt_tm;
  char *content_len;

  if (p == NULL ||
      http == NULL ||
      path == NULL ||
      query_params == NULL ||
      resp_body == NULL ||
      s3 == NULL) {
    errno = EINVAL;
    return -1;
  }

  time(&request_time);

  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  req_headers = s3_http_headers(p, gmt_tm, http_headers);

  if (req_body == NULL) {
    content_len = pstrdup(p, "0");
    req_bodysz = 0;

  } else {
    if (req_bodysz == 0) {
      req_bodysz = (off_t) strlen(req_body);
    }

    content_len = aws_utils_str_off2s(p, req_bodysz);
  }

  (void) pr_table_add(req_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_LEN),
    content_len, 0);

  res = s3_perform(p, http, AWS_HTTP_METHOD_PUT, path, query_params,
    req_headers, req_body, req_bodysz, request_time, resp_headers, resp_body,
    user_data, s3);
  return res;
}
