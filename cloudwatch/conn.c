/*
 * ProFTPD - mod_aws CloudWatch Connection API
 * Copyright (c) 2017 TJ Saunders
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
#include "creds.h"
#include "http.h"
#include "error.h"
#include "sign.h"
#include "xml.h"
#include "../utils.h"
#include "cloudwatch/conn.h"
#include "cloudwatch/error.h"

/* The AWS service name */
static const char *aws_service = "monitoring";

/* The version of the CloudWatch API we want to use. */
static const char *api_version = "2010-08-01";

static const char *trace_channel = "aws.cloudwatch.conn";

struct cloudwatch_conn *aws_cloudwatch_conn_alloc(pool *p,
    unsigned long max_connect_secs, unsigned long max_request_secs,
    const char *cacerts, const char *region, const char *domain,
    const array_header *credential_providers,
    const struct aws_credential_info *credential_info, const char *namespace) {
  pool *cw_pool;
  struct cloudwatch_conn *cw;
  void *http;

  if (p == NULL ||
      domain == NULL) {
    errno = EINVAL;
    return NULL;
  }

  http = aws_http_alloc(p, max_connect_secs, max_request_secs, cacerts);
  if (http == NULL) {
    return NULL;
  }

  cw_pool = make_sub_pool(p);
  pr_pool_tag(cw_pool, "CloudWatch Connection Pool");

  cw = pcalloc(cw_pool, sizeof(struct cloudwatch_conn));
  cw->pool = cw_pool;
  cw->http = http;
  cw->region = pstrdup(cw->pool, region);
  cw->domain = pstrdup(cw->pool, domain);
  cw->credential_providers = credential_providers;
  cw->credential_info = credential_info;

  if (namespace != NULL) {
    cw->namespace = pstrdup(cw->pool, namespace);

  } else {
    cw->namespace = pstrdup(cw->pool, AWS_CLOUDWATCH_DEFAULT_NAMESPACE);
  }

  pr_trace_msg(trace_channel, 17,
    "opening CloudWatch connection using AWS region '%s', domain '%s', "
    "namespace '%s'", cw->region, cw->domain, cw->namespace);
  return cw;
}

int aws_cloudwatch_conn_destroy(pool *p, struct cloudwatch_conn *cw) {
  int res, xerrno;

  if (cw == NULL) {
    errno = EINVAL;
    return -1;
  }

  (void) aws_cloudwatch_conn_flush(p, cw);

  res = aws_http_destroy(p, cw->http);
  xerrno = errno;

  destroy_pool(cw->pool);

  errno = xerrno;
  return res;
}

void aws_cloudwatch_conn_clear_response(struct cloudwatch_conn *cw) {
  if (cw == NULL) {
    return;
  }

  if (cw->req_pool != NULL) {
    destroy_pool(cw->req_pool);
    cw->req_pool = NULL;
  }

  cw->resp = NULL;
  cw->respsz = 0;
}

void aws_cloudwatch_conn_reset_response(struct cloudwatch_conn *cw) {
  if (cw == NULL) {
    return;
  }

  cw->resp = NULL;
  cw->respsz = 0;
}

static pr_table_t *cloudwatch_http_headers(pool *p, struct tm *gmt_tm,
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

static int cloudwatch_http_error(long resp_code) {
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

static int cloudwatch_perform(pool *p, void *http, int http_method,
    const char *path, array_header *query_params, pr_table_t *req_headers,
    char *request_body, off_t request_bodysz, time_t request_time,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    struct cloudwatch_conn *cw) {
  int res;
  long resp_code;
  const char *content_type = NULL, *method_name, *host;
  char *base_url, *url = NULL;

  switch (http_method) {
    case AWS_HTTP_METHOD_GET:
      method_name = "GET";
      break;

    default:
      errno = EINVAL;
      return -1;
  }

  if (cw->credentials == NULL) {
    /* Need to get AWS credentials for signing requests. */
    res = aws_creds_from_chain(cw->pool, cw->credential_providers,
      cw->credential_info, &(cw->credentials));
    if (res < 0) {
      pr_trace_msg(trace_channel, 1,
        "error obtaining AWS credentials: %s", strerror(errno));
      errno = EPERM;
      return -1;
    }
  }

  host = pstrcat(p, aws_service, ".", cw->region, ".", cw->domain, NULL);
  (void) pr_table_add(req_headers, pstrdup(p, AWS_HTTP_HEADER_HOST), host, 0);

  if (cw->credentials->session_token != NULL) {
    (void) pr_table_add(req_headers,
      pstrdup(p, AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN),
      pstrdup(p, cw->credentials->session_token), 0);
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

  res = aws_sign_v4_generate(p, cw->credentials->access_key_id,
    cw->credentials->secret_access_key, cw->credentials->session_token, cw->region,
    aws_service, http, method_name, path, query_params, req_headers,
    request_body, request_bodysz, request_time);
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
        &resp_code, &content_type);
      break;
  }

  if (res < 0) {
    return -1;
  }

  if (cloudwatch_http_error(resp_code) == TRUE) {
    pr_trace_msg(trace_channel, 2,
      "received %ld response code for '%s %s' request", resp_code, method_name,
      url);

    if (resp_code >= 400L) {
      /* If we received an error, AND no Content-Type, then ASSUME that
       * the response is XML.  (Thanks, AWS.)
       */
      if (content_type == NULL ||
          (strstr(content_type, AWS_HTTP_CONTENT_TYPE_APPLICATION_XML) != NULL ||
           strstr(content_type, AWS_HTTP_CONTENT_TYPE_TEXT_XML) != NULL)) {
        struct aws_error *err;

        err = aws_cloudwatch_error_parse_xml(p, cw->resp, cw->respsz);
        if (err == NULL) {
          if (errno == EINVAL) {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response with unexpected elements:\n"
              "%.*s", (int) cw->respsz, cw->resp);

          } else {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response: %s", strerror(errno));
          }

        } else {
          if (err->err_code == AWS_ERROR_CODE_UNKNOWN) {
            pr_trace_msg(trace_channel, 9,
              "received error response: '%.*s'", (int) cw->respsz, cw->resp);
          }

          if (err->err_extra != NULL) {
            (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
              "received error: code = %s (%u), msg = %s, resource = %s, "
              "request_id = %s", aws_cloudwatch_error_get_name(err->err_code),
              err->err_code, err->err_msg, err->err_extra, err->req_id);

          } else {
            (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
              "received error: code = %s (%u), msg = %s, request_id = %s",
              aws_cloudwatch_error_get_name(err->err_code), err->err_code,
              err->err_msg, err->req_id);
          }
        }
      }
    }

  } else {
    if (resp_code == AWS_HTTP_RESPONSE_CODE_OK) {
      /* Note: If we receive a 200 OK, BUT the content type is HTML, then it's
       * an unexpected error.
       */
      if (content_type != NULL &&
          strstr(content_type, AWS_HTTP_CONTENT_TYPE_TEXT_HTML) != NULL) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "received unexpected HTML response for '%s'", url);
        errno = EINVAL;
        return -1;
      }

      pr_trace_msg(trace_channel, 19, "received response: '%.*s'",
        (int) cw->respsz, cw->resp);
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
       * the named bucket or object does not exist.  Unfortunately, the same
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

int aws_cloudwatch_get(pool *p, void *http, pr_table_t *http_headers,
    const char *path, array_header *query_params,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    struct cloudwatch_conn *cw) {
  int res;
  pr_table_t *req_headers;
  time_t request_time;
  struct tm *gmt_tm;

  if (p == NULL ||
      http == NULL ||
      path == NULL ||
      query_params == NULL ||
      resp_body == NULL ||
      cw == NULL) {
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

  req_headers = cloudwatch_http_headers(p, gmt_tm, http_headers);

  *((char **) push_array(query_params)) = pstrcat(p, "Version=",
    api_version, NULL);

  res = cloudwatch_perform(p, http, AWS_HTTP_METHOD_GET, path, query_params,
    req_headers, NULL, 0, request_time, resp_body, user_data, cw);
  return res;
}

int aws_cloudwatch_conn_flush(pool *p, struct cloudwatch_conn *cw) {
  if (p == NULL ||
      cw == NULL) {
    errno = EINVAL;
    return -1;
  }

  /* XXX TODO */
  return 0;
}
