/*
 * ProFTPD - mod_aws Route53 API
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
#include "instance.h"
#include "xml.h"
#include "error.h"
#include "sign.h"
#include "route53.h"

/* The AWS service name */
static const char *aws_service = "route53";

/* For Route53, the region is always "us-east-1". */
static const char *aws_region = "us-east-1";

static const char *trace_channel = "aws.route53";

static void clear_response(struct route53_conn *route53) {
  if (route53->req_pool != NULL) {
    destroy_pool(route53->req_pool);
    route53->req_pool = NULL;
  }

  route53->resp = NULL;
  route53->respsz = 0;
}

struct route53_conn *aws_route53_conn_alloc(pool *p,
    unsigned long max_connect_secs, unsigned long max_request_secs,
    const char *cacerts, const char *domain, const char *iam_role) {
  pool *route53_pool;
  struct route53_conn *route53;
  void *http;

  http = aws_http_alloc(p, max_connect_secs, max_request_secs, cacerts);
  if (http == NULL) {
    return NULL;
  }

  route53_pool = make_sub_pool(p);
  pr_pool_tag(route53_pool, "Route53 Connection Pool");

  route53 = pcalloc(route53_pool, sizeof(struct route53_conn));
  route53->pool = route53_pool;
  route53->http = http;
  route53->domain = pstrdup(route53->pool, domain);
  route53->iam_role = pstrdup(route53->pool, iam_role);

  return route53;
}

int aws_route53_conn_destroy(pool *p, struct route53_conn *route53) {
  int res, xerrno;

  res = aws_http_destroy(p, route53->http);
  xerrno = errno;

  destroy_pool(route53->pool);

  errno = xerrno;
  return res;
}

static int route53_get(pool *p, void *http, const char *path,
    array_header *query_params,
    size_t (*resp_body)(char *, size_t, size_t, void *),
    struct route53_conn *route53) {
  pr_table_t *http_headers;
  int res;
  long resp_code;
  const char *content_type = NULL;
  char *base_url, *host = NULL, *iso_date, *url = NULL;
  time_t request_time;
  size_t iso_datesz;
  struct tm *gmt_tm;

  if (route53->iam_info == NULL) {
    /* Need to get the temporary IAM credentials for signing. */

    route53->iam_info = aws_instance_get_iam_credentials(route53->pool,
      route53->iam_role);
    if (route53->iam_info == NULL) {
      pr_trace_msg(trace_channel, 1,
        "error obtaining IAM credentials for role '%s': %s", route53->iam_role,
        strerror(errno));
      errno = EPERM;
      return -1;
    }
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

  /* The Route53 API docs are specific about the Host header value. */
  host = pstrcat(p, aws_service, ".", route53->domain, NULL);

  http_headers = pr_table_nalloc(p, 0, 2);
  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_HOST), host, 0);
  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_ACCEPT),
    "*/*", 0);

  iso_datesz = 16;
  iso_date = pcalloc(p, iso_datesz + 1);
  (void) strftime(iso_date, iso_datesz, "%Y%m%dT%H%M%SZ", gmt_tm);

  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_X_AMZ_DATE),
    iso_date, 0);

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

  res = aws_sign_v4_generate(p,
    route53->iam_info->access_key_id, route53->iam_info->secret_access_key,
    route53->iam_info->token, aws_region, aws_service, http, "GET", path,
    query_params, http_headers, "", request_time);
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

  res = aws_http_get(p, http, url, http_headers, resp_body, (void *) route53,
    &resp_code, &content_type);
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

        err = aws_xml_parse_error(p, route53->resp, route53->respsz);
        if (err == NULL) {
          pr_trace_msg(trace_channel, 3,
            "unable to parse XML error response: %s", strerror(errno));

        } else {
          (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
            "received error: code = %s (%u), msg = %s, req_id = %s",
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

static size_t route53_resp_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct route53_conn *info;
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

int aws_route53_get_hosted_zones(pool *p, struct route53_conn *route53,
    const char *account_id) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params;

  req_pool = make_sub_pool(route53->pool);
  pr_pool_tag(req_pool, "Route53 Request Pool");
  route53->req_pool = req_pool;

  path = "/2013-04-01/hostedzone";

  /* Note: do any of these query parameters need to be URL-encoded?  Per the
   * AWS docs, the answer is "yes".
   */

  query_params = make_array(req_pool, 1, sizeof(char *));

  res = route53_get(p, route53->http, path, query_params, route53_resp_cb,
    route53);
  if (res == 0) {
/* XXX Parse response data */
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "hosted zones response: '%.*s'", (int) route53->respsz, route53->resp);
  }

  clear_response(route53);

  errno = EINVAL;
  return -1;
}
