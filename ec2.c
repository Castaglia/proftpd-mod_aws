/*
 * ProFTPD - mod_aws EC2 API
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
#include "ec2.h"

/* The AWS service name */
static const char *aws_service = "ec2";

static const char *trace_channel = "aws.ec2";

static void clear_response(struct ec2_conn *ec2) {
  if (ec2->req_pool != NULL) {
    destroy_pool(ec2->req_pool);
    ec2->req_pool = NULL;
  }

  ec2->resp = NULL;
  ec2->respsz = 0;
}

struct ec2_conn *aws_ec2_conn_alloc(pool *p, unsigned long max_connect_secs,
    unsigned long max_request_secs, const char *cacerts, const char *region,
    const char *domain, const char *api_version, const char *iam_role) {
  pool *ec2_pool;
  struct ec2_conn *ec2;
  void *http;

  http = aws_http_alloc(p, max_connect_secs, max_request_secs, cacerts);
  if (http == NULL) {
    return NULL;
  }

  ec2_pool = make_sub_pool(p);
  pr_pool_tag(ec2_pool, "EC2 Connection Pool");

  ec2 = pcalloc(ec2_pool, sizeof(struct ec2_conn));
  ec2->pool = ec2_pool;
  ec2->http = http;
  ec2->region = pstrdup(ec2->pool, region);
  ec2->domain = pstrdup(ec2->pool, domain);
  ec2->api_version = pstrdup(ec2->pool, api_version);
  ec2->iam_role = pstrdup(ec2->pool, iam_role);

  return ec2;
}

int aws_ec2_conn_destroy(pool *p, struct ec2_conn *ec2) {
  int res, xerrno;

  res = aws_http_destroy(p, ec2->http);
  xerrno = errno;

  destroy_pool(ec2->pool);

  errno = xerrno;
  return res;
}

/* NOTE: for an ec2_post() function, we will need to set a Content-Type
 * request header of "application/x-www-form-urlencoded; charset=utf-8".
 */

static int ec2_get(pool *p, void *http, const char *path,
    array_header *query_params,
    size_t (*resp_body)(char *, size_t, size_t, void *), struct ec2_conn *ec2) {
  pr_table_t *http_headers;
  int res;
  long resp_code;
  const char *content_type = NULL;
  char *base_url, *host = NULL, *iso_date, *url = NULL;
  time_t request_time;
  size_t iso_datesz;
  struct tm *gmt_tm;

  if (ec2->iam_info == NULL) {
    /* Need to get the temporary IAM credentials for signing. */

    ec2->iam_info = aws_instance_get_iam_credentials(ec2->pool, ec2->iam_role);
    if (ec2->iam_info == NULL) {
      pr_trace_msg(trace_channel, 1,
        "error obtaining IAM credentials for role '%s': %s", ec2->iam_role,
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

  host = pstrcat(p, aws_service, ".", ec2->region, ".", ec2->domain, NULL);

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
    ec2->iam_info->access_key_id, ec2->iam_info->secret_access_key,
    ec2->iam_info->token, ec2->region, aws_service, http, "GET", path,
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

  res = aws_http_get(p, http, url, http_headers, resp_body, (void *) ec2,
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

        err = aws_xml_parse_error(p, ec2->resp, ec2->respsz);
        if (err == NULL) {
          pr_trace_msg(trace_channel, 3,
            "unable to parse XML error response: %s", strerror(errno));

        } else {
          if (err->err_code == AWS_ERROR_CODE_UNKNOWN) {
            pr_trace_msg(trace_channel, 9,
              "received error response: '%.*s'", (int) ec2->respsz, ec2->resp);
          }

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

static size_t ec2_resp_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct ec2_conn *info;
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

static struct ec2_security_group *get_security_group(pool *p,
    struct ec2_conn *ec2, const char *group_name) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  struct ec2_security_group *sg = NULL;

  req_pool = make_sub_pool(ec2->pool);
  pr_pool_tag(req_pool, "EC2 Request Pool");
  ec2->req_pool = req_pool;

  path = "/";

  /* Note: do any of these query parameters need to be URL-encoded?  Per the
   * AWS docs, the answer is "yes".
   */

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrdup(req_pool,
    "Action=DescribeSecurityGroups");
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "GroupName.1=", aws_http_urlencode(req_pool, ec2->http, group_name, 0),
    NULL);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "Version=", aws_http_urlencode(req_pool, ec2->http, ec2->api_version, 0),
    NULL);

  res = ec2_get(p, ec2->http, path, query_params, ec2_resp_cb, ec2);
  if (res == 0) {
/* XXX Parse response data */
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "security groups response: '%.*s'", (int) ec2->respsz, ec2->resp);
  }

  clear_response(ec2);
  return sg;
}

pr_table_t *aws_ec2_get_security_groups(pool *p, struct ec2_conn *ec2,
    array_header *security_groups) {
  register unsigned int i;
  char **elts;
  pr_table_t *info;

  if (p == NULL ||
      ec2 == NULL ||
      security_groups == NULL) {
    errno = EINVAL;
    return NULL;
  }

  info = pr_table_nalloc(p, 0, security_groups->nelts);

  elts = security_groups->elts;
  for (i = 0; i < security_groups->nelts; i++) {
    char *group_name;
    struct ec2_security_group *sg;

    group_name = elts[i];
    sg = get_security_group(p, ec2, group_name);
    if (sg != NULL) {
      if (pr_table_add(info, pstrdup(p, group_name), sg, sizeof(void *)) < 0) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error adding security group '%s' to result: %s", group_name,
          strerror(errno));
      }
    }
  }

  return info;
}
