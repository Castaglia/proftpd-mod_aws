/*
 * ProFTPD - mod_aws CloudWatch Metric API
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
#include "../utils.h"
#include "cloudwatch/dimension.h"
#include "cloudwatch/metric.h"

static const char *trace_channel = "aws.cloudwatch.metric";

/* An array of dimensions is assumed to be alternating key/value strings. */
static void add_dimensions(pool *p, array_header *query_params,
    array_header *dimensions, const char *itemno) {
  register unsigned int i;

  if (dimensions == NULL) {
    return;
  }

  for (i = 0; i < dimensions->nelts; i++) {
    char *memberno, *name, *value;

    memberno = aws_utils_str_n2s(p, (int) i+1);
    name = ((char **) dimensions->elts)[i];
    value = ((char **) dimensions->elts)[i++];

    *((char **) push_array(query_params)) = pstrcat(p,
      "MetricData.member.", itemno, ".Dimensions.member.", memberno, ".Name=",
      name, NULL);
    *((char **) push_array(query_params)) = pstrcat(p,
      "MetricData.member.", itemno, ".Dimensions.member.", memberno, ".Value=",
      value, NULL);
  }
}

static size_t metric_resp_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct cloudwatch_conn *info;
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

static int send_metric(pool *p, struct cloudwatch_conn *cw, const char *name,
    const char *units, double val, array_header *dimensions, int flags) {
  int res, xerrno;
  const char *path;
  pool *req_pool;
  array_header *query_params;

  req_pool = make_sub_pool(cw->pool);
  pr_pool_tag(req_pool, "CloudWatch Request Pool");
  cw->req_pool = req_pool;

  path = "/";
  query_params = make_array(req_pool, 1, sizeof(char *));
  *((char **) push_array(query_params)) = pstrcat(req_pool, "Namespace=",
    cw->namespace, NULL);

  /* Note: Interestingly, if you omit this parameter, AWS will actually
   * issue a redirect for this request, to a plain HTTP (not HTTPS) URL, to:
   *
   *  http://aws.amazon.com/cloudwatch?...
   *
   * rather than returning an error.  Weird.  And that will actually cause
   * us to fail this request, with a misleading error message from libcurl:
   *
   *   request error: SSL certificate problem: unable to get local issuer certificate
   * because we cannot look up a local issuer for a plain HTTP site, and we
   * tell libcurl that we REQUIRE TLS.
   */
  *((char **) push_array(query_params)) = pstrdup(req_pool,
    "Action=PutMetricData");

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "MetricData.member.1.MetricName=", name, NULL);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "MetricData.member.1.Unit=", units, NULL);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "MetricData.member.1.Value=", aws_utils_str_d2s(req_pool, val), NULL);

  add_dimensions(req_pool, query_params, dimensions, "1");

  pr_trace_msg(trace_channel, 14, "sending metric: %s = %0.03lf %s",
    name, val, units);
  res = aws_cloudwatch_get(p, cw->http, NULL, path, query_params,
    metric_resp_cb, cw, cw);
  xerrno = errno;

  aws_cloudwatch_conn_clear_response(cw);

  errno = xerrno;
  return res;
}

int aws_cloudwatch_metric_counter(pool *p, struct cloudwatch_conn *cw,
    const char *name, double incr, array_header *dimensions, int flags) {

  if (p == NULL ||
      cw == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (dimensions != NULL &&
      (dimensions->nelts / 2) > AWS_CLOUDWATCH_MAX_DIMENSIONS) {
    errno = EINVAL;
    return -1;
  }

  return send_metric(p, cw, name, "Count", incr, dimensions, flags);
}

int aws_cloudwatch_metric_timer(pool *p, struct cloudwatch_conn *cw,
    const char *name, double ms, array_header *dimensions, int flags) {

  if (p == NULL ||
      cw == NULL ||
      name == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (dimensions != NULL &&
      (dimensions->nelts / 2) > AWS_CLOUDWATCH_MAX_DIMENSIONS) {
    errno = EINVAL;
    return -1;
  }

  return send_metric(p, cw, name, "Milliseconds", ms, dimensions, flags);
}
