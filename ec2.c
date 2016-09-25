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
#include "utils.h"
#include "http.h"
#include "instance.h"
#include "error.h"
#include "sign.h"
#include "xml.h"
#include "ec2.h"

/* The AWS service name */
static const char *aws_service = "ec2";

/* The version of the EC2 API which we want to use. */
static const char *ec2_api_version = "2015-10-01";

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
    const char *domain, const char *iam_role) {
  pool *ec2_pool;
  struct ec2_conn *ec2;
  void *http;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

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
  ec2->iam_role = pstrdup(ec2->pool, iam_role);

  return ec2;
}

int aws_ec2_conn_destroy(pool *p, struct ec2_conn *ec2) {
  int res, xerrno;

  if (ec2 == NULL) {
    errno = EINVAL;
    return -1;
  }

  res = aws_http_destroy(p, ec2->http);
  xerrno = errno;

  destroy_pool(ec2->pool);

  errno = xerrno;
  return res;
}

static int ec2_perform(pool *p, void *http, int http_method, const char *path,
    array_header *query_params, pr_table_t *http_headers, char *request_body,
    time_t request_time, size_t (*resp_body)(char *, size_t, size_t, void *),
    struct ec2_conn *ec2) {
  int res;
  long resp_code;
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

  if (ec2->iam_info == NULL) {
    /* Need to get AWS credentials for signing requests. */
    if (ec2->iam_role != NULL) {
      ec2->iam_info = aws_instance_get_iam_credentials(ec2->pool,
        ec2->iam_role);
      if (ec2->iam_info == NULL) {
        pr_trace_msg(trace_channel, 1,
          "error obtaining IAM credentials for role '%s': %s", ec2->iam_role,
          strerror(errno));
        errno = EPERM;
        return -1;
      }

    } else {
      /* XXX TODO:
       * Use aws_creds_from_chain, with a providers list of "profile",
       * "properties", "env", to try to get credentials.
       */
    }
  }

  host = pstrcat(p, aws_service, ".", ec2->region, ".", ec2->domain, NULL);
  (void) pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_HOST), host, 0);

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
    ec2->iam_info->token, ec2->region, aws_service, http, method_name, path,
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
      res = aws_http_get(p, http, url, http_headers, resp_body, (void *) ec2,
        &resp_code, &content_type, NULL);
      break;

    case AWS_HTTP_METHOD_POST:
      res = aws_http_post(p, http, url, http_headers, resp_body, (void *) ec2,
        request_body, &resp_code, &content_type, NULL);
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

        /* TODO: Make and use an aws_ec2_error_parse_xml() here, as was done
         * for S3.
         */
        err = aws_error_parse_xml(p, ec2->resp, ec2->respsz);
        if (err == NULL) {
          if (errno == EINVAL) {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response with unexpected elements:\n"
              "%.*s", (int) ec2->respsz, ec2->resp);

          } else {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response: %s", strerror(errno));
          }

        } else {
          if (err->err_code == AWS_ERROR_CODE_UNKNOWN) {
            pr_trace_msg(trace_channel, 9,
              "received error response: '%.*s'", (int) ec2->respsz, ec2->resp);
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

static int ec2_get(pool *p, void *http, const char *path,
    array_header *query_params,
    size_t (*resp_body)(char *, size_t, size_t, void *), struct ec2_conn *ec2) {
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

  res = ec2_perform(p, http, AWS_HTTP_METHOD_GET, path, query_params,
    http_headers, NULL, request_time, resp_body, ec2);
  return res;
}

static int ec2_post(pool *p, void *http, const char *path,
    array_header *query_params, char *request_body,
    size_t (*resp_body)(char *, size_t, size_t, void *), struct ec2_conn *ec2) {
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

  res = ec2_perform(p, http, AWS_HTTP_METHOD_POST, path, query_params,
    http_headers, request_body, request_time, resp_body, ec2);
  return res;
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

static array_header *parse_sg_ranges(pool *p, void *parent) {
  pool *tmp_pool;
  void *item;
  unsigned long count;
  array_header *ranges = NULL;

  (void) aws_xml_elt_get_child_count(p, parent, &count);
  ranges = make_array(p, count, sizeof(pr_netacl_t *));

  if (count == 0) {
    return ranges;
  }

  tmp_pool = make_sub_pool(p);
  item = aws_xml_elt_get_child(p, parent, "item", 4);
  while (item != NULL) {
    void *elt;

    pr_signals_handle();

    elt = aws_xml_elt_get_child(p, item, "cidrIp", 6);
    if (elt != NULL) {
      char *elt_text;
      pr_netacl_t *range;

      elt_text = (char *) aws_xml_elt_get_text(tmp_pool, elt);
      range = pr_netacl_create(p, elt_text);
      if (range != NULL) {
        *((pr_netacl_t **) push_array(ranges)) = range;

      } else {
        pr_trace_msg(trace_channel, 8,
          "error parsing '%s' as netacl: %s", elt_text, strerror(errno));
      }
    }

    item = aws_xml_elt_get_next(p, item);
  }

  destroy_pool(tmp_pool);
  return ranges;
}

static struct ec2_ip_rule *parse_sg_rule(pool *p, void *parent) {
  pool *tmp_pool;
  void *elt;
  const char *elt_text;
  struct ec2_ip_rule *rule = NULL;

  /* ipProtocol */
  elt = aws_xml_elt_get_child(p, parent, "ipProtocol", 10);
  if (elt == NULL) {
    errno = EINVAL;
    return NULL;
  }

  tmp_pool = make_sub_pool(p);

  /* Filter out any protocol other than 'tcp'. */
  elt_text = aws_xml_elt_get_text(tmp_pool, elt);
  if (strncmp(elt_text, "tcp", 4) != 0) {
    pr_trace_msg(trace_channel, 9,
      "ignoring security group permission for '%s' protocol", elt_text);
    destroy_pool(tmp_pool);
    errno = ENOENT;
    return NULL;
  }

  rule = pcalloc(p, sizeof(struct ec2_ip_rule));
  rule->proto = pstrdup(p, elt_text);

  /* fromPort */
  elt = aws_xml_elt_get_child(p, parent, "fromPort", 8);
  if (elt == NULL) {
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  elt_text = aws_xml_elt_get_text(tmp_pool, elt);
  rule->from_port = atoi(elt_text);

  /* toPort */
  elt = aws_xml_elt_get_child(p, parent, "toPort", 6);
  if (elt == NULL) {
    destroy_pool(tmp_pool);
    errno = EINVAL;
    return NULL;
  }

  elt_text = aws_xml_elt_get_text(tmp_pool, elt);
  rule->to_port = atoi(elt_text);

  /* XXX groups, i.e. security groups */

  /* ipRanges */
  elt = aws_xml_elt_get_child(p, parent, "ipRanges", 8);
  if (elt != NULL) {
    rule->ranges = parse_sg_ranges(p, elt);

  } else {
    /* Make an empty list. */
    rule->ranges = make_array(p, 0, sizeof(pr_netacl_t *));
  }

  destroy_pool(tmp_pool);
  return rule;
}

static array_header *parse_sg_rules(pool *p, void *parent, const char *name,
    size_t name_len) {
  void *elt, *kid;
  unsigned long count;
  array_header *ip_rules = NULL;

  elt = aws_xml_elt_get_child(p, parent, name, name_len);
  if (elt == NULL) {
    /* Return an empty list. */
    return make_array(p, 0, sizeof(struct ec2_ip_rule *));
  }

  (void) aws_xml_elt_get_child_count(p, elt, &count);
  ip_rules = make_array(p, count, sizeof(struct ec2_ip_rule *));

  kid = aws_xml_elt_get_child(p, elt, "item", 4);
  while (kid != NULL) {
    struct ec2_ip_rule *rule;

    pr_signals_handle();

    rule = parse_sg_rule(p, kid);
    if (rule != NULL) {
      *((struct ec2_ip_rule **) push_array(ip_rules)) = rule;
    }

    kid = aws_xml_elt_get_next(p, kid);
  }

  return ip_rules;
}

static struct ec2_security_group *parse_sg_xml(pool *p, const char *data,
    size_t datasz) {
  void *doc, *root, *req_id, *info, *item, *elt;
  pool *sg_pool;
  struct ec2_security_group *sg;
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
  if (elt_namelen != 30 ||
      strncmp(elt_name, "DescribeSecurityGroupsResponse",
        elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  req_id = aws_xml_elt_get_child(p, root, "requestId", 9);
  if (req_id == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  sg_pool = make_sub_pool(p);
  pr_pool_tag(sg_pool, "AWS Security Group Pool");
  sg = pcalloc(sg_pool, sizeof(struct ec2_security_group));
  sg->pool = sg_pool;

  sg->req_id = aws_xml_elt_get_text(sg->pool, req_id);

  info = aws_xml_elt_get_child(p, root, "securityGroupInfo", 17);
  if (info == NULL) {
    destroy_pool(sg_pool);
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  /* Since we only requested ONE security group by ID, we expect only ONE
   * child in this element.
   */

  (void) aws_xml_elt_get_child_count(p, info, &count);
  if (count != 1) {
    pr_trace_msg(trace_channel, 5,
      "expected 1 security group element, found %lu", count);
  }

  item = aws_xml_elt_get_child(p, info, "item", 4);
  if (item == NULL) {
    destroy_pool(sg_pool);
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  /* ownerId */
  elt = aws_xml_elt_get_child(p, item, "ownerId", 7);
  if (elt == NULL) {
    destroy_pool(sg_pool);
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  sg->owner_id = aws_xml_elt_get_text(sg->pool, elt);

  /* groupName */
  elt = aws_xml_elt_get_child(p, item, "groupName", 9);
  if (elt == NULL) {
    destroy_pool(sg_pool);
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  sg->name = aws_xml_elt_get_text(sg->pool, elt);

  /* groupDescription */
  elt = aws_xml_elt_get_child(p, item, "groupDescription", 16);
  if (elt == NULL) {
    destroy_pool(sg_pool);
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  sg->desc = aws_xml_elt_get_text(sg->pool, elt);

  sg->inbound_rules = parse_sg_rules(sg->pool, item,
    "ipPermissions", 13);
  sg->outbound_rules = parse_sg_rules(sg->pool, item,
    "ipPermissionsEgress", 19);

  aws_xml_doc_free(p, doc);
  return sg;
}

static struct ec2_security_group *get_security_group(pool *p,
    struct ec2_conn *ec2, const char *vpc_id, const char *sg_id) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  struct ec2_security_group *sg = NULL;

  req_pool = make_sub_pool(ec2->pool);
  pr_pool_tag(req_pool, "EC2 Request Pool");
  ec2->req_pool = req_pool;

  path = "/";

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrdup(req_pool,
    "Action=DescribeSecurityGroups");

  /* Although the AWS EC2 docs SAY you can use the GroupId filter, the
   * docs lie.  You'll get an UnknownParameter error using GroupId.
   */
  *((char **) push_array(query_params)) = pstrdup(req_pool,
    "Filter.1.Name=group-id");
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "Filter.1.Value=", aws_http_urlencode(req_pool, ec2->http, sg_id, 0),
    NULL);

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "Version=", ec2_api_version, NULL);

  if (vpc_id != NULL) {
    *((char **) push_array(query_params)) = pstrdup(req_pool,
      "Filter.2.Name=vpc-id");
    *((char **) push_array(query_params)) = pstrcat(req_pool,
      "Filter.2.Value=", aws_http_urlencode(req_pool, ec2->http, vpc_id, 0),
      NULL);
  }

  res = ec2_get(p, ec2->http, path, query_params, ec2_resp_cb, ec2);
  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "security groups response: '%.*s'", (int) ec2->respsz, ec2->resp);
    sg = parse_sg_xml(p, ec2->resp, ec2->respsz);
    if (sg == NULL) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing security group XML response: %s", strerror(errno));
    }
  }

  clear_response(ec2);

  if (sg != NULL) {
    register unsigned int i;
    struct ec2_ip_rule **rules;

    if (sg->id == NULL) {
      sg->id = pstrdup(sg->pool, sg_id);
    }

    if (sg->vpc_id == NULL) {
      sg->vpc_id = pstrdup(sg->pool, vpc_id);
    }

    pr_trace_msg(trace_channel, 15,
      "received security group: id = %s, name = %s, desc = %s, owner_id = %s, "
      "vpc_id = %s, request_id = %s, inbound rule count = %d, "
      "outbound rule count = %d", sg->id, sg->name, sg->desc, sg->owner_id,
      sg->vpc_id, sg->req_id, sg->inbound_rules->nelts,
      sg->outbound_rules->nelts);

    rules = sg->inbound_rules->elts;
    for (i = 0; i < sg->inbound_rules->nelts; i++) {
      register unsigned int j;
      struct ec2_ip_rule *rule;
      pr_netacl_t **acls;

      rule = rules[i];
      pr_trace_msg(trace_channel, 15,
        "  inbound rule #%u: proto = %s, ports %d-%d, ranges (%d):", i+1,
        rule->proto, rule->from_port, rule->to_port, rule->ranges->nelts);

      acls = rule->ranges->elts;
      for (j = 0; j < rule->ranges->nelts; j++) {
        pr_trace_msg(trace_channel, 15,
          "    range: %s", pr_netacl_get_str(sg->pool, acls[j]));
      }
    }

    rules = sg->outbound_rules->elts;
    for (i = 0; i < sg->outbound_rules->nelts; i++) {
      register unsigned int j;
      struct ec2_ip_rule *rule;
      pr_netacl_t **acls;

      rule = rules[i];
      pr_trace_msg(trace_channel, 15,
        "  outbound rule #%u: proto = %s, ports %d-%d, ranges (%d):", i+1,
        rule->proto, rule->from_port, rule->to_port, rule->ranges->nelts);

      acls = rule->ranges->elts;
      for (j = 0; j < rule->ranges->nelts; j++) {
        pr_trace_msg(trace_channel, 15,
          "    range: %s", pr_netacl_get_str(sg->pool, acls[j]));
      }
    }
  }

  return sg;
}

pr_table_t *aws_ec2_get_security_groups(pool *p, struct ec2_conn *ec2,
    const char *vpc_id, array_header *security_groups) {
  register unsigned int i;
  char **elts;
  pr_table_t *info;

  /* Note: the VPC ID can be null, for it may not be applicable for this
   * instance.
   */
  if (p == NULL ||
      ec2 == NULL ||
      security_groups == NULL) {
    errno = EINVAL;
    return NULL;
  }

  info = pr_table_nalloc(p, 0, security_groups->nelts);

  elts = security_groups->elts;
  for (i = 0; i < security_groups->nelts; i++) {
    char *sg_id;
    struct ec2_security_group *sg;

    sg_id = elts[i];
    sg = get_security_group(p, ec2, vpc_id, sg_id);
    if (sg != NULL) {
      if (pr_table_add(info, pstrdup(p, sg_id), sg, sizeof(void *)) < 0) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error adding security group '%s' to result: %s", sg_id,
          strerror(errno));
      }
    }
  }

  return info;
}

int aws_ec2_security_group_allow_rule(pool *p, struct ec2_conn *ec2,
    const char *sg_id, struct ec2_ip_rule *rule) {
  register unsigned int i;
  int res, xerrno = 0;
  const char *path;
  char *from_port, *to_port, *request_body = NULL;
  pool *req_pool;
  array_header *query_params;
  pr_netacl_t **acls;

  if (p == NULL ||
      ec2 == NULL ||
      sg_id == NULL ||
      rule == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(ec2->pool);
  pr_pool_tag(req_pool, "EC2 Request Pool");
  ec2->req_pool = req_pool;

  path = "/";

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrdup(req_pool,
    "Action=AuthorizeSecurityGroupIngress");

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "GroupId=", aws_http_urlencode(req_pool, ec2->http, sg_id, 0), NULL);

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "Version=", ec2_api_version, NULL);

  if (aws_opts & AWS_OPT_DRY_RUN) {
    pr_trace_msg(trace_channel, 12,
      "performing dry-run check for adding inbound security group rule");
    *((char **) push_array(query_params)) = pstrdup(req_pool, "DryRun=true");
  }

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "IpPermissions.1.IpProtocol=", aws_http_urlencode(req_pool, ec2->http,
    rule->proto, 0), NULL);

  from_port = aws_utils_str_n2s(req_pool, rule->from_port);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "IpPermissions.1.FromPort=", aws_http_urlencode(req_pool, ec2->http,
    from_port, 0), NULL);

  to_port = aws_utils_str_n2s(req_pool, rule->to_port);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "IpPermissions.1.ToPort=", aws_http_urlencode(req_pool, ec2->http,
    to_port, 0), NULL);

  acls = rule->ranges->elts;
  for (i = 0; i < rule->ranges->nelts; i++) {
    pr_netacl_t *acl;
    const char *cidr, *rangeno;

    acl = acls[i];
    cidr = pr_netacl_get_str2(req_pool, acl, PR_NETACL_FL_STR_NO_DESC);

    rangeno = aws_utils_str_n2s(req_pool, i+1);

    *((char **) push_array(query_params)) = pstrcat(req_pool,
      "IpPermissions.1.IpRanges.", rangeno, ".CidrIp=",
      aws_http_urlencode(req_pool, ec2->http, cidr, 0), NULL);
  }

  res = ec2_post(p, ec2->http, path, query_params, request_body, ec2_resp_cb,
    ec2);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "update security group response: '%.*s'", (int) ec2->respsz, ec2->resp);
  }

  clear_response(ec2);

  errno = xerrno;
  return res;
}

int aws_ec2_security_group_revoke_rule(pool *p, struct ec2_conn *ec2,
    const char *sg_id, struct ec2_ip_rule *rule) {
  register unsigned int i;
  int res, xerrno = 0;
  const char *path;
  char *from_port, *to_port, *request_body = NULL;
  pool *req_pool;
  array_header *query_params;
  pr_netacl_t **acls;

  if (p == NULL ||
      ec2 == NULL ||
      sg_id == NULL ||
      rule == NULL) {
    errno = EINVAL;
    return -1;
  }

  req_pool = make_sub_pool(ec2->pool);
  pr_pool_tag(req_pool, "EC2 Request Pool");
  ec2->req_pool = req_pool;

  path = "/";

  query_params = make_array(req_pool, 1, sizeof(char *));

  *((char **) push_array(query_params)) = pstrdup(req_pool,
    "Action=RevokeSecurityGroupIngress");

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "GroupId=", aws_http_urlencode(req_pool, ec2->http, sg_id, 0), NULL);

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "Version=", ec2_api_version, NULL);

  if (aws_opts & AWS_OPT_DRY_RUN) {
    pr_trace_msg(trace_channel, 12,
      "performing dry-run check for removing inbound security group rule");
    *((char **) push_array(query_params)) = pstrdup(req_pool, "DryRun=true");
  }

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "IpPermissions.1.IpProtocol=", aws_http_urlencode(req_pool, ec2->http,
    rule->proto, 0), NULL);

  from_port = aws_utils_str_n2s(req_pool, rule->from_port);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "IpPermissions.1.FromPort=", aws_http_urlencode(req_pool, ec2->http,
    from_port, 0), NULL);

  to_port = aws_utils_str_n2s(req_pool, rule->to_port);
  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "IpPermissions.1.ToPort=", aws_http_urlencode(req_pool, ec2->http,
    to_port, 0), NULL);

  acls = rule->ranges->elts;
  for (i = 0; i < rule->ranges->nelts; i++) {
    pr_netacl_t *acl;
    const char *cidr, *rangeno;

    acl = acls[i];
    cidr = pr_netacl_get_str2(req_pool, acl, PR_NETACL_FL_STR_NO_DESC);

    rangeno = aws_utils_str_n2s(req_pool, i+1);

    *((char **) push_array(query_params)) = pstrcat(req_pool,
      "IpPermissions.1.IpRanges.", rangeno, ".CidrIp=",
      aws_http_urlencode(req_pool, ec2->http, cidr, 0), NULL);
  }

  res = ec2_post(p, ec2->http, path, query_params, request_body, ec2_resp_cb,
    ec2);
  xerrno = errno;

  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "update security group response: '%.*s'", (int) ec2->respsz, ec2->resp);
  }

  clear_response(ec2);

  errno = xerrno;
  return res;
}
