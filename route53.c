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

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

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
  char *base_url, *host = NULL, *url = NULL;
  time_t request_time;
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

  http_headers = aws_http_default_headers(p, gmt_tm);
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

/* XXX NOTE: how to get the x-amz-request-id response header from the
 * Route53 responses, given the current HTTP API?
 */

  res = aws_http_get(p, http, url, http_headers, resp_body, (void *) route53,
    &resp_code, &content_type, NULL);
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
        int fmt = AWS_ERROR_XML_FORMAT_DEFAULT;

        err = aws_error_parse_xml(p, route53->resp, route53->respsz, fmt);
        if (err == NULL) {
          if (errno == EINVAL) {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response with unexpected elements:\n"
              "%.*s", (int) route53->respsz, route53->resp);

          } else {
            pr_trace_msg(trace_channel, 3,
              "unable to parse XML error response: %s", strerror(errno));
          }

        } else {
          if (err->err_code == AWS_ERROR_CODE_UNKNOWN) {
            pr_trace_msg(trace_channel, 9,
              "received error response: '%.*s'", (int) route53->respsz,
              route53->resp);
          }

          (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
            "received error: code = %s (%u), msg = %s, req_id = %s",
            aws_error_get_name(err->err_code, fmt), err->err_code, err->err_msg,
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

static array_header *parse_ipranges_xml(pool *p, void *parent, const char *name,
    size_t name_len) {
  void *elt;
  unsigned long count = 0;
  array_header *ranges;
  pool *tmp_pool;

  ranges = make_array(p, 0, sizeof(pr_netacl_t **));

  (void) aws_xml_elt_get_child_count(p, parent, &count);
  if (count == 0) {
    pr_trace_msg(trace_channel, 5,
      "expected multiple IP ranges, found %lu", count);
    return ranges;
  }

  tmp_pool = make_sub_pool(p);
  elt = aws_xml_elt_get_child(p, parent, name, name_len);
  while (elt != NULL) {
    char *elt_text;
    pr_netacl_t *range;

    pr_signals_handle();

    elt_text = (char *) aws_xml_elt_get_text(tmp_pool, elt);
    range = pr_netacl_create(p, elt_text);
    if (range != NULL) {
      *((pr_netacl_t **) push_array(ranges)) = range;

    } else {
      pr_trace_msg(trace_channel, 8,
        "error parsing '%s' as netacl: %s", elt_text, strerror(errno));
    }

    elt = aws_xml_elt_get_next(p, elt);
  }

  destroy_pool(tmp_pool);
  return ranges;
}

static array_header *parse_ranges_xml(pool *p, const char *data,
    size_t datasz) {
  void *doc, *root, *info;
  array_header *ranges = NULL;
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
  if (elt_namelen != 26 ||
      strncmp(elt_name, "GetCheckerIpRangesResponse",
        elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  info = aws_xml_elt_get_child(p, root, "CheckerIpRanges", 15);
  if (info == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  ranges = parse_ipranges_xml(p, info, "member", 6);

  aws_xml_doc_free(p, doc);
  return ranges;
}

array_header *aws_route53_get_healthcheck_ranges(pool *p,
    struct route53_conn *route53) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params, *ranges = NULL;

  req_pool = make_sub_pool(route53->pool);
  pr_pool_tag(req_pool, "Route53 Request Pool");
  route53->req_pool = req_pool;

  path = "/2013-04-01/checkeripranges";

  query_params = make_array(req_pool, 0, sizeof(char *));

  res = route53_get(p, route53->http, path, query_params, route53_resp_cb,
    route53);
  if (res == 0) {
    pr_trace_msg(trace_channel, 19,
      "healthcheck ranges response: '%.*s'", (int) route53->respsz,
      route53->resp);
    ranges = parse_ranges_xml(p, route53->resp, route53->respsz);
    if (ranges == NULL) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error parsing healthcheck ranges XML response: %s", strerror(errno));
    }
  }

  if (ranges != NULL) {
    register unsigned int i;
    pr_netacl_t **acls;

    pr_trace_msg(trace_channel, 15,
      "received healthcheck range count = %d", ranges->nelts);
    acls = ranges->elts;
    for (i = 0; i < ranges->nelts; i++) {
      pr_trace_msg(trace_channel, 15,
        "  range: %s", pr_netacl_get_str(req_pool, acls[i]));
    }
  }

  clear_response(route53);
  return ranges;
}

static struct route53_hosted_zone *parse_hostzone_xml(pool *p, void *parent) {
  void *elt, *item;
  pool *zone_pool;
  struct route53_hosted_zone *zone;

  zone_pool = make_sub_pool(p);
  zone = pcalloc(zone_pool, sizeof(struct route53_hosted_zone));
  zone->pool = zone_pool;

  elt = aws_xml_elt_get_child(p, parent, "Id", 2);
  if (elt != NULL) {
    char *elt_text;

    elt_text = (char *) aws_xml_elt_get_text(zone_pool, elt);
    if (elt_text != NULL) {
      char *ptr;

      ptr = elt_text;

      /* Skip past the "/hostedzone/" prefix. */
      if (strncmp(ptr, "/hostedzone/", 12) == 0) {
        ptr += 12;
      }

      zone->zone_id = ptr;
    }
  }

  /* The values of these <Name> elements look like: "example.com." */
  elt = aws_xml_elt_get_child(p, parent, "Name", 4);
  if (elt != NULL) {
    zone->domain_name = (char *) aws_xml_elt_get_text(zone_pool, elt);
  }

  elt = aws_xml_elt_get_child(p, parent, "CallerReference", 15);
  if (elt != NULL) {
    zone->reference = (char *) aws_xml_elt_get_text(zone_pool, elt);
  }

  item = aws_xml_elt_get_child(p, parent, "Config", 6);
  if (item != NULL) {
    elt = aws_xml_elt_get_child(p, item, "Comment", 8);
    if (elt != NULL) {
      zone->comment = (char *) aws_xml_elt_get_text(zone_pool, elt);
    }

    elt = aws_xml_elt_get_child(p, item, "PrivateZone", 11);
    if (elt != NULL) {
      char *elt_text;
      int private;

      elt_text = (char *) aws_xml_elt_get_text(zone_pool, elt);
      private = pr_str_is_boolean(elt_text);
      if (private < 0) {
        pr_trace_msg(trace_channel, 5,
          "error parsing <PrivateZone> value '%s' as Boolean: %s", elt_text,
          strerror(errno));

      } else {
        zone->private = private;
      }
    }
  }

  return zone;
}

static struct route53_hosted_zone *parse_hostzone_fqdn_xml(pool *p,
    void *parent, const char *name, size_t namelen, const char *fqdn) {
  void *kid;
  unsigned long count;
  size_t fqdnsz;
  struct route53_hosted_zone *fqdn_zone = NULL;

  (void) aws_xml_elt_get_child_count(p, parent, &count);
  if (count == 0) {
    pr_trace_msg(trace_channel, 5,
      "expected multiple hosted zones, found %lu", count);
    errno = ENOENT;
    return NULL;
  }

  /* The <Name> elements contain zone names which end in a period.  Make
   * sure the given FQDN ends with a period as well, for better/easier
   * comparison.
   */
  fqdnsz = strlen(fqdn);
  if (fqdn[fqdnsz-1] != '.') {
    fqdn = pstrcat(p, fqdn, ".", NULL);
    fqdnsz += 1;
  }

  kid = aws_xml_elt_get_child(p, parent, name, namelen);
  while (kid != NULL) {
    struct route53_hosted_zone *zone;

    pr_signals_handle();

    zone = parse_hostzone_xml(p, kid);
    if (zone != NULL) {
      size_t domain_namesz;

      domain_namesz = strlen(zone->domain_name);
      if (pr_strnrstr(fqdn, fqdnsz, zone->domain_name,
          domain_namesz, 0) == TRUE) {
        fqdn_zone = zone;
        break;
      }
    }

    kid = aws_xml_elt_get_next(p, kid);
  }

  if (fqdn_zone == NULL) {
    errno = ENOENT;
  }

  return fqdn_zone;
}

static struct route53_hosted_zone *parse_hostedzones_xml(pool *p,
    const char *data, size_t datasz, const char *fqdn) {
  void *doc, *root, *info, *elt;
  struct route53_hosted_zone *zone;
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
  if (elt_namelen != 23 ||
      strncmp(elt_name, "ListHostedZonesResponse",
        elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  elt = aws_xml_elt_get_child(p, root, "IsTruncated", 11);
  if (elt != NULL) {
    char *elt_text;
    int truncated;

    elt_text = (char *) aws_xml_elt_get_text(p, elt);
    truncated = pr_str_is_boolean(elt_text);
    if (truncated < 0) {
      pr_trace_msg(trace_channel, 5,
        "error parsing <IsTruncated> value '%s' as Boolean: %s", elt_text,
        strerror(errno));

    } else {
      pr_trace_msg(trace_channel, 19,
        "hosted zones response: truncated = %s", truncated ? "true" : "false");
    }

  } else {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  info = aws_xml_elt_get_child(p, root, "HostedZones", 11);
  if (info == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  zone = parse_hostzone_fqdn_xml(p, info, "HostedZone", 10, fqdn);

  aws_xml_doc_free(p, doc);
  return zone;
}

struct route53_hosted_zone *aws_route53_get_hosted_zone(pool *p,
    struct route53_conn *route53, const char *fqdn) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  struct route53_hosted_zone *zone = NULL;

  if (p == NULL ||
      route53 == NULL ||
      fqdn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  req_pool = make_sub_pool(route53->pool);
  pr_pool_tag(req_pool, "Route53 Request Pool");
  route53->req_pool = req_pool;

  path = "/2013-04-01/hostedzone";

  /* Note: do any of these query parameters need to be URL-encoded?  Per the
   * AWS docs, the answer is "yes".
   */

  query_params = make_array(req_pool, 0, sizeof(char *));

  res = route53_get(p, route53->http, path, query_params, route53_resp_cb,
    route53);
  if (res == 0) {
    struct route53_hosted_zone *found;

    pr_trace_msg(trace_channel, 19,
      "hosted zones response: '%.*s'", (int) route53->respsz, route53->resp);

    found = parse_hostedzones_xml(req_pool, route53->resp, route53->respsz,
      fqdn);
    if (found == NULL) {
      if (errno != ENOENT) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error parsing hosted zones XML response: %s", strerror(errno));
      }

    } else {
      pool *zone_pool;

      /* Make a duplicate of the found data. */
      zone_pool = make_sub_pool(p);
      pr_pool_tag(zone_pool, "AWS Route53 Hosted Zone Pool");

      zone = pcalloc(zone_pool, sizeof(struct route53_hosted_zone));
      zone->pool = zone_pool;
      zone->zone_id = pstrdup(zone->pool, found->zone_id);
      zone->domain_name = pstrdup(zone->pool, found->domain_name);

      if (found->reference != NULL) {
        zone->reference = pstrdup(zone->pool, found->reference);
      }

      if (found->comment != NULL) {
        zone->comment = pstrdup(zone->pool, found->comment);
      }

      zone->private = found->private;
    }
  }

  if (zone != NULL) {
    pr_trace_msg(trace_channel, 15,
      "received hosted zone: zone ID = %s, domain name = %s, reference = %s, "
      "comment = %s, private = %s", zone->zone_id, zone->domain_name,
      zone->reference ? zone->reference : "N/A",
      zone->comment ? zone->comment : "N/A", zone->private ? "true" : "false");
  }

  clear_response(route53);
  return zone;
}

static struct route53_rrset *parse_rrset_xml(pool *p, void *parent) {
  void *elt;
  pool *rrset_pool;
  struct route53_rrset *rrset;

  rrset_pool = make_sub_pool(p);
  rrset = pcalloc(rrset_pool, sizeof(struct route53_rrset));
  rrset->pool = rrset_pool;

  elt = aws_xml_elt_get_child(p, parent, "Name", 4);
  if (elt != NULL) {
    char *elt_text;

    elt_text = (char *) aws_xml_elt_get_text(rrset_pool, elt);
    rrset->domain_name = elt_text;
  }

  elt = aws_xml_elt_get_child(p, parent, "Type", 4);
  if (elt != NULL) {
    char *elt_text;

    elt_text = (char *) aws_xml_elt_get_text(rrset_pool, elt);
    if (elt_text != NULL) {
      size_t elt_textlen;

      elt_textlen = strlen(elt_text);
      if (elt_textlen == 1 &&
          strncmp(elt_text, "A", 2) == 0) {
        rrset->type = AWS_ROUTE53_RRSET_TYPE_A;

      } else if (elt_textlen == 4 &&
                 strncmp(elt_text, "AAAA", 5) == 0) {
        rrset->type = AWS_ROUTE53_RRSET_TYPE_AAAA;

      } else if (elt_textlen == 5 &&
                 strncmp(elt_text, "CNAME", 6) == 0) {
        rrset->type = AWS_ROUTE53_RRSET_TYPE_CNAME;

      } else {
        pr_trace_msg(trace_channel, 4,
          "unknown/unsupported rrset type for '%s': %s", rrset->domain_name,
          elt_text);
      }
    }
  }

  elt = aws_xml_elt_get_child(p, parent, "TTL", 3);
  if (elt != NULL) {
    char *elt_text;
    int ttl_secs;

    elt_text = (char *) aws_xml_elt_get_text(rrset_pool, elt);
    ttl_secs = atoi(elt_text);
    if (ttl_secs < 0) {
      pr_trace_msg(trace_channel, 4,
        "unexpected/illegal TTL value for '%s': %s", rrset->domain_name,
        elt_text);

    } else {
      rrset->ttl_secs = ttl_secs;
    }
  }

  elt = aws_xml_elt_get_child(p, parent, "HealthCheckId", 13);
  if (elt != NULL) {
    char *elt_text;

    elt_text = (char *) aws_xml_elt_get_text(rrset_pool, elt);
    rrset->healthcheck_id = elt_text;
  }

  return rrset;
}

static struct route53_rrset *parse_rrsets_fqdn_xml(pool *p, void *parent,
    const char *name, size_t namelen, const char *fqdn) {
  void *kid;
  unsigned long count;
  size_t fqdnsz;
  struct route53_rrset *fqdn_rrset = NULL;

  (void) aws_xml_elt_get_child_count(p, parent, &count);
  if (count == 0) {
    pr_trace_msg(trace_channel, 5,
      "expected multiple rrsets, found %lu", count);
    errno = ENOENT;
    return NULL;
  }

  /* The <Name> elements contain zone names which end in a period.  Make
   * sure the given FQDN ends with a period as well, for better/easier
   * comparison.
   */
  fqdnsz = strlen(fqdn);
  if (fqdn[fqdnsz-1] != '.') {
    fqdn = pstrcat(p, fqdn, ".", NULL);
    fqdnsz += 1;
  }

  kid = aws_xml_elt_get_child(p, parent, name, namelen);
  while (kid != NULL) {
    struct route53_rrset *rrset;

    pr_signals_handle();

    rrset = parse_rrset_xml(p, kid);
    if (rrset != NULL) {

      /* Only look for A, AAAA, CNAME rrsets. */
      if (rrset->type != AWS_ROUTE53_RRSET_TYPE_A &&
          rrset->type != AWS_ROUTE53_RRSET_TYPE_AAAA &&
          rrset->type != AWS_ROUTE53_RRSET_TYPE_CNAME) {
        kid = aws_xml_elt_get_next(p, kid);
        continue;
      }

      if (strncmp(rrset->domain_name, fqdn, fqdnsz) == 0) {
        fqdn_rrset = rrset;
        break;
      }
    }

    kid = aws_xml_elt_get_next(p, kid);
  }

  if (fqdn_rrset == NULL) {
    errno = ENOENT;
  }

  return fqdn_rrset;
}

static struct route53_rrset *parse_rrsets_xml(pool *p, const char *data,
    size_t datasz, const char *fqdn) {
  void *doc, *root, *info;
  struct route53_rrset *rrset;
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
      strncmp(elt_name, "ListResourceRecordSetsResponse",
        elt_namelen + 1) != 0) {

    /* Not the root element we expected. */
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  info = aws_xml_elt_get_child(p, root, "ResourceRecordSets", 18);
  if (info == NULL) {
    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  rrset = parse_rrsets_fqdn_xml(p, info, "ResourceRecordSet", 17, fqdn);

  aws_xml_doc_free(p, doc);
  return rrset;
}

struct route53_rrset *aws_route53_get_rrset(pool *p,
    struct route53_conn *route53, const char *zone_id, const char *fqdn) {
  int res;
  const char *path;
  pool *req_pool;
  array_header *query_params;
  struct route53_rrset *rrset = NULL;

  if (p == NULL ||
      route53 == NULL ||
      zone_id == NULL ||
      fqdn == NULL) {
    errno = EINVAL;
    return NULL;
  }

  req_pool = make_sub_pool(route53->pool);
  pr_pool_tag(req_pool, "Route53 Request Pool");
  route53->req_pool = req_pool;

  path = pstrcat(req_pool, "/2013-04-01/hostedzone/", zone_id, "/rrset", NULL);

  /* Note: do any of these query parameters need to be URL-encoded?  Per the
   * AWS docs, the answer is "yes".
   */

  query_params = make_array(req_pool, 0, sizeof(char *));

  *((char **) push_array(query_params)) = pstrcat(req_pool,
    "name=", fqdn, NULL);

  res = route53_get(p, route53->http, path, query_params, route53_resp_cb,
    route53);
  if (res == 0) {
    struct route53_rrset *found;

    pr_trace_msg(trace_channel, 19,
      "resource record sets response: '%.*s'", (int) route53->respsz,
      route53->resp);

    found = parse_rrsets_xml(req_pool, route53->resp, route53->respsz, fqdn);
    if (found == NULL) {
      if (errno != ENOENT) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error parsing resource record sets XML response: %s",
          strerror(errno));
      }

    } else {
      pool *rrset_pool;

      /* Make a duplicate of the found data. */
      rrset_pool = make_sub_pool(p);
      pr_pool_tag(rrset_pool, "AWS Route53 ResourceRecordSets Pool");

      rrset = pcalloc(rrset_pool, sizeof(struct route53_rrset));
      rrset->pool = rrset_pool;
      rrset->domain_name = pstrdup(rrset->pool, found->domain_name);
      rrset->type = found->type;
      rrset->ttl_secs = found->ttl_secs;

      if (found->healthcheck_id != NULL) {
        rrset->healthcheck_id = pstrdup(rrset->pool, found->healthcheck_id);
      }
    }
  }

  if (rrset != NULL) {
    const char *rrset_type;

    switch (rrset->type) {
      case AWS_ROUTE53_RRSET_TYPE_UNKNOWN:
        rrset_type = "Unknown";
        break;

      case AWS_ROUTE53_RRSET_TYPE_A:
        rrset_type = "A";
        break;

      case AWS_ROUTE53_RRSET_TYPE_AAAA:
        rrset_type = "AAAA";
        break;

      case AWS_ROUTE53_RRSET_TYPE_CNAME:
        rrset_type = "CNAME";
        break;

      default:
        rrset_type = "Unknown/unsupported";
        break;
    }

    pr_trace_msg(trace_channel, 15,
      "received rrset: domain name = %s, type = %s, ttl = %u, "
      "health check ID = %s", rrset->domain_name, rrset_type, rrset->ttl_secs,
      rrset->healthcheck_id ? rrset->healthcheck_id : "N/A");
  }

  clear_response(route53);
  return rrset;
}
