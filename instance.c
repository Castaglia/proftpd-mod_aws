/*
 * ProFTPD - mod_aws EC2 instance info
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
#include "instance.h"

#ifdef HAVE_CURL_CURL_H
# include <curl/curl.h>
#endif

static char curl_errorbuf[CURL_ERROR_SIZE];

static const char *trace_channel = "aws.instance";

/* To discover the EC2 instance metadata for this instance, we query/use the
 * information available via:
 *
 *  http://169.254.169.254/latest/meta-data/
 *  http://169.254.169.254/latest/dynamic/instance-identity/document
 *
 */

#define AWS_HTTP_RESPONSE_CODE_OK		200L
#define AWS_HTTP_RESPONSE_CODE_BAD_REQUEST	400L
#define AWS_HTTP_RESPONSE_CODE_NOT_FOUND	404L

#define AWS_INSTANCE_METADATA_HOST	"169.254.169.254"
#define AWS_INSTANCE_METADATA_URL	"http://" AWS_INSTANCE_METADATA_HOST "/latest/meta-data"
#define AWS_INSTANCE_DYNAMIC_URL	"http://" AWS_INSTANCE_METADATA_HOST "/latest/dynamic"

static int get_url(pool *p, CURL *curl, struct aws_info *info, const char *url,
    size_t (*handle_body)(char *, size_t, size_t, void *)) {
  CURLcode curl_code;
  long resp_code;
  double content_len, rcvd_bytes, total_secs;
  char *content_type = NULL;

  curl_code = curl_easy_setopt(curl, CURLOPT_URL, url);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_URL '%s': %s", url, curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, handle_body);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_WRITEFUNCTION: %s", curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, info);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_WRITEDATA: %s", curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  /* Clear error buffer, response message before performing request,
   * per docs.
   */
  curl_errorbuf[0] = '\0';
  info->last_resp_msg = NULL;

  curl_code = curl_easy_perform(curl);
  if (curl_code != CURLE_OK) {
    size_t error_len;

    error_len = strlen(curl_errorbuf);
    if (error_len > 0) {
      pr_trace_msg(trace_channel, 1,
        "'%s' request error: %s", url, curl_errorbuf);

      /* Note: What other error strings should we search for here? */
      if (strstr(curl_errorbuf, "Could not resolve host") != NULL) {
        errno = ESRCH;

      } else if (strstr(curl_errorbuf, "Connection timed out") != NULL) {
        /* Hit our AWSTimeoutConnect? */
        errno = ETIMEDOUT;

      } else {
        /* Generic error */
        errno = EPERM;
      }

    } else {
      pr_trace_msg(trace_channel, 1,
        "'%s' request error: %s", url, curl_easy_strerror(curl_code));
      errno = EPERM;
    }

    return -1;
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
  if (curl_code == CURLE_UNKNOWN_OPTION) {
    /* Use the older option name. */
    curl_code = curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &resp_code);
  }

  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 2,
      "unable to get '%s' response code: %s", url,
      curl_easy_strerror(curl_code));

    errno = EPERM;
    return -1;
  }

  if (info->last_resp_msg != NULL) {
    pr_trace_msg(trace_channel, 15,
      "received response '%ld %s' for '%s' request", resp_code,
      info->last_resp_msg, url);

  } else {
    pr_trace_msg(trace_channel, 15,
      "received response code %ld for '%s' request", resp_code, url);
  }

  /* Note: should we handle other response codes? */
  switch (resp_code) {
    case AWS_HTTP_RESPONSE_CODE_OK:
      break;

    case AWS_HTTP_RESPONSE_CODE_BAD_REQUEST:
      pr_trace_msg(trace_channel, 2,
        "received %ld response code for '%s' request", resp_code, url);
      errno = EINVAL;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_NOT_FOUND:
      pr_trace_msg(trace_channel, 2,
        "received %ld response code for '%s' request", resp_code, url);
      errno = ENOENT;
      return -1;

    default:
      pr_trace_msg(trace_channel, 2,
        "received %ld response code for '%s' request", resp_code, url);
      errno = EPERM;
      return -1;
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
    &content_len);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "received Content-Length %0.0lf for '%s' request", content_len, url);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_CONTENT_LENGTH_DOWNLOAD: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
  if (curl_code == CURLE_OK) {
    if (content_type != NULL) {
      pr_trace_msg(trace_channel, 15,
        "received Content-Type '%s' for '%s' request", content_type, url);
    }

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_CONTENT_TYPE: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_secs);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "'%s' request took %0.3lf secs", url, total_secs);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_TOTAL_TIME: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &rcvd_bytes);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "received %0.0lf bytes for '%s' request", rcvd_bytes, url);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_SIZE_DOWNLOAD: %s",
      curl_easy_strerror(curl_code));
  }

  return 0;
}

/* Domain */
static size_t domain_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->domainsz == 0) {
    info->domainsz = datasz;
    ptr = info->domain = palloc(info->pool, info->domainsz);

  } else {
    ptr = info->domain;
    info->domain = palloc(info->pool, info->domainsz + datasz);
    memcpy(info->domain, ptr, info->domainsz);

    ptr = info->domain + info->domainsz;
    info->domainsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_domain(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/services/domain";

  res = get_url(p, curl, info, url, domain_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->domainsz = 0;
    info->domain = NULL;
  }

  return res;
}

/* Availability zone */
static size_t avail_zone_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->avail_zonesz == 0) {
    info->avail_zonesz = datasz;
    ptr = info->avail_zone = palloc(info->pool, info->avail_zonesz);

  } else {
    ptr = info->avail_zone;
    info->avail_zone = palloc(info->pool, info->avail_zonesz + datasz);
    memcpy(info->avail_zone, ptr, info->avail_zonesz);

    ptr = info->avail_zone + info->avail_zonesz;
    info->avail_zonesz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_avail_zone(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/placement/availability-zone";

  res = get_url(p, curl, info, url, avail_zone_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->avail_zonesz = 0;
    info->avail_zone = NULL;
  }

  return res;
}

/* Instance type */
static size_t instance_type_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->instance_typesz == 0) {
    info->instance_typesz = datasz;
    ptr = info->instance_type = palloc(info->pool, info->instance_typesz);

  } else {
    ptr = info->instance_type;
    info->instance_type = palloc(info->pool, info->instance_typesz + datasz);
    memcpy(info->instance_type, ptr, info->instance_typesz);

    ptr = info->instance_type + info->instance_typesz;
    info->instance_typesz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_instance_type(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/instance-type";

  res = get_url(p, curl, info, url, instance_type_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->instance_typesz = 0;
    info->instance_type = NULL;
  }

  return res;
}

/* Instance ID */
static size_t instance_id_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->instance_idsz == 0) {
    info->instance_idsz = datasz;
    ptr = info->instance_id = palloc(info->pool, info->instance_idsz);

  } else {
    ptr = info->instance_id;
    info->instance_id = palloc(info->pool, info->instance_idsz + datasz);
    memcpy(info->instance_id, ptr, info->instance_idsz);

    ptr = info->instance_id + info->instance_idsz;
    info->instance_idsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_instance_id(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/instance-id";

  res = get_url(p, curl, info, url, instance_id_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->instance_idsz = 0;
    info->instance_id = NULL;
  }

  return res;
}

/* AMI ID */
static size_t ami_id_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->ami_idsz == 0) {
    info->ami_idsz = datasz;
    ptr = info->ami_id = palloc(info->pool, info->ami_idsz);

  } else {
    ptr = info->ami_id;
    info->ami_id = palloc(info->pool, info->ami_idsz + datasz);
    memcpy(info->ami_id, ptr, info->ami_idsz);

    ptr = info->ami_id + info->ami_idsz;
    info->ami_idsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_ami_id(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/ami-id";

  res = get_url(p, curl, info, url, ami_id_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->ami_idsz = 0;
    info->ami_id = NULL;
  }

  return res;
}

/* IAM role */
static size_t iam_role_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->iam_rolesz == 0) {
    info->iam_rolesz = datasz;
    ptr = info->iam_role = palloc(info->pool, info->iam_rolesz);

  } else {
    ptr = info->iam_role;
    info->iam_role = palloc(info->pool, info->iam_rolesz + datasz);
    memcpy(info->iam_role, ptr, info->iam_rolesz);

    ptr = info->iam_role + info->iam_rolesz;
    info->iam_rolesz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_iam_role(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  /* Note: the trailing slash in this URL is important, and is NOT a typo. */
  url = AWS_INSTANCE_METADATA_URL "/iam/security-credentials/";

  res = get_url(p, curl, info, url, iam_role_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->iam_rolesz = 0;
    info->iam_role = NULL;
  }

  return res;
}

/* Hardware MAC */
static size_t hw_mac_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->hw_macsz == 0) {
    info->hw_macsz = datasz;
    ptr = info->hw_mac = palloc(info->pool, info->hw_macsz);

  } else {
    ptr = info->hw_mac;
    info->hw_mac = palloc(info->pool, info->hw_macsz + datasz);
    memcpy(info->hw_mac, ptr, info->hw_macsz);

    ptr = info->hw_mac + info->hw_macsz;
    info->hw_macsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_hw_mac(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/mac";

  res = get_url(p, curl, info, url, hw_mac_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->hw_macsz = 0;
    info->hw_mac = NULL;
  }

  return res;
}

/* VPC ID */
static size_t vpc_id_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->vpc_idsz == 0) {
    info->vpc_idsz = datasz;
    ptr = info->vpc_id = palloc(info->pool, info->vpc_idsz);

  } else {
    ptr = info->vpc_id;
    info->vpc_id = palloc(info->pool, info->vpc_idsz + datasz);
    memcpy(info->vpc_id, ptr, info->vpc_idsz);

    ptr = info->vpc_id + info->vpc_idsz;
    info->vpc_idsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_vpc_id(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  /* If we don't know the MAC, then we cannot find the VPC ID. */
  if (info->hw_mac == NULL) {
    pr_trace_msg(trace_channel, 9, "unable to discover vpc.id without hw.mac");
    errno = EPERM;
    return -1;
  }

  url = pstrcat(p, AWS_INSTANCE_METADATA_URL, "/network/interfaces/macs/",
    info->hw_mac, "/vpc-id", NULL);

  res = get_url(p, curl, info, url, vpc_id_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->vpc_idsz = 0;
    info->vpc_id = NULL;
  }

  return res;
}

/* Local IPv4 */
static size_t local_ipv4_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->local_ipv4sz == 0) {
    info->local_ipv4sz = datasz;
    ptr = info->local_ipv4 = palloc(info->pool, info->local_ipv4sz);

  } else {
    ptr = info->local_ipv4;
    info->local_ipv4 = palloc(info->pool, info->local_ipv4sz + datasz);
    memcpy(info->local_ipv4, ptr, info->local_ipv4sz);

    ptr = info->local_ipv4 + info->local_ipv4sz;
    info->local_ipv4sz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_local_ipv4(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/local-ipv4";

  res = get_url(p, curl, info, url, local_ipv4_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->local_ipv4sz = 0;
    info->local_ipv4 = NULL;
  }

  return res;
}

/* Local hostname */
static size_t local_hostname_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->local_hostnamesz == 0) {
    info->local_hostnamesz = datasz;
    ptr = info->local_hostname = palloc(info->pool, info->local_hostnamesz);

  } else {
    ptr = info->local_hostname;
    info->local_hostname = palloc(info->pool, info->local_hostnamesz + datasz);
    memcpy(info->local_hostname, ptr, info->local_hostnamesz);

    ptr = info->local_hostname + info->local_hostnamesz;
    info->local_hostnamesz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_local_hostname(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/local-hostname";

  res = get_url(p, curl, info, url, local_hostname_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->local_hostnamesz = 0;
    info->local_hostname = NULL;
  }

  return res;
}

/* Public IPv4 */
static size_t public_ipv4_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->public_ipv4sz == 0) {
    info->public_ipv4sz = datasz;
    ptr = info->public_ipv4 = palloc(info->pool, info->public_ipv4sz);

  } else {
    ptr = info->public_ipv4;
    info->public_ipv4 = palloc(info->pool, info->public_ipv4sz + datasz);
    memcpy(info->public_ipv4, ptr, info->public_ipv4sz);

    ptr = info->public_ipv4 + info->public_ipv4sz;
    info->public_ipv4sz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_public_ipv4(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/public-ipv4";

  res = get_url(p, curl, info, url, public_ipv4_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->public_ipv4sz = 0;
    info->public_ipv4 = NULL;
  }

  return res;
}

/* Public hostname */
static size_t public_hostname_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->public_hostnamesz == 0) {
    info->public_hostnamesz = datasz;
    ptr = info->public_hostname = palloc(info->pool, info->public_hostnamesz);

  } else {
    ptr = info->public_hostname;
    info->public_hostname = palloc(info->pool,
      info->public_hostnamesz + datasz);
    memcpy(info->public_hostname, ptr, info->public_hostnamesz);

    ptr = info->public_hostname + info->public_hostnamesz;
    info->public_hostnamesz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_public_hostname(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/public-hostname";

  res = get_url(p, curl, info, url, public_hostname_cb);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->public_hostnamesz = 0;
    info->public_hostname = NULL;
  }

  return res;
}

/* Security groups */
static size_t security_groups_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->sg_namessz == 0) {
    info->sg_namessz = datasz;
    ptr = info->sg_names = palloc(info->pool, info->sg_namessz);

  } else {
    ptr = info->sg_names;
    info->sg_names = palloc(info->pool, info->sg_namessz + datasz);
    memcpy(info->sg_names, ptr, info->sg_namessz);

    ptr = info->sg_names + info->sg_namessz;
    info->sg_namessz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_security_groups(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/security-groups";

  res = get_url(p, curl, info, url, security_groups_cb);
  if (res == 0) {
    /* XXX Post-process info->sg_names into an array_header. */

  } else if (res < 0 &&
             errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->sg_namessz = 0;
    info->sg_names = NULL;
  }

  return res;
}

/* Identity doc */
static size_t identity_doc_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->identity_docsz == 0) {
    info->identity_docsz = datasz;
    ptr = info->identity_doc = palloc(info->pool, info->identity_docsz);

  } else {
    ptr = info->identity_doc;
    info->identity_doc = palloc(info->pool, info->identity_docsz + datasz);
    memcpy(info->identity_doc, ptr, info->identity_docsz);

    ptr = info->identity_doc + info->identity_docsz;
    info->identity_docsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_identity_doc(pool *p, CURL *curl, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_DYNAMIC_URL "/instance-identity/document";

  res = get_url(p, curl, info, url, identity_doc_cb);
  if (res == 0) {
    /* XXX Post-process the identity doc JSON into account_id, region */

  } else if (res < 0 &&
             errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->identity_docsz = 0;
    info->identity_doc = NULL;
  }

  return res;
}

/* Gather up the EC2 instance metadata. */
static int get_info(pool *p, CURL *curl, struct aws_info *info) {
  int res;

  /* Note: the ESRCH errno value is used here by get_url() to indicate that
   * the requested host could not be resolved/does not exist.
   */

  res = get_domain(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_avail_zone(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_instance_type(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_instance_id(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_ami_id(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_iam_role(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_hw_mac(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_vpc_id(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_local_ipv4(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_local_hostname(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_public_ipv4(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_public_hostname(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_security_groups(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_identity_doc(p, curl, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  return 0;
}

static size_t curl_header_cb(char *data, size_t itemsz, size_t item_count,
    void *user_data) {
  CURL *curl;
  size_t datasz;

  curl = user_data;
  datasz = itemsz * item_count;

  /* Fortunately, only COMPLETE headers are passed to us, so that we do not
   * need to do any buffering.  Be aware that the header data may NOT be
   * NUL-terminated.
   */

  if (strncmp(data, "HTTP/1.0 ", 9) == 0 ||
      strncmp(data, "HTTP/1.1 ", 9) == 0) {
    struct aws_info *info = NULL;
    CURLcode curl_code;

    /* We're receiving the HTTP response status line. */

    curl_code = curl_easy_getinfo(curl, CURLINFO_PRIVATE, &info);
    if (curl_code == CURLE_OK &&
        info != NULL) {
      char *resp_msg;
      size_t resp_msglen;

      /* Advance the pointer past "HTTP/1.x NNNN "(13). And take back 2,
       * for whose CRLF this line is.
       */
      resp_msg = data + 13;
      resp_msglen = datasz - 13 - 2;

      info->last_resp_msg = pstrndup(info->pool, resp_msg, resp_msglen);

    } else {
      pr_trace_msg(trace_channel, 3,
        "unable to get CURLINFO_PRIVATE: %s",
        curl_easy_strerror(curl_code));
    }
  }

  return datasz;
}

static int curl_trace_cb(CURL *curl, curl_infotype data_type, char *data,
    size_t datasz, void *user_data) {

  /* Tell the compiler we won't be using this argument. */
  (void) curl;

  switch (data_type) {
    case CURLINFO_TEXT:
      pr_trace_msg(trace_channel, 15, "[debug] INFO: %s", data);
      break;

    case CURLINFO_HEADER_IN:
      if (datasz > 2) {
        pr_trace_msg(trace_channel, 15,
          "[debug] HEADER IN: %.*s (%ld bytes)", (int) datasz-2, data, datasz);
      }
      break;

    case CURLINFO_HEADER_OUT:
      if (datasz > 2) {
        pr_trace_msg(trace_channel, 15,
          "[debug] HEADER OUT: %.*s (%ld bytes)", (int) datasz-2, data, datasz);
      }
      break;

    case CURLINFO_DATA_IN:
      pr_trace_msg(trace_channel, 19,
        "[debug] DATA IN: (%ld bytes)", datasz);
      break;

    case CURLINFO_DATA_OUT:
      pr_trace_msg(trace_channel, 19,
        "[debug] DATA OUT: (%ld bytes)", datasz);
      break;

    case CURLINFO_SSL_DATA_IN:
      pr_trace_msg(trace_channel, 19,
        "[debug] SSL DATA IN: (%ld bytes)", datasz);
      break;

    case CURLINFO_SSL_DATA_OUT:
      pr_trace_msg(trace_channel, 19,
        "[debug] SSL DATA OUT: (%ld bytes)", datasz);
      break;

    default:
      pr_trace_msg(trace_channel, 3,
        "[debug] UNKNOWN DEBUG DATA: %d", (int) data_type);
      break;
  }

  return 0;
}

struct aws_info *aws_instance_get_info(pool *p, unsigned long max_connect_secs,
    unsigned long max_request_secs) {
  int res, xerrno = 0;
  pool *info_pool;
  struct aws_info *info;
  CURL *curl;
  CURLcode curl_code;

  /* XXX use an easy handle, then clean it up when we're done; we don't need
   * to keep persistent connections open to the metadata service after
   * discovery.
   */

  curl = curl_easy_init();
  if (curl == NULL) {
    pr_trace_msg(trace_channel, 3,
      "error initializing curl easy handle");
    errno = ENOMEM;
    return NULL;
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_FOLLOWLOCATION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_NOPROGRESS: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_NOSIGNAL: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_TCP_NODELAY: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_TCP_KEEPALIVE: %s",
      curl_easy_strerror(curl_code));
  }

  /* HTTP-isms. */
  curl_code = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
    CURL_HTTP_VERSION_1_1);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HTTP_VERSION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HTTPGET: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_USERAGENT, MOD_AWS_VERSION);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_USERAGENT: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_cb);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HEADERFUNCTION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_HEADERDATA, curl);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HEADERDATA: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_trace_cb);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_DEBUGFUNCTION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_DEBUGDATA: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_VERBOSE: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errorbuf);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_ERRORBUFFER: %s",
      curl_easy_strerror(curl_code));
  }

  /* Timeouts */
  curl_code = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
    (long) max_connect_secs);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_CONNECTTIMEOUT: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) max_request_secs);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_TIMEOUT: %s",
      curl_easy_strerror(curl_code));
  }

  info_pool = make_sub_pool(p);
  pr_pool_tag(info_pool, "Instance info pool");

  info = pcalloc(info_pool, sizeof(struct aws_info));
  info->pool = info_pool;

  curl_code = curl_easy_setopt(curl, CURLOPT_PRIVATE, info);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_PRIVATE: %s",
      curl_easy_strerror(curl_code));
  }

  res = get_info(p, curl, info);
  xerrno = errno;

  curl_easy_cleanup(curl);

  if (res < 0) {
    info = NULL;
    errno = xerrno;
  }

  return info;
}
