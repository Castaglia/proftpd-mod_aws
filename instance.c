/*
 * ProFTPD - mod_aws EC2 instance info
 * Copyright (c) 2016-2017 TJ Saunders
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
#include "ccan-json.h"

static const char *trace_channel = "aws.instance";

static int get_metadata(pool *p, void *http, const char *url,
    size_t (*resp_body)(char *, size_t, size_t, void *),
    void *user_data) {
  int res;
  long resp_code;

  res = aws_http_get(p, http, url, NULL, resp_body, user_data, &resp_code,
    NULL);
  if (res < 0) {
    return -1;
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

static int get_domain(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/services/domain";

  res = get_metadata(p, http, url, domain_cb, info);
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

static int get_avail_zone(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/placement/availability-zone";

  res = get_metadata(p, http, url, avail_zone_cb, info);
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

static int get_instance_type(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/instance-type";

  res = get_metadata(p, http, url, instance_type_cb, info);
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

static int get_instance_id(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/instance-id";

  res = get_metadata(p, http, url, instance_id_cb, info);
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

static int get_ami_id(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/ami-id";

  res = get_metadata(p, http, url, ami_id_cb, info);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->ami_idsz = 0;
    info->ami_id = NULL;
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

static int get_hw_mac(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/mac";

  res = get_metadata(p, http, url, hw_mac_cb, info);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->hw_macsz = 0;
    info->hw_mac = NULL;
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

static int get_iam_role(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  /* Note: the trailing slash in this URL is important, and is NOT a typo. */
  url = AWS_INSTANCE_METADATA_URL "/iam/security-credentials/";

  res = get_metadata(p, http, url, iam_role_cb, info);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->iam_rolesz = 0;
    info->iam_role = NULL;
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

static int get_vpc_id(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  /* If we don't know the MAC, then we cannot find the VPC ID. */
  if (info->hw_mac == NULL) {
    pr_trace_msg(trace_channel, 9,
      "unable to discover aws.vpc-id without aws.mac");
    errno = EPERM;
    return -1;
  }

  url = pstrcat(p, AWS_INSTANCE_METADATA_URL, "/network/interfaces/macs/",
    info->hw_mac, "/vpc-id", NULL);

  res = get_metadata(p, http, url, vpc_id_cb, info);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->vpc_idsz = 0;
    info->vpc_id = NULL;
  }

  return res;
}

/* Subnet ID */
static size_t subnet_id_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->subnet_idsz == 0) {
    info->subnet_idsz = datasz;
    ptr = info->subnet_id = palloc(info->pool, info->subnet_idsz);

  } else {
    ptr = info->subnet_id;
    info->subnet_id = palloc(info->pool, info->subnet_idsz + datasz);
    memcpy(info->subnet_id, ptr, info->subnet_idsz);

    ptr = info->subnet_id + info->subnet_idsz;
    info->subnet_idsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_subnet_id(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  /* If we don't know the MAC, then we cannot find the Subnet ID. */
  if (info->hw_mac == NULL) {
    pr_trace_msg(trace_channel, 9,
      "unable to discover aws.subnet-id without aws.mac");
    errno = EPERM;
    return -1;
  }

  url = pstrcat(p, AWS_INSTANCE_METADATA_URL, "/network/interfaces/macs/",
    info->hw_mac, "/subnet-id", NULL);

  res = get_metadata(p, http, url, subnet_id_cb, info);
  if (res < 0 &&
      errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->subnet_idsz = 0;
    info->subnet_id = NULL;
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

static int get_local_ipv4(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/local-ipv4";

  res = get_metadata(p, http, url, local_ipv4_cb, info);
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

static int get_local_hostname(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/local-hostname";

  res = get_metadata(p, http, url, local_hostname_cb, info);
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

static int get_public_ipv4(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/public-ipv4";

  res = get_metadata(p, http, url, public_ipv4_cb, info);
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

static int get_public_hostname(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_METADATA_URL "/public-hostname";

  res = get_metadata(p, http, url, public_hostname_cb, info);
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

  if (info->sg_idssz == 0) {
    info->sg_idssz = datasz;
    ptr = info->sg_ids = palloc(info->pool, info->sg_idssz);

  } else {
    ptr = info->sg_ids;
    info->sg_ids = palloc(info->pool, info->sg_idssz + datasz);
    memcpy(info->sg_ids, ptr, info->sg_idssz);

    ptr = info->sg_ids + info->sg_idssz;
    info->sg_idssz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_security_groups(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  /* If we don't know the MAC, then we cannot find the SG IDs. */
  if (info->hw_mac == NULL) {
    pr_trace_msg(trace_channel, 9,
      "unable to discover aws.security-groups without aws.mac");
    errno = EPERM;
    return -1;
  }

  url = pstrcat(p, AWS_INSTANCE_METADATA_URL, "/network/interfaces/macs/",
    info->hw_mac, "/security-group-ids", NULL);

  res = get_metadata(p, http, url, security_groups_cb, info);
  if (res == 0) {
    info->security_groups = make_array(info->pool, 0, sizeof(char *));

    if (info->sg_idssz > 0) {
      char *sg_ids, *ptr;

      /* Since strchr(3) wants NUL-terminated strings, we need to make one. */
      sg_ids = pstrndup(info->pool, info->sg_ids, info->sg_idssz);

      /* The list of security group IDs is LF-delimited; if there is only
       * one security group, then there is no LF.
       */
      ptr = strchr(sg_ids, '\n');
      if (ptr == NULL) {
        /* Just one SG. */
        *((char **) push_array(info->security_groups)) = sg_ids;

      } else {
        char *ptr2;

        ptr = sg_ids;
        ptr2 = strchr(ptr, '\n');
        while (ptr2 != NULL) {
          char *sg_id;

          sg_id = pstrndup(info->pool, ptr, ptr2 - ptr);
          *((char **) push_array(info->security_groups)) = sg_id;

          ptr = ptr2 + 1;
          ptr2 = strchr(ptr, '\n');
        }

        /* Don't forget to add the last SG. */
        *((char **) push_array(info->security_groups)) = ptr;
      }
    }

  } else if (res < 0 &&
             errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->sg_idssz = 0;
    info->sg_ids = NULL;
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

static int get_identity_doc(pool *p, void *http, struct aws_info *info) {
  int res;
  const char *url;

  url = AWS_INSTANCE_DYNAMIC_URL "/instance-identity/document";

  res = get_metadata(p, http, url, identity_doc_cb, info);
  if (res == 0) {
    const char *json_str;

    json_str = pstrndup(info->pool, info->identity_doc, info->identity_docsz);
    if (json_validate(json_str) == TRUE) {
      JsonNode *field, *json;
      const char *key;

      json = json_decode(json_str);

      key = "accountId";
      field = json_find_member(json, key);
      if (field != NULL) {
        if (field->tag == JSON_STRING) {
          info->account_id = pstrdup(info->pool, field->string_);

        } else {
          pr_trace_msg(trace_channel, 3,
           "ignoring non-string '%s' JSON field in '%s'", key, json_str);
        }
      }

      key = "version";
      field = json_find_member(json, key);
      if (field != NULL) {
        if (field->tag == JSON_STRING) {
          info->api_version = pstrdup(info->pool, field->string_);

        } else {
          pr_trace_msg(trace_channel, 3,
           "ignoring non-string '%s' JSON field in '%s'", key, json_str);
        }
      }

      key = "region";
      field = json_find_member(json, key);
      if (field != NULL) {
        if (field->tag == JSON_STRING) {
          info->region = pstrdup(info->pool, field->string_);

        } else {
          pr_trace_msg(trace_channel, 3,
           "ignoring non-string '%s' JSON field in '%s'", key, json_str);
        }
      }

      json_delete(json);

    } else {
      pr_trace_msg(trace_channel, 3,
        "'%s' JSON failed validation, ignoring", url);

      info->identity_docsz = 0;
      info->identity_doc = NULL;

      errno = ENOENT;
      return -1;
    }

  } else if (res < 0 &&
             errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->identity_docsz = 0;
    info->identity_doc = NULL;
  }

  return res;
}

/* Gather up the EC2 instance metadata. */
static int get_instance_info(pool *p, void *http, struct aws_info *info) {
  int res;

  /* Note: the ESRCH errno value is used here by aws_http_get() to indicate
   * that the requested host could not be resolved/does not exist.
   */

  res = get_domain(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_avail_zone(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_instance_type(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_instance_id(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_ami_id(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_iam_role(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_hw_mac(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_vpc_id(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_subnet_id(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_local_ipv4(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_local_hostname(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_public_ipv4(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_public_hostname(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_security_groups(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  res = get_identity_doc(p, http, info);
  if (res < 0 &&
      errno == ESRCH) {
    return -1;
  }

  return 0;
}

struct aws_info *aws_instance_get_info(pool *p) {
  int res, xerrno = 0;
  pool *info_pool;
  struct aws_info *info;
  void *http;

  /* The metadata URLs do not use SSL, so we don't need to provide the
   * CA certs file.  And we assume short hardcoded timeouts here.
   */
  http = aws_http_alloc(p, 1UL, 1UL, NULL);
  if (http == NULL) {
    return NULL;
  }

  info_pool = make_sub_pool(p);
  pr_pool_tag(info_pool, "Instance info pool");

  info = pcalloc(info_pool, sizeof(struct aws_info));
  info->pool = info_pool;

  res = get_instance_info(p, http, info);
  xerrno = errno;

  aws_http_destroy(p, http);

  if (res < 0) {
    destroy_pool(info_pool);
    info = NULL;
  }

  errno = xerrno;
  return info;
}
