/*
 * ProFTPD - mod_aws Route53 API
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
#include "creds.h"

#ifndef MOD_AWS_ROUTE53_H
#define MOD_AWS_ROUTE53_H

/* Route53 Connections */
struct route53_conn {
  pool *pool;

  void *http;
  const char *domain;

  /* To be refreshed whenever the credentials are deemed too old. */
  const array_header *credential_providers;
  const struct aws_credential_info *credential_info;
  struct aws_credentials *credentials;

  /* For handling request/response documents. */
  pool *req_pool;
  char *resp;
  size_t respsz;
};

/* Route53 Hosted Zones */
struct route53_hosted_zone {
  pool *pool;

  const char *zone_id;
  const char *domain_name;
  const char *reference;
  const char *comment;
  int private;
};

/* Route53 Resource Record Sets */
struct route53_rrset {
  pool *pool;

  const char *domain_name;
  unsigned int type;
  unsigned int ttl_secs;

  const char *healthcheck_id;
};

#define AWS_ROUTE53_RRSET_TYPE_UNKNOWN		0
#define AWS_ROUTE53_RRSET_TYPE_A		1
#define AWS_ROUTE53_RRSET_TYPE_AAAA		2
#define AWS_ROUTE53_RRSET_TYPE_CNAME		3

struct route53_conn *aws_route53_conn_alloc(pool *p,
  unsigned long max_connect_secs, unsigned long max_request_secs,
  const char *cacerts, const char *domain,
  const array_header *credential_providers,
  const struct aws_credential_info *credential_info);
int aws_route53_conn_destroy(pool *p, struct route53_conn *route53);

/* Returns a list of ACLs comprising the IP address ranges from which Route53
 * healthcheck requests will come.  Useful for implementing a known whitelist
 * for checking healthcheck connection requests.
 */
array_header *aws_route53_get_healthcheck_ranges(pool *p,
  struct route53_conn *route53);

struct route53_hosted_zone *aws_route53_get_hosted_zone(pool *p,
  struct route53_conn *route53, const char *fqdn);

struct route53_rrset *aws_route53_get_rrset(pool *p,
  struct route53_conn *route53, const char *zone_id, const char *fqdn);

#endif /* MOD_AWS_ROUTE53_H */
