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
#include "instance.h"

#ifndef MOD_AWS_EC2_H
#define MOD_AWS_EC2_H

struct ec2_conn {
  pool *pool;

  CURL *curl;
  const char *region;
  const char *domain;
  const char *api_version;

  /* To be refreshed whenever the credentials are deemed too old. */
  struct iam_info *iam_info;

  /* For handling request/response documents. */
  pool *req_pool;
  char *resp;
  size_t respsz;
};

struct ec2_conn *aws_ec2_conn_alloc(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs, const char *cacerts, const char *region,
  const char *domain, const char *api_version);
int aws_ec2_conn_destroy(pool *p, struct ec2_conn *ec2);

int aws_ec2_get_security_groups(pool *p, struct ec2_conn *ec2,
  array_header *security_groups);

#endif /* MOD_AWS_EC2_H */
