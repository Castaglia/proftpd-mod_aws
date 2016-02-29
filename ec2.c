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
#include "ec2.h"

static const char *trace_channel = "aws.ec2";

struct ec2_conn *aws_ec2_conn_alloc(pool *p, unsigned long max_connect_secs,
    unsigned long max_request_secs, const char *cacerts, const char *domain) {
  pool *ec2_pool;
  struct ec2_conn *ec2;
  CURL *curl;

  curl = aws_http_alloc(p, max_connect_secs, max_request_secs, cacerts);
  if (curl == NULL) {
    return NULL;
  }

  ec2_pool = make_sub_pool(p);
  pr_pool_tag(ec2_pool, "EC2 Connection Pool");

  ec2 = pcalloc(ec2_pool, sizeof(struct ec2_conn));
  ec2->pool = ec2_pool;
  ec2->curl = curl;
  ec2->domain = pstrdup(ec2->pool, domain);

  return ec2;
}

int aws_ec2_conn_destroy(pool *p, struct ec2_conn *ec2) {
  int res, xerrno;

  res = aws_http_destroy(p, ec2->curl);
  xerrno = errno;

  destroy_pool(ec2->pool);

  errno = xerrno;
  return res;
}

int aws_ec2_get_security_groups(pool *p, struct ec2_conn *ec2,
    array_header *security_groups) {
  errno = ENOSYS;
  return -1;
}
