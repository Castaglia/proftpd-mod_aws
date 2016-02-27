/*
 * ProFTPD - mod_aws EC2 instance
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

#ifndef MOD_AWS_INSTANCE_H
#define MOD_AWS_INSTANCE_H

struct aws_info {
  pool *pool;

  /* Last HTTP response message (since curl does not track this for us). */
  char *last_resp_msg;

  char *aws_domain;
  size_t aws_domainsz;

  char *account_id;
  size_t account_idsz;

  char *region;
  size_t regionsz;

  char *avail_zone;
  size_t avail_zonesz;

  char *instance_type;
  size_t instance_typesz;

  char *instance_id;
  size_t instance_idsz;

  char *ami_id;
  size_t ami_idsz;

  char *iam_role;
  size_t iam_rolesz;

  char *vpc_id;
  size_t vpc_idsz;

  array_header *security_groups;
  pr_netaddr_t *private_addr;
  const char *private_hostname;
  pr_netaddr_t *public_addr;
  const char *public_hostname;
};

struct aws_info *aws_instance_get_info(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs);

#endif /* MOD_AWS_INSTANCE_H */
