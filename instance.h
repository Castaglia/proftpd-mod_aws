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
  const char *last_resp_msg;

  const char *aws_domain;
  size_t aws_domainsz;

  const char *account_id;
  size_t account_idsz;

  const char *region;
  size_t regionsz;

  const char *avail_zone;
  size_t avail_zonesz;

  const char *instance_type;
  size_t instance_typesz;

  const char *instance_id;
  size_t instance_idsz;

  const char *ami_id;
  size_t ami_idsz;

  const char *iam_role;
  size_t iam_rolesz;

  const char *vpc_id;
  size_t vpc_idsz;

  array_header *security_groups;
  pr_netaddr_t *private_addr;
  const char *private_hostname;
  pr_netaddr_t *public_addr;
  const char *public_hostname;
};

struct aws_info *aws_instance_get_info(pool *p);

#endif /* MOD_AWS_INSTANCE_H */
