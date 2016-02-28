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

  /* http://169.254.169.254/latest/meta-data/services/domain */
  char *aws_domain;
  size_t aws_domainsz;

  /* http://169.254.169.254/latest/dynamic/instance-identity/document
   * See "accountId" key.
   */
  char *account_id;
  size_t account_idsz;

  /* http://169.254.169.254/latest/dynamic/instance-identity/document
   * See "region" key.
   */
  char *region;
  size_t regionsz;

  /* http://169.254.169.254/latest/meta-data/placement/availability-zone */
  char *avail_zone;
  size_t avail_zonesz;

  /* http://169.254.169.254/latest/meta-data/instance-type */
  char *instance_type;
  size_t instance_typesz;

  /* http://169.254.169.254/latest/meta-data/instance-id */
  char *instance_id;
  size_t instance_idsz;

  /* http://169.254.169.254/latest/meta-data/ami-id */
  char *ami_id;
  size_t ami_idsz;

  /* http://169.254.169.254/latest/meta-data/iam/security-credentials/ */
  char *iam_role;
  size_t iam_rolesz;

  /* http://169.254.169.254/latest/meta-data/mac */
  char *mac;
  size_t macsz;

  /* http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac}/vpc-id */
  char *vpc_id;
  size_t vpc_idsz;

  /* http://169.254.169.254/latest/meta-data/security-groups */
  array_header *security_groups;

  /* http://169.254.169.254/latest/meta-data/local-ipv4 */
  pr_netaddr_t *private_addr;

  /* http://169.254.169.254/latest/meta-data/local-hostname */
  char *private_hostname;
  size_t private_hostnamesz;

  /* http://169.254.169.254/latest/meta-data/public-ipv4 */
  pr_netaddr_t *public_addr;

  /* http://169.254.169.254/latest/meta-data/public-hostname */
  char *public_hostname;
  size_t public_hostnamesz;
};

struct aws_info *aws_instance_get_info(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs);

#endif /* MOD_AWS_INSTANCE_H */
