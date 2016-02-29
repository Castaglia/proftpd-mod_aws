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

  /* http://169.254.169.254/latest/meta-data/services/domain */
  char *domain;
  size_t domainsz;

  /* http://169.254.169.254/latest/dynamic/instance-identity/document */
  char *identity_doc;
  size_t identity_docsz;

  /* See identity doc "accountId" key. */
  char *account_id;

  /* See identity doc "version" key. */
  char *api_version;

  /* See identity doc "region" key. */
  char *region;

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
  char *hw_mac;
  size_t hw_macsz;

  /* http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac}/vpc-id */
  char *vpc_id;
  size_t vpc_idsz;

  /* http://169.254.169.254/latest/meta-data/network/interfaces/macs/{mac}/subnet-id */
  char *subnet_id;
  size_t subnet_idsz;

  /* http://169.254.169.254/latest/meta-data/security-groups */
  char *sg_names;
  size_t sg_namessz;
  array_header *security_groups;

  /* http://169.254.169.254/latest/meta-data/local-ipv4 */
  char *local_ipv4;
  size_t local_ipv4sz;

  /* http://169.254.169.254/latest/meta-data/local-hostname */
  char *local_hostname;
  size_t local_hostnamesz;

  /* http://169.254.169.254/latest/meta-data/public-ipv4
   *
   * Note that this may NOT be present in e.g. VPC internal hosts.
   */
  char *public_ipv4;
  size_t public_ipv4sz;

  /* http://169.254.169.254/latest/meta-data/public-hostname
   *
   * Note that this may NOT be present in e.g. VPC internal hosts.
   */
  char *public_hostname;
  size_t public_hostnamesz;
};

struct iam_info {
  pool *pool;

  const char *iam_role;

  /* http://169.254.169.254/latest/meta-data/iam/security-credentials/{role} */
  char *creds_doc;
  size_t creds_docsz;

  /* See security credentials doc "AccessKeyId" key. */
  const char *access_key_id;

  /* See security credentials doc "SecretAccessKey" key. */
  const char *secret_access_key;

  /* See security credentials doc "Token" key. */
  const char *token;
};

struct aws_info *aws_instance_get_info(pool *p);

struct iam_info *aws_instance_get_iam_credentials(pool *p,
  const char *iam_role);

#endif /* MOD_AWS_INSTANCE_H */
