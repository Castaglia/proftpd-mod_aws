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

#ifndef MOD_AWS_EC2_H
#define MOD_AWS_EC2_H

#include "mod_aws.h"
#include "instance.h"

/* EC2 Connections */
struct ec2_conn {
  pool *pool;

  void *http;
  const char *region;
  const char *domain;

  /* To be refreshed whenever the credentials are deemed too old. */
  const char *iam_role;
  struct iam_info *iam_info;

  /* For handling request/response documents. */
  pool *req_pool;
  char *resp;
  size_t respsz;
};

/* EC2 Security Groups */

/* Maps to the EC2 IpPermission data type. */
struct ec2_ip_rule {
  /* Note that this could be: 'tcp', 'udp', 'icmp', OR it could be
   * a number, indicating one of the other IANA-registered protocols; see:
   *
   *  http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
   */
  const char *proto;

  int from_port;
  int to_port;

  /* Arrays of pr_netacl_t ACLs. Maps to the EC2 IpRange data type. */
  array_header *ranges;
};

/* Maps to the EC2 SecurityGroup data type. */
struct ec2_security_group {
  pool *pool;

  const char *id;
  const char *name;
  const char *desc;
  const char *owner_id;
  const char *vpc_id;
  const char *req_id;

  array_header *inbound_rules;
  array_header *outbound_rules;
};

struct ec2_conn *aws_ec2_conn_alloc(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs, const char *cacerts, const char *region,
  const char *domain, const char *iam_role);
int aws_ec2_conn_destroy(pool *p, struct ec2_conn *ec2);

/* Returns a table whose keys are the security group names, and the values
 * are the corresponding security group info.
 */
pr_table_t *aws_ec2_get_security_groups(pool *p, struct ec2_conn *ec2,
  const char *vpc_id, array_header *security_groups);

int aws_ec2_security_group_allow_rule(pool *p, struct ec2_conn *ec2,
  const char *sg_id, struct ec2_ip_rule *inbound_rule);
int aws_ec2_security_group_revoke_rule(pool *p, struct ec2_conn *ec2,
  const char *sg_id, struct ec2_ip_rule *inbound_rule);

#endif /* MOD_AWS_EC2_H */
