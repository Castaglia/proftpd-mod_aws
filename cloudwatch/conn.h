/*
 * ProFTPD - mod_aws CloudWatch Connection API
 * Copyright (c) 2017 TJ Saunders
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

#ifndef MOD_AWS_CLOUDWATCH_CONN_H
#define MOD_AWS_CLOUDWATCH_CONN_H

#include "mod_aws.h"
#include "instance.h"

/* CloudWatch Connections */
struct cloudwatch_conn {
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

  /* Metric namespace */
  const char *namespace;
};

#define AWS_CLOUDWATCH_DEFAULT_NAMESPACE	"proftpd"

struct cloudwatch_conn *aws_cloudwatch_conn_alloc(pool *p,
  unsigned long max_connect_secs, unsigned long max_request_secs,
  const char *cacerts, const char *region, const char *domain,
  const char *iam_role, const char *namespace);

int aws_cloudwatch_conn_destroy(pool *p, struct cloudwatch_conn *cw);

void aws_cloudwatch_conn_clear_response(struct cloudwatch_conn *cw);

void aws_cloudwatch_conn_reset_response(struct cloudwatch_conn *cw);

/* Flush any buffered/pending metrics. */
int aws_cloudwatch_conn_flush(pool *p, struct cloudwatch_conn *cw);

int aws_cloudwatch_get(pool *p, void *http, pr_table_t *http_headers,
  const char *path, array_header *query_params,
  size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
  struct cloudwatch_conn *cw);

#endif /* MOD_AWS_CLOUDWATCH_CONN_H */
