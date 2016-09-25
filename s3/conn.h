/*
 * ProFTPD - mod_aws S3 Connection API
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

#ifndef MOD_AWS_S3_CONN_H
#define MOD_AWS_S3_CONN_H

#include "mod_aws.h"

/* S3 Connections */
struct s3_conn {
  pool *pool;

  void *http;
  const char *region;
  const char *domain;

  /* To be refreshed whenever the credentials are deemed too old. */
  const char *access_key_id;
  const char *secret_access_key;
  const char *session_token;

  /* For handling request/response documents. */
  pool *req_pool;
  char *resp;
  size_t respsz;
};

struct s3_conn *aws_s3_conn_alloc(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs, const char *cacerts, const char *region,
  const char *domain, const char *access_key_id, const char *secret_access_key,
  const char *session_token);

int aws_s3_conn_destroy(pool *p, struct s3_conn *s3);

void aws_s3_conn_clear_response(struct s3_conn *s3);

int aws_s3_get(pool *p, void *http, pr_table_t *http_headers, const char *path,
  array_header *query_params, pr_table_t *resp_headers,
  size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
  struct s3_conn *s3);

int aws_s3_head(pool *p, void *http, pr_table_t *http_headers, const char *path,
  array_header *query_params, pr_table_t *resp_headers, struct s3_conn *s3);

int aws_s3_post(pool *p, void *http, pr_table_t *http_headers, const char *path,
  array_header *query_params, char *req_body, pr_table_t *resp_headers,
  size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
  struct s3_conn *s3);

#endif /* MOD_AWS_S3_CONN_H */
