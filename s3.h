/*
 * ProFTPD - mod_aws S3 API
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

#ifndef MOD_AWS_S3_H
#define MOD_AWS_S3_H

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

/* Returns a list of the bucket names. */
array_header *aws_s3_get_buckets(pool *p, struct s3_conn *s3,
  const char **owner_id, const char **owner_name);

/* Returns a list of the object keys in the given bucket. */
array_header *aws_s3_get_bucket_keys(pool *p, struct s3_conn *s3,
  const char *bucket_name, const char *prefix);

/* Get an object from the specified bucket, using a byte range specified by the
 * given offset and length.
 *
 * The caller will provide a callback for consuming the retrieved data.  Any
 * metadata for the retrieved object will be returned in a table, if desired
 * by the caller.
 */
int aws_s3_get_object(pool *p, struct s3_conn *s3, const char *bucket_name,
  const char *object_key, off_t object_offset, off_t object_len,
  pr_table_t *object_metadata,
  int (*consume)(pool *p, void *data, off_t data_offset, off_t data_len));

#endif /* MOD_AWS_S3_H */
