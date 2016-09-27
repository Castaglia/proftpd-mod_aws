/*
 * ProFTPD - mod_aws S3 Bucket API
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

#ifndef MOD_AWS_S3_BUCKET_H
#define MOD_AWS_S3_BUCKET_H

#include "mod_aws.h"
#include "s3/conn.h"

struct s3_object_attrs {
  off_t size;
  time_t last_modified;
  const char *etag;

  /* Note: Maybe move these to an enum in the future? */
  const char *storage_class;
};

/* Returns a list of the bucket names for the account. */
array_header *aws_s3_bucket_get_names(pool *p, struct s3_conn *s3,
  const char **owner_id, const char **owner_name);

/* Returns table containing the object keys in the given bucket; the values
 * are struct s3_object_attrs for each object.
 */
pr_table_t *aws_s3_bucket_get_keys(pool *p, struct s3_conn *s3,
  const char *bucket_name, const char *prefix);

/* Returns zero if the given bucket can be accessed, otherwise -1, with
 * errno set appropriately.
 */
int aws_s3_bucket_access(pool *p, struct s3_conn *s3, const char *bucket_name);

#endif /* MOD_AWS_S3_BUCKET_H */
