/*
 * ProFTPD - mod_aws S3 FSIO API
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

#ifndef MOD_AWS_S3_FSIO_H
#define MOD_AWS_S3_FSIO_H

#include "mod_aws.h"
#include "s3/conn.h"

pr_fs_t *aws_s3_fsio_get_fs(pool *p, const char *path, struct s3_conn *s3,
  const char *bucket_name, const char *object_prefix);

/* Convert from a table of S3 object metadata to/from struct stat. */
int aws_s3_fsio_stat2table(pool *p, struct stat *st,
  pr_table_t *object_metadata);

int aws_s3_fsio_table2stat(pool *p, pr_table_t *object_metadata,
  struct stat *st);

/* Below are the most common keys used for storing filesystem metadata about
 * a file, with that file's data in an S3 object.
 */
#define AWS_S3_FSIO_METADATA_KEY_SIZE		"Content-Length"
#define AWS_S3_FSIO_METADATA_KEY_ATIME		"x-amz-meta-atime"
#define AWS_S3_FSIO_METADATA_KEY_GID		"x-amz-meta-gid"
#define AWS_S3_FSIO_METADATA_KEY_GROUP		"x-amz-meta-group"
#define AWS_S3_FSIO_METADATA_KEY_MODE		"x-amz-meta-mode"
#define AWS_S3_FSIO_METADATA_KEY_MTIME		"x-amz-meta-mtime"
#define AWS_S3_FSIO_METADATA_KEY_OWNER		"x-amz-meta-owner"
#define AWS_S3_FSIO_METADATA_KEY_PERMS		"x-amz-meta-permissions"
#define AWS_S3_FSIO_METADATA_KEY_UID		"x-amz-meta-uid"

#endif /* MOD_AWS_S3_FSIO_H */
