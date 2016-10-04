/*
 * ProFTPD - mod_aws S3 Object API
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

#ifndef MOD_AWS_S3_OBJECT_H
#define MOD_AWS_S3_OBJECT_H

#include "mod_aws.h"
#include "s3/conn.h"

/* S3 Objects */

/* Names of system-defined object metadata. */
#define AWS_S3_OBJECT_METADATA_SIZE		"Content-Length"
#define AWS_S3_OBJECT_METADATA_MTIME		"Last-Modified"
#define AWS_S3_OBJECT_METADATA_STORAGE_CLASS	"x-amz-storage-class"

/* Prefix for user-defined object metadata. */
#define AWS_S3_OBJECT_METADATA_PREFIX		"x-amz-meta-"
#define AWS_S3_OBJECT_METADATA_PREFIX_LEN	11

/* For object copying. */
#define AWS_S3_OBJECT_COPY_SOURCE_KEY		"x-amz-copy-source"
#define AWS_S3_OBJECT_COPY_SOURCE_METADATA	"x-amz-metadata-directive"

/* Maximum size of object for single PUT: 5 GB */
#define AWS_S3_OBJECT_PUT_MAX_SIZE		((off_t) (5UL * 1024UL * 1024UL * 1024UL))

/* Minimum size of single part for multipart uploads: 5 MB */
#define AWS_S3_OBJECT_MULTIPART_MIN_SIZE	((off_t) (5UL * 1024UL * 1024UL))

/* Get an object from the specified bucket, using a byte range specified by the
 * given offset and length.
 *
 * The caller will provide a callback for consuming the retrieved data.  Any
 * metadata for the retrieved object will be returned in a table, if desired
 * by the caller.
 */
int aws_s3_object_get(pool *p, struct s3_conn *s3, const char *bucket_name,
  const char *object_key, off_t object_offset, off_t object_len,
  pr_table_t *object_metadata,
  int (*consume_data)(pool *p, void *data, off_t data_offset, off_t data_len));

/* Obtain the metadata for the given object in the specified bucket. */
int aws_s3_object_stat(pool *p, struct s3_conn *s3, const char *bucket_name,
  const char *object_key, pr_table_t *object_metadata);

/* Store an object in the specified bucket in a single request. */
int aws_s3_object_put(pool *p, struct s3_conn *s3, const char *bucket_name,
  const char *object_key, pr_table_t *object_metadata, char *object_data,
  off_t object_datasz);

/* Multipart S3 object uploads. */

struct s3_object_part;
struct s3_object_multipart;

struct s3_object_multipart *aws_s3_object_multipart_open(pool *p,
  struct s3_conn *s3, const char *bucket_name, const char *object_key,
  pr_table_t *object_metadata);

int aws_s3_object_multipart_append(pool *p, struct s3_conn *s3,
  struct s3_object_multipart *multipart, char *part_data, off_t part_datasz);

int aws_s3_object_multipart_close(pool *p, struct s3_conn *s3,
  struct s3_object_multipart *mulipart, int flags);
#define AWS_S3_OBJECT_MULTIPART_FL_SUCCESS		0
#define AWS_S3_OBJECT_MULTIPART_FL_FAILURE		1

/* Delete an object from the specified bucket. */
int aws_s3_object_delete(pool *p, struct s3_conn *s3, const char *bucket_name,
  const char *object_key);

/* Copy an object from the specified bucket, to a new bucket/key, with
 * the provided metadata.
 */
int aws_s3_object_copy(pool *p, struct s3_conn *s3,
  const char *src_bucket_name, const char *src_object_key,
  const char *dst_bucket_name, const char *dst_object_key,
  pr_table_t *dst_object_metadata);

#endif /* MOD_AWS_S3_OBJECT_H */
