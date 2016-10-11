/*
 * ProFTPD - mod_aws S3 Utilities API
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

#ifndef MOD_AWS_S3_UTILS_H
#define MOD_AWS_S3_UTILS_H

#include "mod_aws.h"

/* Slightly modified URL encoding scheme for S3 object names; we URL-encode
 * non-ASCII characters except for slashes.
 */
const char *aws_s3_utils_urlencode(pool *p, const char *str);

/* The timestamp format used for the <LastModified> elements in S3 responses. */
time_t aws_s3_utils_lastmod2unix(pool *p, const char *last_modified);
const char *aws_s3_utils_unix2lastmod(pool *p, time_t last_modified);

#endif /* MOD_AWS_S3_UTILS_H */
