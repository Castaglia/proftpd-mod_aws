/*
 * ProFTPD - mod_aws AWS credentials
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
#include "instance.h"

#ifndef MOD_AWS_CREDS_H
#define MOD_AWS_CREDS_H

/* Obtain AWS credentials from the environment, via the following environment
 * variables:
 *
 *  AWS_ACCESS_KEY_ID
 *  AWS_SECRET_ACCESS_KEY
 */
int aws_creds_from_env(pool *p, char **access_key_id, char **secret_access_key);

/* Obtain AWS credentials from the given path, for the named profile
 * (if any).
 *
 * Note that if a profile is provided, the default path of "~/.aws/credentials"
 * is used; this default location can be overridden via the
 * AWS_CREDENTIAL_PROFILES_FILE environment variable.
 */
int aws_creds_from_file(pool *p, const char *path, const char *profile,
  char **access_key_id, char **secret_access_key);

/* Obtain AWS credentials via SQL query. */
int aws_creds_from_sql(pool *p, const char *query, char **access_key_id,
  char **secret_access_key);

#endif /* MOD_AWS_CREDS_H */
