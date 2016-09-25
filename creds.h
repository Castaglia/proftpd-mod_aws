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

#ifndef MOD_AWS_CREDS_H
#define MOD_AWS_CREDS_H

#include "mod_aws.h"
#include "instance.h"

/* Default profile name. */
#define AWS_CREDS_DEFAULT_PROFILE	"default"

/* Obtain AWS credentials from the environment, via the following environment
 * variables:
 *
 *  AWS_ACCESS_KEY_ID
 *  AWS_SECRET_ACCESS_KEY
 */
int aws_creds_from_env(pool *p, char **access_key_id, char **secret_access_key,
  char **session_token);

/* Obtain AWS credentials from the given path, for the named profile
 * (if any).
 */
int aws_creds_from_file(pool *p, const char *path, const char *profile,
  char **access_key_id, char **secret_access_key, char **session_token);

/* Obtain AWS credentials from a "chain" of providers.  The order in which
 * providers are checked is determined by the given providers list.
 *
 *  1.  Check for per-profile credentials.
 *  2.  Check for "default" profile credentials.
 *  3.  Check for properties-based credentials.
 *  4.  Check for environment variable-based credentials.
 *
 * Note that if a profile is provided, the default path of "~/.aws/credentials"
 * is used; this default location can be overridden via the
 * AWS_CREDENTIAL_PROFILES_FILE environment variable.
 */
int aws_creds_from_chain(pool *p, array_header *providers,
  char **access_key_id, char **secret_access_key, char **session_token,
  const char *iam_role, const char *profile, const char *path);
#define AWS_CREDS_PROVIDER_NAME_IAM			"iam"
#define AWS_CREDS_PROVIDER_NAME_PROFILE			"profile"
#define AWS_CREDS_PROVIDER_NAME_PROPERTIES		"props"
#define AWS_CREDS_PROVIDER_NAME_ENVIRONMENT		"env"

/* Obtain AWS credentials via SQL query. */
int aws_creds_from_sql(pool *p, const char *query, char **access_key_id,
  char **secret_access_key, char **session_token);

#endif /* MOD_AWS_CREDS_H */
