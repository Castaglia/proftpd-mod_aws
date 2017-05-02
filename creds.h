/*
 * ProFTPD - mod_aws AWS credentials
 * Copyright (c) 2016-2017 TJ Saunders
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

struct aws_credential_info {
  const char *iam_role;
  const char *profile;
  const char *creds_path;
};

struct aws_credentials {
  const char *access_key_id;
  const char *secret_access_key;
  const char *session_token;
};

/* Default profile name. */
#define AWS_CREDS_DEFAULT_PROFILE	"default"

/* Obtain AWS credentials from the instance metadata. */
int aws_creds_from_iam(pool *p, const char *iam_role,
  struct aws_credentials **creds);

/* Obtain AWS credentials from the environment, via the following environment
 * variables:
 *
 *  AWS_ACCESS_KEY_ID
 *  AWS_SECRET_ACCESS_KEY
 */
int aws_creds_from_env(pool *p, struct aws_credentials **creds);

/* Obtain AWS credentials from the given path, for the named profile
 * (if any).
 */
int aws_creds_from_file(pool *p, const char *config_path, const char *profile,
  struct aws_credentials **creds);

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
int aws_creds_from_chain(pool *p, const array_header *providers,
  const struct aws_credential_info *info, struct aws_credentials **creds);
#define AWS_CREDS_PROVIDER_NAME_IAM			"iam"
#define AWS_CREDS_PROVIDER_NAME_PROFILE			"profile"
#define AWS_CREDS_PROVIDER_NAME_PROPERTIES		"props"
#define AWS_CREDS_PROVIDER_NAME_ENVIRONMENT		"env"

/* Obtain AWS credentials via SQL query. */
int aws_creds_from_sql(pool *p, const char *query,
  struct aws_credentials **creds);

#endif /* MOD_AWS_CREDS_H */
