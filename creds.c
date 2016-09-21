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
#include "creds.h"

int aws_creds_from_env(pool *p, char **access_key_id,
    char **secret_access_key) {
  const char *k, *id, *secret;

  if (p == NULL ||
      access_key_id == NULL ||
      secret_access_key == NULL) {
    errno = EINVAL;
    return -1;
  }

  k = "AWS_ACCESS_KEY_ID";
  id = pr_env_get(p, k);
  if (id == NULL) {
    errno = ENOENT;
    return -1;
  }

  k = "AWS_SECRET_ACCESS_KEY";
  secret = pr_env_get(p, k);
  if (secret == NULL) {
    errno = ENOENT;
    return -1;
  }

  *access_key_id = pstrdup(p, id);
  *secret_access_key = pstrdup(p, secret);

  return 0;
}

int aws_creds_from_file(pool *p, const char *path, const char *profile,
    char **access_key_id, char **secret_access_key) {
  errno = ENOSYS;
  return -1;
}

int aws_creds_from_sql(pool *p, char **access_key_id,
    char **secret_access_key) {
  errno = ENOSYS;
  return -1;
}
