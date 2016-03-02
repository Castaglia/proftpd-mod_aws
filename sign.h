/*
 * ProFTPD - mod_aws AWS signatures
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

#ifndef MOD_AWS_SIGN_H
#define MOD_AWS_SIGN_H

int aws_sign_v4_generate(pool *p, const char *access_key_id,
  const char *secret_access_key, const char *token, const char *region,
  const char *service, void *http, const char *http_method,
  const char *http_path, array_header *query_params, pr_table_t *http_headers,
  const char *http_body, time_t request_time);

#endif /* MOD_AWS_SIGN_H */
