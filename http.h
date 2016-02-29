/*
 * ProFTPD - mod_aws HTTP requests
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

#ifndef MOD_AWS_HTTP_H
#define MOD_AWS_HTTP_H

#define AWS_HTTP_RESPONSE_CODE_OK		200L
#define AWS_HTTP_RESPONSE_CODE_BAD_REQUEST	400L
#define AWS_HTTP_RESPONSE_CODE_NOT_FOUND	404L

#define AWS_HTTP_CONTENT_TYPE_XML		"application/xml"

void *aws_http_alloc(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs, const char *cacerts);
int aws_http_destroy(pool *p, void *http);

const char *aws_http_urldecode(pool *p, void *http, const char *item,
  size_t item_len, size_t *decoded_len);
const char *aws_http_urlencode(pool *p, void *http, const char *item,
  size_t item_len);

int aws_http_get(pool *p, void *http, const char *url,
  size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
  long *resp_code, const char **content_type);

/* API lifetime functions, for mod_aws use only. */
int aws_http_init(pool *p, unsigned long *feature_flags,
  const char **http_details);
int aws_http_free(void);

#endif /* MOD_AWS_HTTP_H */
