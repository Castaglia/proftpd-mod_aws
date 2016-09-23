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

/* HTTP methods */
#define AWS_HTTP_METHOD_GET				1
#define AWS_HTTP_METHOD_HEAD				2
#define AWS_HTTP_METHOD_POST				3
#define AWS_HTTP_METHOD_PUT				4
#define AWS_HTTP_METHOD_DELETE				5

/* HTTP headers */
#define AWS_HTTP_HEADER_ACCEPT				"Accept"
#define AWS_HTTP_HEADER_AUTHZ				"Authorization"
#define AWS_HTTP_HEADER_CACHE_CONTROL			"Cache-Control"
#define AWS_HTTP_HEADER_CONNECTION			"Connection"
#define AWS_HTTP_HEADER_CONTENT_LEN			"Content-Length"
#define AWS_HTTP_HEADER_CONTENT_TYPE			"Content-Type"
#define AWS_HTTP_HEADER_DATE				"Date"
#define AWS_HTTP_HEADER_EXPECT				"Expect"
#define AWS_HTTP_HEADER_EXPIRES				"Expires"
#define AWS_HTTP_HEADER_HOST				"Host"
#define AWS_HTTP_HEADER_LAST_MODIFIED			"Last-Modified"
#define AWS_HTTP_HEADER_USER_AGENT			"User-Agent"
#define AWS_HTTP_HEADER_X_AMZ_CONTENT_SHA256		"x-amz-content-sha256"
#define AWS_HTTP_HEADER_X_AMZ_DATE			"X-Amz-Date"
#define AWS_HTTP_HEADER_X_AMZ_REQUEST_ID		"x-amz-request-id"
#define AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN		"X-Amz-Security-Token"
#define AWS_HTTP_HEADER_X_AMZN_REQUEST_ID		"x-amzn-RequestId"

/* HTTP response codes */
#define AWS_HTTP_RESPONSE_CODE_OK			200L

#define AWS_HTTP_RESPONSE_CODE_BAD_REQUEST		400L
#define AWS_HTTP_RESPONSE_CODE_UNAUTHORIZED		401L
#define AWS_HTTP_RESPONSE_CODE_FORBIDDEN		403L
#define AWS_HTTP_RESPONSE_CODE_NOT_FOUND		404L
#define AWS_HTTP_RESPONSE_CODE_PRECONDITION_FAILED	412L
#define AWS_HTTP_RESPONSE_CODE_TOO_MANY_REQUESTS	429L

#define AWS_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR	500L
#define AWS_HTTP_RESPONSE_CODE_BAD_GATEWAY		502L
#define AWS_HTTP_RESPONSE_CODE_SERVICE_UNAVAIL		503L
#define AWS_HTTP_RESPONSE_CODE_GATEWAY_TIMEOUT		504L

/* HTTP content types */
#define AWS_HTTP_CONTENT_TYPE_HTML			"text/html"
#define AWS_HTTP_CONTENT_TYPE_XML			"application/xml"

/* HTTP Date format buffer size; contains space for 16 characters
 * (YYYYMMDDThhmmssZ) plus the trailing NUL.
 */
#define AWS_HTTP_DATE_ISO8601_BUFSZ			18

void *aws_http_alloc(pool *p, unsigned long max_connect_secs,
  unsigned long max_request_secs, const char *cacerts);
int aws_http_destroy(pool *p, void *http);

/* Return a table populated with the default request headers: Accept,
 * User-Agent, etc.
 *
 * If a struct tm * is provided, a properly formatted X-Amz-Date header
 * is also automatically provided.
 */
pr_table_t *aws_http_default_headers(pool *p, struct tm *gmt_tm);

const char *aws_http_urldecode(pool *p, void *http, const char *item,
  size_t item_len, size_t *decoded_len);
const char *aws_http_urlencode(pool *p, void *http, const char *item,
  size_t item_len);

int aws_http_head(pool *p, void *http, const char *url, pr_table_t *req_headers,
  long *resp_code, const char **content_type, pr_table_t *resp_headers);

int aws_http_get(pool *p, void *http, const char *url, pr_table_t *req_headers,
  size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
  long *resp_code, const char **content_type, pr_table_t *resp_headers);

int aws_http_post(pool *p, void *http, const char *url, pr_table_t *req_headers,
  size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
  char *req_body, long *resp_code, const char **content_type,
  pr_table_t *resp_headers);

/* API lifetime functions, for mod_aws use only. */
int aws_http_init(pool *p, unsigned long *feature_flags,
  const char **http_details);
int aws_http_free(void);

#endif /* MOD_AWS_HTTP_H */
