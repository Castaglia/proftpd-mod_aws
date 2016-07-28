/*
 * ProFTPD - mod_aws testsuite
 * Copyright (c) 2016 TJ Saunders <tj@castaglia.org>
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

/* Sign API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_http_init(p, NULL, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 1, 20);
    pr_trace_set_levels("aws.sign", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
    pr_trace_set_levels("aws.sign", 0, 0);
  }

  aws_http_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (sign_v4_generate_invalid_params_test) {
  int res;
  const char *access_key_id, *secret_access_key, *token, *region, *service;
  const char *http_method, *http_path;
  void *http;
  array_header *query_params;

  mark_point();
  res = aws_sign_v4_generate(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_sign_v4_generate(p, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null access key ID");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  access_key_id = "ACCESS_KEY_ID";
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null secret access key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  secret_access_key = "SECRET_ACCESS_KEY";
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null region");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  token = NULL;
  region = "us-west-2";
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null service");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  service = "ec2";
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, NULL, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null HTTP handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null HTTP method");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_method = "GET";
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null HTTP path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_path = "/";
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null query params");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  query_params = make_array(p, 0, sizeof(char *));
  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null headers");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (sign_v4_generate_valid_params_test) {
  int res;
  const char *access_key_id, *secret_access_key, *token, *region, *service;
  const char *http_method, *http_path, *http_body, *signature, *added_token;
  void *http;
  pr_table_t *http_headers;
  array_header *query_params;

  access_key_id = "ACCESS_KEY_ID";
  secret_access_key = "SECRET_ACCESS_KEY";
  token = NULL;
  region = "us-west-2";
  service = "ec2";
  http_method = "GET";
  http_path = "/";
  http_headers = aws_http_default_headers(p, NULL);
  query_params = make_array(p, 0, sizeof(char *));

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, http_headers, NULL, 0);
  fail_unless(res == 0, "Failed to generate V4 signature: %s", strerror(errno));

  mark_point();
  signature = pr_table_get(http_headers, AWS_HTTP_HEADER_AUTHZ, NULL);
  fail_unless(signature != NULL, "Failed to get '%s' signature header: %s",
    AWS_HTTP_HEADER_AUTHZ, strerror(errno));

  http_body = "{ \"test\": true }\n";
  http_headers = aws_http_default_headers(p, NULL);
  pr_table_add_dup(http_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_TYPE),
    "application/json", 0);

  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, http_headers,
    http_body, 0);
  fail_unless(res == 0, "Failed to generate V4 signature: %s", strerror(errno));

  signature = pr_table_get(http_headers, AWS_HTTP_HEADER_AUTHZ, NULL);
  fail_unless(signature != NULL, "Failed to get '%s' signature header: %s",
    AWS_HTTP_HEADER_AUTHZ, strerror(errno));

  /* Provide a token */

  http_body = NULL;
  http_headers = aws_http_default_headers(p, NULL);
  token = "TOKEN";

  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, http_headers,
    http_body, 0);
  fail_unless(res == 0, "Failed to generate V4 signature: %s", strerror(errno));

  signature = pr_table_get(http_headers, AWS_HTTP_HEADER_AUTHZ, NULL);
  fail_unless(signature != NULL, "Failed to get '%s' signature header: %s",
    AWS_HTTP_HEADER_AUTHZ, strerror(errno));

  added_token = pr_table_get(http_headers, AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN,
    NULL);
  fail_unless(added_token != NULL, "Failed to get '%s' token header: %s",
    AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN, strerror(errno));

  /* Provide a longer path, and some query params */

  http_headers = aws_http_default_headers(p, NULL);
  http_path = "/foo/bar";
  query_params = make_array(p, 1, sizeof(char *));
  *((char **) push_array(query_params)) = pstrdup(p, "DryRun=true");
  token = NULL;

  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, http_headers,
    http_body, 0);
  fail_unless(res == 0, "Failed to generate V4 signature: %s", strerror(errno));

  signature = pr_table_get(http_headers, AWS_HTTP_HEADER_AUTHZ, NULL);
  fail_unless(signature != NULL, "Failed to get '%s' signature header: %s",
    AWS_HTTP_HEADER_AUTHZ, strerror(errno));

  /* Provide empty headers */

  http_headers = pr_table_alloc(p, 0);
  http_path = "/";
  query_params = make_array(p, 0, sizeof(char *));
  token = NULL;

  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, http_headers,
    http_body, 0);
  fail_unless(res == 0, "Failed to generate V4 signature: %s", strerror(errno));

  signature = pr_table_get(http_headers, AWS_HTTP_HEADER_AUTHZ, NULL);
  fail_unless(signature != NULL, "Failed to get '%s' signature header: %s",
    AWS_HTTP_HEADER_AUTHZ, strerror(errno));

  /* Provide a table with header names, but not values */

  http_headers = pr_table_alloc(p, 0);
  pr_table_add(http_headers, pstrdup(p, "Foo"), NULL, 0);
  pr_table_add(http_headers, pstrdup(p, "Bar"), NULL, 0);
  http_path = "/";
  query_params = make_array(p, 0, sizeof(char *));
  token = NULL;

  mark_point();
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, token, region,
    service, http, http_method, http_path, query_params, http_headers,
    http_body, 0);
  fail_unless(res == 0, "Failed to generate V4 signature: %s", strerror(errno));

  signature = pr_table_get(http_headers, AWS_HTTP_HEADER_AUTHZ, NULL);
  fail_unless(signature != NULL, "Failed to get '%s' signature header: %s",
    AWS_HTTP_HEADER_AUTHZ, strerror(errno));

  /* XXX Provide a body larger than OpenSSL's SHA256() max buffer? */

  /* XXX Provide a body large enough, such that the canonical request is larger
   * than OpenSSL's SHA256() max buffer?
   */

  aws_http_destroy(p, http);
}
END_TEST

Suite *tests_get_sign_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("sign");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, sign_v4_generate_invalid_params_test);
  tcase_add_test(testcase, sign_v4_generate_valid_params_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
