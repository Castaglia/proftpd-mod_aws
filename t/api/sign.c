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
  const char *http_method, *http_path, *http_body;
  void *http;
  pr_table_t *http_headers;
  array_header *query_params;

  res = aws_sign_v4_generate(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_sign_v4_generate(p, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null access key ID");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  access_key_id = "ACCESS_KEY_ID";
  res = aws_sign_v4_generate(p, access_key_id, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null secret access key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  secret_access_key = "SECRET_ACCESS_KEY";
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null region");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  region = "us-west-2";
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null service");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  service = "ec2";
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region,
    service, NULL, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null HTTP handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region,
    service, http, NULL, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null HTTP method");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_method = "GET";
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region,
    service, http, http_method, NULL, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null HTTP path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_path = "/some/example/path";
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region,
    service, http, http_method, http_path, NULL, NULL, 0);
  fail_unless(res < 0, "Failed to handle null query params");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  query_params = make_array(p, 0, sizeof(char *));
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region,
    service, http, http_method, http_path, query_params, NULL, 0);
  fail_unless(res < 0, "Failed to handle null headers");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_headers = aws_http_default_headers(p, NULL);
  res = aws_sign_v4_generate(p, access_key_id, secret_access_key, region,
    service, http, http_method, http_path, query_params, http_headers, NULL, 0);
  fail_unless(res < 0, "Failed to handle null headers");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
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

  suite_add_tcase(suite, testcase);
  return suite;
}
