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

/* HTTP API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_http_init(p, NULL, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
  }

  aws_http_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (http_alloc_test) {
  void *http;
  const char *cacerts;

  /* Note: We don't use the pool for allocating HTTP handles. */

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));
  aws_http_destroy(p, http);

  /* Assume that the tests are being run from the top-level of the project. */
  cacerts = "./aws-cacerts.pem";
  http = aws_http_alloc(p, 3, 5, cacerts);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));
  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_destroy_test) {
  int res;

  res = aws_http_destroy(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (http_default_headers_test) {
}
END_TEST

START_TEST (http_urldecode_test) {
}
END_TEST

START_TEST (http_urlencode_test) {
}
END_TEST

START_TEST (http_get_test) {
}
END_TEST

START_TEST (http_post_test) {
}
END_TEST

Suite *tests_get_http_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("http");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, http_alloc_test);
  tcase_add_test(testcase, http_free_test);
  tcase_add_test(testcase, http_default_headers_test);
  tcase_add_test(testcase, http_urldecode_test);
  tcase_add_test(testcase, http_urlencode_test);
  tcase_add_test(testcase, http_get_test);
  tcase_add_test(testcase, http_post_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
