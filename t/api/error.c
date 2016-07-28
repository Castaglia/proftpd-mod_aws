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

/* Error API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_xml_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.error", 1, 20);
    pr_trace_set_levels("aws.xml", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.error", 0, 0);
    pr_trace_set_levels("aws.xml", 0, 0);
  }

  aws_xml_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (error_get_code_test) {
  unsigned int res, expected;

  expected = AWS_ERROR_CODE_UNKNOWN;
  res = aws_error_get_code(p, NULL);
  fail_unless(res == expected, "Expected %u, got %u", expected, res);

  expected = AWS_ERROR_CODE_AUTH_FAILURE;
  res = aws_error_get_code(p, "AuthFailure");
  fail_unless(res == expected, "Expected %u, got %u", expected, res);

  expected = AWS_ERROR_CODE_UNKNOWN;
  res = aws_error_get_code(p, "fooBarBaz");
  fail_unless(res == expected, "Expected %u, got %u", expected, res);
}
END_TEST

START_TEST (error_get_name_test) {
  const char *res, *expected;

  expected = "<unknown>";
  res = aws_error_get_name(0);
  fail_unless(res != NULL, "Failed to handle zero");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  expected = "AuthFailure";
  res = aws_error_get_name(AWS_ERROR_CODE_AUTH_FAILURE);
  fail_unless(res != NULL, "Failed to handle zero");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  expected = "<unknown>";
  res = aws_error_get_name(UINT_MAX);
  fail_unless(res != NULL, "Failed to handle UINT_MAX");
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);
}
END_TEST

START_TEST (error_parse_xml_test) {
  struct aws_error *err;

  err = aws_error_parse_xml(p, NULL, 0);
  fail_unless(err == NULL, "Failed to handle null data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_error_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("error");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, error_get_code_test);
  tcase_add_test(testcase, error_get_name_test);
  tcase_add_test(testcase, error_parse_xml_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
