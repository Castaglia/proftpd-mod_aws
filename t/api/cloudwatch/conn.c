/*
 * ProFTPD - mod_aws testsuite
 * Copyright (c) 2017 TJ Saunders <tj@castaglia.org>
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

/* CloudWatch Conn API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  unsigned long feature_flags = 0UL;

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  aws_http_init(p, &feature_flags, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 1, 20);
    pr_trace_set_levels("aws.cloudwatch.conn", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
    pr_trace_set_levels("aws.cloudwatch.conn", 0, 0);
  }

  aws_http_free();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (cloudwatch_conn_destroy_test) {
  int res;

  res = aws_cloudwatch_conn_destroy(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null cloudwatch");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (cloudwatch_conn_alloc_test) {
  struct cloudwatch_conn *cw;

  cw = aws_cloudwatch_conn_alloc(NULL, 0, 0, NULL, NULL, NULL, NULL);
  fail_unless(cw == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (cloudwatch_conn_clear_response_test) {
  mark_point();
  aws_cloudwatch_conn_clear_response(NULL);
}
END_TEST

START_TEST (cloudwatch_conn_reset_response_test) {
  mark_point();
  aws_cloudwatch_conn_reset_response(NULL);
}
END_TEST

START_TEST (cloudwatch_conn_flush_test) {
  int res;

  mark_point();
  res = aws_cloudwatch_conn_flush(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_cloudwatch_conn_flush(p, NULL);
  fail_unless(res < 0, "Failed to handle null cloudwetch");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_cloudwatch_conn_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("cloudwatch.conn");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, cloudwatch_conn_destroy_test);
  tcase_add_test(testcase, cloudwatch_conn_alloc_test);
  tcase_add_test(testcase, cloudwatch_conn_clear_response_test);
  tcase_add_test(testcase, cloudwatch_conn_reset_response_test);
  tcase_add_test(testcase, cloudwatch_conn_flush_test);

/* XXX TODO:
 *  cloudwatch_get_test
 */

  suite_add_tcase(suite, testcase);
  return suite;
}
