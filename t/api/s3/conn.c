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

/* S3 Conn API tests. */

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
    pr_trace_set_levels("aws.s3.conn", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
    pr_trace_set_levels("aws.s3.conn", 0, 0);
  }

  aws_http_free();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (s3_conn_destroy_test) {
  int res;

  res = aws_s3_conn_destroy(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (s3_conn_alloc_test) {
  struct s3_conn *s3;

  s3 = aws_s3_conn_alloc(NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(s3 == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (s3_conn_clear_response_test) {
  mark_point();
  aws_s3_conn_clear_response(NULL);
}
END_TEST

Suite *tests_get_s3_conn_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3.conn");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, s3_conn_destroy_test);
  tcase_add_test(testcase, s3_conn_alloc_test);
  tcase_add_test(testcase, s3_conn_clear_response_test);

/* XXX TODO:
 *  s3_get_test
 *  s3_head_test
 *  s3_post_test
 *  (s3_put_test)
 *  (s3_delete_test)
 */

  suite_add_tcase(suite, testcase);
  return suite;
}
