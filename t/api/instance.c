/*
 * ProFTPD - mod_aws testsuite
 * Copyright (c) 2016-2022 TJ Saunders <tj@castaglia.org>
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

/* Instance API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  unsigned long feature_flags = 0UL;

  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_http_init(p, &feature_flags, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.instance", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.instance", 0, 0);
  }

  aws_http_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (instance_get_info_test) {
  struct aws_info *info;

  mark_point();
  info = aws_instance_get_info(p);
  ck_assert_msg(info != NULL, "Failed to handle non-AWS environment");
  ck_assert_msg(info->account_id == NULL, "Expected null account ID, got '%s'",
    info->account_id);
}
END_TEST

Suite *tests_get_instance_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("instance");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);
  tcase_set_timeout(testcase, 10);

  tcase_add_test(testcase, instance_get_info_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
