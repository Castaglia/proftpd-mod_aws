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

START_TEST (instance_get_iam_credentials_test) {
  struct iam_info *iam;
  const char *iam_role;

  iam = aws_instance_get_iam_credentials(NULL, NULL);
  fail_unless(iam == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  iam = aws_instance_get_iam_credentials(p, NULL);
  fail_unless(iam == NULL, "Failed to handle null role");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  iam_role = "foo";
  iam = aws_instance_get_iam_credentials(p, iam_role);
  fail_unless(iam == NULL, "Failed to handle unavailable creds for role");
  fail_unless(errno == ENOENT || errno == ETIMEDOUT,
    "Expected ENOENT (%d) or ETIMEDOUT (%d), got %s (%d)", ENOENT, ETIMEDOUT,
    strerror(errno), errno);
}
END_TEST

Suite *tests_get_instance_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("instance");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, instance_get_iam_credentials_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
