/*
 * ProFTPD - mod_aws testsuite
 * Copyright (c) 2017-2022 TJ Saunders <tj@castaglia.org>
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

/* CloudWatch Dimension API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.cloudwatch.dimension", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.cloudwatch.dimension", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  }
}

START_TEST (cloudwatch_dimension_get_test) {
  unsigned long flags;
  array_header *res;

  mark_point();
  res = aws_cloudwatch_dimension_get(NULL, 0, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  flags = 0;

  mark_point();
  res = aws_cloudwatch_dimension_get(p, flags, NULL);
  ck_assert_msg(res != NULL, "Failed to get dimension for flags %lu: %s",
    flags, strerror(errno));
  ck_assert_msg(res->nelts == 0, "Expected nelts 0, got %u", res->nelts);

  flags = AWS_CLOUDWATCH_DIMENSION_PROTOCOL;

  mark_point();
  res = aws_cloudwatch_dimension_get(p, flags, NULL);
  ck_assert_msg(res != NULL, "Failed to get dimension for flags %lu: %s",
    flags, strerror(errno));
  ck_assert_msg(res->nelts == 2, "Expected nelts 2, got %u", res->nelts);

  flags = AWS_CLOUDWATCH_DIMENSION_INSTANCE_ID;

  mark_point();
  res = aws_cloudwatch_dimension_get(p, flags, NULL);
  ck_assert_msg(res != NULL, "Failed to get dimension for flags %lu: %s",
    flags, strerror(errno));
  ck_assert_msg(res->nelts == 0, "Expected nelts 0, got %u", res->nelts);

  flags = AWS_CLOUDWATCH_DIMENSION_AVAIL_ZONE;

  mark_point();
  res = aws_cloudwatch_dimension_get(p, flags, NULL);
  ck_assert_msg(res != NULL, "Failed to get dimension for flags %lu: %s",
    flags, strerror(errno));
  ck_assert_msg(res->nelts == 0, "Expected nelts 0, got %u", res->nelts);
}
END_TEST

Suite *tests_get_cloudwatch_dimension_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("cloudwatch.dimension");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, cloudwatch_dimension_get_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
