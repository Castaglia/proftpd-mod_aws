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

/* S3 Utilities API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.s3.utils", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.s3.utils", 0, 0);
  }

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (s3_utils_lastmod2unix_test) {
  time_t res, expected;
  const char *last_modified;

  mark_point();
  res = aws_s3_utils_lastmod2unix(NULL, NULL);
  fail_unless(res == 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_utils_lastmod2unix(p, NULL);
  fail_unless(res == 0, "Failed to handle null last_modified");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  last_modified = "foo";

  mark_point();
  res = aws_s3_utils_lastmod2unix(p, last_modified);
  fail_unless(res == 0, "Failed to handle invalid last_modified '%s': %s",
    last_modified, strerror(errno));
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  last_modified = "2016-09-26T22:50:31.000Z";
  expected = 1474959031;

  mark_point();
  res = aws_s3_utils_lastmod2unix(p, last_modified);

  /* The expected value is sensitive to the TZ setting, so make this
   * assertion a little more lenient.
   */
  if (res != expected) {
    expected = 1474930231;
  }

  fail_unless(res == expected, "Expected %lu, got %lu",
    (unsigned long) expected, (unsigned long) res);
}
END_TEST

START_TEST (s3_utils_unix2lastmod_test) {
  time_t now;
  const char *last_modified, *expected;

  mark_point();
  last_modified = aws_s3_utils_unix2lastmod(NULL, 0);
  fail_unless(last_modified == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), %s (%d)", EINVAL,
    strerror(errno), errno);

  now = 0;

  mark_point();
  last_modified = aws_s3_utils_unix2lastmod(p, now);
  fail_unless(last_modified != NULL, "Failed to handle Unix epoch %lu: %s",
    (unsigned long) now, strerror(errno));

  expected = "1970-01-01T00:00:00";
  fail_unless(strcmp(last_modified, expected) == 0, "Expected '%s', got '%s'",
    expected, last_modified);

  now = 1476157691;

  mark_point();
  last_modified = aws_s3_utils_unix2lastmod(p, now);
  fail_unless(last_modified != NULL, "Failed to handle Unix epoch %lu: %s",
    (unsigned long) now, strerror(errno));

  expected = "2016-10-11T03:48:11";
  fail_unless(strcmp(last_modified, expected) == 0, "Expected '%s', got '%s'",
    expected, last_modified);
}
END_TEST

START_TEST (s3_utils_urlencode_test) {
  const char *res, *str, *expected;

  mark_point();
  res = aws_s3_utils_urlencode(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_utils_urlencode(p, NULL);
  fail_unless(res == NULL, "Failed to handle null str");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  str = "foo bar";
  expected = "foo+bar";

  mark_point();
  res = aws_s3_utils_urlencode(p, str);
  fail_unless(res != NULL, "Failed to URL-encode '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  str = "foo/bar";
  expected = "foo/bar";

  mark_point();
  res = aws_s3_utils_urlencode(p, str);
  fail_unless(res != NULL, "Failed to URL-encode '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  str = "foo.bar";
  expected = "foo.bar";

  mark_point();
  res = aws_s3_utils_urlencode(p, str);
  fail_unless(res != NULL, "Failed to URL-encode '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  str = "foo/bar@baz&&quxx";
  expected = "foo/bar%40baz%26%26quxx";

  mark_point();
  res = aws_s3_utils_urlencode(p, str);
  fail_unless(res != NULL, "Failed to URL-encode '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);
}
END_TEST

Suite *tests_get_s3_utils_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3.utils");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, s3_utils_lastmod2unix_test);
  tcase_add_test(testcase, s3_utils_unix2lastmod_test);
  tcase_add_test(testcase, s3_utils_urlencode_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
