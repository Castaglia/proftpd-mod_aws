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

/* Utils API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }
}

static void tear_down(void) {
  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (utils_table2array_test) {
  array_header *res;
  pr_table_t *tab;
  const char **elts, *expected;

  res = aws_utils_table2array(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_utils_table2array(p, NULL);
  fail_unless(res == NULL, "Failed to handle null table");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  tab = pr_table_alloc(p, 0);
  pr_table_add_dup(tab, pstrdup(p, "Foo"), "Bar", 0);
  pr_table_add_dup(tab, pstrdup(p, "Baz"), "Quxx", 0);
  pr_table_add_dup(tab, pstrdup(p, "Quzz"), NULL, 0);

  res = aws_utils_table2array(p, tab);
  fail_unless(res != NULL, "Failed to convert table to array: %s",
    strerror(errno));
  fail_unless(res->nelts == 2, "Expected 2 elements, got %u", res->nelts);

  elts = res->elts;

  expected = "Foo: Bar";
  fail_unless(strcmp(elts[0], expected) == 0,
    "Expected '%s', got '%s'", expected, elts[0]);

  expected = "Baz: Quxx";
  fail_unless(strcmp(elts[1], expected) == 0,
    "Expected '%s', got '%s'", expected, elts[1]);

  pr_table_free(tab);
}
END_TEST

START_TEST (utils_str_n2s_test) {
  char *res, *expected;
  int n;

  res = aws_utils_str_n2s(NULL, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  n = 0;
  expected = "0";
  res = aws_utils_str_n2s(p, n);
  fail_unless(res != NULL, "Failed to handle %d: %s", n, strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = -1;
  expected = "-1";
  res = aws_utils_str_n2s(p, n);
  fail_unless(res != NULL, "Failed to handle %d: %s", n, strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = 7;
  expected = "7";
  res = aws_utils_str_n2s(p, n);
  fail_unless(res != NULL, "Failed to handle %d: %s", n, strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_str_ul2s_test) {
  char *res, *expected;
  unsigned long n;

  res = aws_utils_str_ul2s(NULL, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  n = 0;
  expected = "0";
  res = aws_utils_str_ul2s(p, n);
  fail_unless(res != NULL, "Failed to handle %lu: %s", n, strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = 7;
  expected = "7";
  res = aws_utils_str_ul2s(p, n);
  fail_unless(res != NULL, "Failed to handle %lu: %s", n, strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_str_trim_test) {
  char *res, *expected;
  const char *str;

  res = aws_utils_str_trim(NULL, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_utils_str_trim(p, NULL);
  fail_unless(res == NULL, "Failed to handle null string");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  str = "";
  expected = "";
  res = aws_utils_str_trim(p, str);
  fail_unless(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo";
  expected = "foo";
  res = aws_utils_str_trim(p, str);
  fail_unless(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "bar  ";
  expected = "bar";
  res = aws_utils_str_trim(p, str);
  fail_unless(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo  bar  ";
  expected = "foo  bar";
  res = aws_utils_str_trim(p, str);
  fail_unless(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  fail_unless(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

Suite *tests_get_utils_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("utils");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, utils_table2array_test);
  tcase_add_test(testcase, utils_str_n2s_test);
  tcase_add_test(testcase, utils_str_ul2s_test);
  tcase_add_test(testcase, utils_str_trim_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
