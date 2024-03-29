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
  const char **elts, *expected, *expected2;

  res = aws_utils_table2array(NULL, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_utils_table2array(p, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null table");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  tab = pr_table_alloc(p, 0);
  pr_table_add_dup(tab, pstrdup(p, "Foo"), "Bar", 0);
  pr_table_add_dup(tab, pstrdup(p, "Baz"), "Quxx", 0);
  pr_table_add_dup(tab, pstrdup(p, "Quzz"), NULL, 0);

  res = aws_utils_table2array(p, tab);
  ck_assert_msg(res != NULL, "Failed to convert table to array: %s",
    strerror(errno));
  ck_assert_msg(res->nelts == 2, "Expected 2 elements, got %u", res->nelts);

  elts = res->elts;

  expected = "Foo: Bar";
  expected2 = "Baz: Quxx";
  ck_assert_msg(strcmp(elts[0], expected) == 0 || strcmp(elts[0], expected2) == 0,
    "Expected '%s' or '%s', got '%s'", expected, expected2, elts[0]);

  ck_assert_msg(strcmp(elts[1], expected) == 0 || strcmp(elts[1], expected2) == 0,
    "Expected '%s' or '%s', got '%s'", expected, expected2, elts[1]);

  pr_table_empty(tab);
  pr_table_free(tab);
}
END_TEST

START_TEST (utils_str_d2s_test) {
  char *res, *expected;
  double n;

  res = aws_utils_str_d2s(NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  n = 0;
  expected = "0.000";
  res = aws_utils_str_d2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %lf: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = -1;
  expected = "-1.000";
  res = aws_utils_str_d2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %lf: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = 7;
  expected = "7.000";
  res = aws_utils_str_d2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %lf: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_str_n2s_test) {
  char *res, *expected;
  int n;

  res = aws_utils_str_n2s(NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  n = 0;
  expected = "0";
  res = aws_utils_str_n2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %d: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = -1;
  expected = "-1";
  res = aws_utils_str_n2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %d: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = 7;
  expected = "7";
  res = aws_utils_str_n2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %d: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_str_off2s_test) {
  char *res, *expected;
  off_t n;

  res = aws_utils_str_off2s(NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  n = 0;
  expected = "0";
  res = aws_utils_str_off2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %" PR_LU ": %s", (pr_off_t) n,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = 7;
  expected = "7";
  res = aws_utils_str_off2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %" PR_LU ": %s", (pr_off_t) n,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = (off_t) -1;
  expected = "18446744073709551615";
  res = aws_utils_str_off2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %" PR_LU ": %s", (pr_off_t) n,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_str_ul2s_test) {
  char *res, *expected;
  unsigned long n;

  res = aws_utils_str_ul2s(NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  n = 0;
  expected = "0";
  res = aws_utils_str_ul2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %lu: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  n = 7;
  expected = "7";
  res = aws_utils_str_ul2s(p, n);
  ck_assert_msg(res != NULL, "Failed to handle %lu: %s", n, strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_str_trim_test) {
  char *res, *expected;
  const char *str;

  res = aws_utils_str_trim(NULL, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_utils_str_trim(p, NULL);
  ck_assert_msg(res == NULL, "Failed to handle null string");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  str = "";
  expected = "";
  res = aws_utils_str_trim(p, str);
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo";
  expected = "foo";
  res = aws_utils_str_trim(p, str);
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "bar  ";
  expected = "bar";
  res = aws_utils_str_trim(p, str);
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo  bar  ";
  expected = "foo  bar";
  res = aws_utils_str_trim(p, str);
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);
}
END_TEST

START_TEST (utils_strn_trim_test) {
  char *res, *expected;
  const char *str;

  res = aws_utils_strn_trim(NULL, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_utils_strn_trim(p, NULL, 0);
  ck_assert_msg(res == NULL, "Failed to handle null string");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  str = "";
  expected = "";
  res = aws_utils_strn_trim(p, str, 0);
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo";
  expected = "foo";
  res = aws_utils_strn_trim(p, str, strlen(str));
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "bar  ";
  expected = "bar";
  res = aws_utils_strn_trim(p, str, strlen(str));
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo  bar  ";
  expected = "foo  bar";
  res = aws_utils_strn_trim(p, str, strlen(str));
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
    "Expected '%s', got '%s'", expected, res);

  str = "  foo  bar  ";
  expected = "foo";
  res = aws_utils_strn_trim(p, str, 7);
  ck_assert_msg(res != NULL, "Failed to trim string '%s': %s", str,
    strerror(errno));
  ck_assert_msg(strcmp(res, expected) == 0,
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
  tcase_add_test(testcase, utils_str_d2s_test);
  tcase_add_test(testcase, utils_str_n2s_test);
  tcase_add_test(testcase, utils_str_off2s_test);
  tcase_add_test(testcase, utils_str_ul2s_test);
  tcase_add_test(testcase, utils_str_trim_test);
  tcase_add_test(testcase, utils_strn_trim_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
