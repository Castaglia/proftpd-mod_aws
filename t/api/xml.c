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

/* XML API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_xml_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.xml", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.xml", 0, 0);
  }

  aws_xml_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (xml_doc_parse_test) {
  void *xml;
  const char *data;
  size_t datasz;

  xml = aws_xml_doc_parse(p, NULL, NULL);
  fail_unless(xml == NULL, "Failed to handle null data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  data = "foo bar baz";

  xml = aws_xml_doc_parse(p, data, 0);
  fail_unless(xml == NULL, "Failed to handle empty data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  datasz = strlen(data);
  xml = aws_xml_doc_parse(p, data, datasz);
  fail_unless(xml == NULL, "Failed to handle malformed XML data");
}
END_TEST

START_TEST (xml_elt_get_child_count_test) {
}
END_TEST

Suite *tests_get_xml_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("xml");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, xml_doc_parse_test);
  tcase_add_test(testcase, xml_elt_get_child_count_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
