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

  xml = aws_xml_doc_parse(p, NULL, 0);
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

START_TEST (xml_doc_get_root_elt_test) {
  void *elt;

  elt = aws_xml_doc_get_root_elt(NULL, NULL);
  fail_unless(elt == NULL, "Failed to handle null doc");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (xml_elt_get_child_test) {
  void *kid;

  kid = aws_xml_elt_get_child(NULL, NULL, NULL, 0);
  fail_unless(kid == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (xml_elt_get_child_count_test) {
  int res;

  res = aws_xml_elt_get_child_count(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (xml_elt_get_next_test) {
  void *elt;

  elt = aws_xml_elt_get_next(NULL, NULL);
  fail_unless(elt == NULL, "Failed to handle null arguments");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (xml_elt_get_name_test) {
  const char *name;

  name = aws_xml_elt_get_name(NULL, NULL, NULL);
  fail_unless(name == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = aws_xml_elt_get_name(p, NULL, NULL);
  fail_unless(name == NULL, "Failed to handle null element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (xml_elt_get_text_test) {
  const char *text;

  text = aws_xml_elt_get_text(NULL, NULL);
  fail_unless(text == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = aws_xml_elt_get_text(p, NULL);
  fail_unless(text == NULL, "Failed to handle null element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (xml_text_alloc_test) {
  void *text;

  mark_point();
  text = aws_xml_text_alloc(NULL);
  fail_unless(text == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  aws_xml_text_free(NULL, NULL);

  mark_point();
  aws_xml_text_free(p, NULL);

  mark_point();
  text = aws_xml_text_alloc(p);
  fail_unless(text != NULL, "Failed to allocate XML text: %s", strerror(errno));

  mark_point();
  aws_xml_text_free(p, text);
}
END_TEST

START_TEST (xml_text_elt_start_test) {
  void *text;
  int res;

  mark_point();
  res = aws_xml_text_elt_start(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_start(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = aws_xml_text_alloc(p);
  fail_unless(text != NULL, "Failed to allocate XML text: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_start(p, text, NULL);
  fail_unless(res < 0, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_start(p, text, "Test");
  fail_unless(res == 0, "Failed to start element <Test>: %s", strerror(errno));

  mark_point();
  aws_xml_text_free(p, text);
}
END_TEST

START_TEST (xml_text_elt_end_test) {
  void *text;
  int res;

  mark_point();
  res = aws_xml_text_elt_end(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_end(p, NULL);
  fail_unless(res < 0, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = aws_xml_text_alloc(p);
  fail_unless(text != NULL, "Failed to allocate XML text: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_end(p, text);
  fail_unless(res < 0, "Failed to handle unstarted element");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_start(p, text, "Test");
  fail_unless(res == 0, "Failed to start element <Test>: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_end(p, text);
  fail_unless(res == 0, "Failed to end element <Test>: %s", strerror(errno));

  mark_point();
  aws_xml_text_free(p, text);
}
END_TEST

START_TEST (xml_text_elt_add_attribute_test) {
  void *text;
  int res;
  const char *name, *value;

  mark_point();
  res = aws_xml_text_elt_add_attribute(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_add_attribute(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = aws_xml_text_alloc(p);
  fail_unless(text != NULL, "Failed to allocate XML text: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_add_attribute(p, text, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo";

  mark_point();
  res = aws_xml_text_elt_add_attribute(p, text, name, NULL);
  fail_unless(res < 0, "Failed to handle null value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  value = "bar";

  /* We can't add an attribute if we haven't started an element. */

  mark_point();
  res = aws_xml_text_elt_add_attribute(p, text, name, value);
  fail_unless(res < 0, "Failed to handle null value");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_start(p, text, "Foo");
  fail_unless(res == 0, "Failed to start element <Foo>: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_add_attribute(p, text, name, value);
  fail_unless(res == 0, "Failed add attribute '%s=%s': %s", name, value,
    strerror(errno));

  mark_point();
  aws_xml_text_free(p, text);
}
END_TEST

START_TEST (xml_text_elt_add_child_test) {
  void *text;
  int res;
  const char *name, *value;

  mark_point();
  res = aws_xml_text_elt_add_child(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_xml_text_elt_add_child(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = aws_xml_text_alloc(p);
  fail_unless(text != NULL, "Failed to allocate XML text: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_add_child(p, text, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo";

  mark_point();
  res = aws_xml_text_elt_add_child(p, text, name, NULL);
  fail_unless(res < 0, "Failed to handle null value");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  value = "bar";

  mark_point();
  res = aws_xml_text_elt_add_child(p, text, name, value);
  fail_unless(res == 0, "Failed add child '<%s>%s</%s>': %s", name, value,
    name, strerror(errno));

  mark_point();
  aws_xml_text_free(p, text);
}
END_TEST

START_TEST (xml_text_content_test) {
  void *text;
  int res;
  const char *name, *value, *content, *expected;

  mark_point();
  content = aws_xml_text_content(NULL, NULL);
  fail_unless(content == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  content = aws_xml_text_content(p, NULL);
  fail_unless(content == NULL, "Failed to handle null text");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  text = aws_xml_text_alloc(p);
  fail_unless(text != NULL, "Failed to allocate XML text: %s", strerror(errno));

  name = "Root";

  mark_point();
  res = aws_xml_text_elt_start(p, text, name);
  fail_unless(res == 0, "Failed to start element <%s>: %s", name,
    strerror(errno));

  name = "Kids";

  mark_point();
  res = aws_xml_text_elt_start(p, text, name);
  fail_unless(res == 0, "Failed to start element <%s>: %s", name,
    strerror(errno));

  name = "Kid";
  value = "foo";

  mark_point();
  res = aws_xml_text_elt_add_child(p, text, name, value);
  fail_unless(res == 0, "Failed add child '<%s>%s</%s>': %s", name, value,
    name, strerror(errno));

  value = "bar";
  mark_point();
  res = aws_xml_text_elt_add_child(p, text, name, value);
  fail_unless(res == 0, "Failed add child '<%s>%s</%s>': %s", name, value,
    name, strerror(errno));

  mark_point();
  res = aws_xml_text_elt_end(p, text);
  fail_unless(res == 0, "Failed to end element <Kids>: %s", strerror(errno));

  mark_point();
  res = aws_xml_text_elt_end(p, text);
  fail_unless(res == 0, "Failed to end element <Root>: %s", strerror(errno));

  content = aws_xml_text_content(p, text);
  fail_unless(content != NULL, "Failed to get XML text content: %s",
    strerror(errno));

  mark_point();
  aws_xml_text_free(p, text);

  expected = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Root><Kids><Kid>foo</Kid><Kid>bar</Kid></Kids></Root>\n";
  fail_unless(strcmp(content, expected) == 0, "Expected '%s', got '%s'",
    expected, content);
}
END_TEST

Suite *tests_get_xml_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("xml");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  /* XML document parsing/reading */
  tcase_add_test(testcase, xml_doc_parse_test);
  tcase_add_test(testcase, xml_doc_get_root_elt_test);
  tcase_add_test(testcase, xml_elt_get_child_test);
  tcase_add_test(testcase, xml_elt_get_child_count_test);
  tcase_add_test(testcase, xml_elt_get_next_test);
  tcase_add_test(testcase, xml_elt_get_name_test);
  tcase_add_test(testcase, xml_elt_get_text_test);

  /* XML text writing */
  tcase_add_test(testcase, xml_text_alloc_test);
  tcase_add_test(testcase, xml_text_elt_start_test);
  tcase_add_test(testcase, xml_text_elt_end_test);
  tcase_add_test(testcase, xml_text_elt_add_attribute_test);
  tcase_add_test(testcase, xml_text_elt_add_child_test);
  tcase_add_test(testcase, xml_text_content_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
