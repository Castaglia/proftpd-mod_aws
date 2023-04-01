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

/* Error API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_xml_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.error", 1, 20);
    pr_trace_set_levels("aws.xml", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.error", 0, 0);
    pr_trace_set_levels("aws.xml", 0, 0);
  }

  aws_xml_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  }
}

START_TEST (error_get_code_test) {
  unsigned int res, expected;

  expected = AWS_ERROR_CODE_UNKNOWN;
  res = aws_error_get_code(p, NULL);
  ck_assert_msg(res == expected, "Expected %u, got %u", expected, res);

  expected = AWS_ERROR_CODE_AUTH_FAILURE;
  res = aws_error_get_code(p, "AuthFailure");
  ck_assert_msg(res == expected, "Expected %u, got %u", expected, res);

  expected = AWS_ERROR_CODE_UNKNOWN;
  res = aws_error_get_code(p, "fooBarBaz");
  ck_assert_msg(res == expected, "Expected %u, got %u", expected, res);
}
END_TEST

START_TEST (error_get_name_test) {
  const char *res, *expected;

  expected = "<unknown>";
  res = aws_error_get_name(0);
  ck_assert_msg(res != NULL, "Failed to handle zero");
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  expected = "AuthFailure";
  res = aws_error_get_name(AWS_ERROR_CODE_AUTH_FAILURE);
  ck_assert_msg(res != NULL, "Failed to handle zero");
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  expected = "<unknown>";
  res = aws_error_get_name(UINT_MAX);
  ck_assert_msg(res != NULL, "Failed to handle UINT_MAX");
  ck_assert_msg(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);
}
END_TEST

START_TEST (error_parse_xml_test) {
  struct aws_error *err;
  const char *data;
  size_t datasz;

  err = aws_error_parse_xml(p, NULL, 0);
  ck_assert_msg(err == NULL, "Failed to handle null data");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  data = "foo";
  err = aws_error_parse_xml(p, data, 0);
  ck_assert_msg(err == NULL, "Failed to handle empty data");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no root element */

  data = pstrdup(p, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no root element");

  /* Malformed XML: no <Response> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<FooBar/>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no <Response> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: <Response> element with wrong child count (1) */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <RequestID>ea966190-f9aa-478e-9ede-example</RequestID>\n"
    "</Response>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with bad <Response> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <Errors> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <Foo>bar</Foo>\n"
    "  <RequestID>ea966190-f9aa-478e-9ede-example</RequestID>\n"
    "</Response>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no <Errors> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <Error> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <Errors>\n"
    "    <Foo>bar</Foo>\n"
    "  </Errors>\n"
    "  <RequestID>ea966190-f9aa-478e-9ede-example</RequestID>\n"
    "</Response>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no <Error> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <Code> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <Errors>\n"
    "    <Error>\n"
    "      <Number>7</Number>\n"
    "    </Error>\n"
    "  </Errors>\n"
    "  <RequestID>ea966190-f9aa-478e-9ede-example</RequestID>\n"
    "</Response>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no <Code> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <Message> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <Errors>\n"
    "    <Error>\n"
    "      <Code>InvalidGroup.NotFound</Code>\n"
    "    </Error>\n"
    "  </Errors>\n"
    "  <RequestID>ea966190-f9aa-478e-9ede-example</RequestID>\n"
    "</Response>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no <Message> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <RequestID> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <Errors>\n"
    "    <Error>\n"
    "      <Code>InvalidGroup.NotFound</Code>\n"
    "      <Message>The security group ID 'sg-1a2b3c4d' does not exist</Message>\n"
    "    </Error>\n"
    "  </Errors>\n"
    "  <Random>ea966190-f9aa-478e-9ede-example</Random>\n"
    "</Response>\n");
  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err == NULL, "Failed to handle XML with no <RequestID> element");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Currently, mod_aws expects XML error responses as returned by EC2;
   * other services like S3 MAY return slightly different formats.
   * Caveat emptor.
   */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Response>\n"
    "  <Errors>\n"
    "    <Error>\n"
    "      <Code>InvalidGroup.NotFound</Code>\n"
    "      <Message>The security group ID 'sg-1a2b3c4d' does not exist</Message>\n"
    "    </Error>\n"
    "  </Errors>\n"
    "  <RequestID>ea966190-f9aa-478e-9ede-example</RequestID>\n"
    "</Response>\n");

  datasz = strlen(data);
  err = aws_error_parse_xml(p, data, datasz);
  ck_assert_msg(err != NULL, "Failed to parse error XML: %s", strerror(errno));
  ck_assert_msg(err->err_code == AWS_ERROR_CODE_EC2_INVALID_GROUP_NOT_FOUND,
    "Expected error code %u, got %u",
    AWS_ERROR_CODE_EC2_INVALID_GROUP_NOT_FOUND, err->err_code);
  ck_assert_msg(err->err_msg != NULL, "Expected error message, got null");
  ck_assert_msg(strcmp(err->err_msg,
    "The security group ID 'sg-1a2b3c4d' does not exist") == 0,
    "Failed to get expected error message");
  ck_assert_msg(err->req_id != NULL, "Expected request ID, got null");
  ck_assert_msg(strcmp(err->req_id, "ea966190-f9aa-478e-9ede-example") == 0,
    "Failed to get expected request ID");
}
END_TEST

Suite *tests_get_error_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("error");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, error_get_code_test);
  tcase_add_test(testcase, error_get_name_test);
  tcase_add_test(testcase, error_parse_xml_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
