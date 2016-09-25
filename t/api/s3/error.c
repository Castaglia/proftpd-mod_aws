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

/* S3 Error API tests. */

#include "../tests.h"

static pool *p = NULL;

static void set_up(void) {
  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  aws_xml_init(p);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.s3.error", 1, 20);
    pr_trace_set_levels("aws.xml", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.s3.error", 0, 0);
    pr_trace_set_levels("aws.xml", 0, 0);
  }

  aws_xml_free();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (s3_error_get_code_test) {
  unsigned int err_code;
  const char *err_name;

  err_code = aws_s3_error_get_code(NULL, NULL);
  fail_unless(err_code == AWS_ERROR_CODE_UNKNOWN, "Failed to handle null pool");

  err_code = aws_s3_error_get_code(p, NULL);
  fail_unless(err_code == AWS_ERROR_CODE_UNKNOWN, "Failed to handle null name");

  err_name = "SlowDown";
  err_code = aws_s3_error_get_code(p, err_name);
  fail_unless(err_code == AWS_S3_ERROR_CODE_SLOW_DOWN,
    "Failed to resolve S3 error name '%s'", err_name);

  err_name = "AuthFailure";
  err_code = aws_s3_error_get_code(p, err_name);
  fail_unless(err_code == AWS_ERROR_CODE_AUTH_FAILURE,
    "Failed to resolve error name '%s'", err_name);
}
END_TEST

START_TEST (s3_error_get_name_test) {
  unsigned int err_code;
  const char *res, *expected;

  err_code = AWS_ERROR_CODE_AUTH_FAILURE;
  res = aws_s3_error_get_name(err_code);
  fail_unless(res != NULL, "Failed to resolve error code %u", err_code);
  expected = "AuthFailure";
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);

  err_code = AWS_S3_ERROR_CODE_SLOW_DOWN;
  res = aws_s3_error_get_name(err_code);
  fail_unless(res != NULL, "Failed to resolve S3 error code %u", err_code);
  expected = "SlowDown";
  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'", expected,
    res);
}
END_TEST

START_TEST (s3_error_parse_xml_test) {
  struct aws_error *err;
  const char *data;
  size_t datasz;

  err = aws_s3_error_parse_xml(p, NULL, 0);
  fail_unless(err == NULL, "Failed to handle null data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  data = "foo";
  err = aws_s3_error_parse_xml(p, data, 0);
  fail_unless(err == NULL, "Failed to handle empty data");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no root element */

  data = pstrdup(p, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err == NULL, "Failed to handle XML with no root element");

  /* Malformed XML: no <Error> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<FooBar/>\n");
  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err == NULL, "Failed to handle XML with no <Error> element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: <Error> element with wrong child count (1) */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Error>\n"
    "  <RequestId>ea966190-f9aa-478e-9ede-example</RequestId>\n"
    "</Error>\n");
  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err == NULL, "Failed to handle XML with bad <Error> element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <Code> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Error>\n"
    "  <Number>7</Number>\n"
    "  <RequestId>ea966190-f9aa-478e-9ede-example</RequestId>\n"
    "</Error>\n");
  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err == NULL, "Failed to handle XML with no <Code> element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <Message> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Error>\n"
    "  <Code>InvalidGroup.NotFound</Code>\n"
    "  <RequestId>ea966190-f9aa-478e-9ede-example</RequestId>\n"
    "</Error>\n");
  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err == NULL, "Failed to handle XML with no <Message> element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  /* Malformed XML: no <RequestId> element */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Error>\n"
    "  <Code>InvalidGroup.NotFound</Code>\n"
    "  <Message>The security group ID 'sg-1a2b3c4d' does not exist</Message>\n"
    "  <Random>ea966190-f9aa-478e-9ede-example</Random>\n"
    "</Error>\n");
  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err == NULL, "Failed to handle XML with no <RequestId> element");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

/* XXX Need to populate S3-specific error codes, handle <Resource> element, etc. */

  data = pstrdup(p,
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<Error>\n"
    "  <Code>InvalidGroup.NotFound</Code>\n"
    "  <Message>The security group ID 'sg-1a2b3c4d' does not exist</Message>\n"
    "  <RequestId>ea966190-f9aa-478e-9ede-example</RequestId>\n"
    "</Error>\n");

  datasz = strlen(data);
  err = aws_s3_error_parse_xml(p, data, datasz);
  fail_unless(err != NULL, "Failed to parse error XML: %s", strerror(errno));
  fail_unless(err->err_code == AWS_ERROR_CODE_EC2_INVALID_GROUP_NOT_FOUND,
    "Expected error code %u, got %u",
    AWS_ERROR_CODE_EC2_INVALID_GROUP_NOT_FOUND, err->err_code);
  fail_unless(err->err_msg != NULL, "Expected error message, got null");
  fail_unless(strcmp(err->err_msg,
    "The security group ID 'sg-1a2b3c4d' does not exist") == 0,
    "Failed to get expected error message");
  fail_unless(err->req_id != NULL, "Expected request ID, got null");
  fail_unless(strcmp(err->req_id, "ea966190-f9aa-478e-9ede-example") == 0,
    "Failed to get expected request ID");
}
END_TEST

Suite *tests_get_s3_error_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3.error");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, s3_error_get_code_test);
  tcase_add_test(testcase, s3_error_get_name_test);
  tcase_add_test(testcase, s3_error_parse_xml_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
