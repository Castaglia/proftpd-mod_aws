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

/* HTTP API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  unsigned long feature_flags = 0UL;

  if (p == NULL) {
    p = make_sub_pool(NULL);
  }

  aws_http_init(p, &feature_flags, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
  }

  aws_http_free();

  if (p) {
    destroy_pool(p);
    p = NULL;
  } 
}

START_TEST (http_alloc_test) {
  void *http;
  const char *cacerts;

  /* Note: We don't use the pool for allocating HTTP handles. */

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));
  aws_http_destroy(p, http);

  /* Assume that the tests are being run from the top-level of the project. */
  cacerts = "./aws-cacerts.pem";
  http = aws_http_alloc(p, 3, 5, cacerts);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));
  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_destroy_test) {
  int res;

  res = aws_http_destroy(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (http_default_headers_test) {
  pr_table_t *tab;
  time_t now;
  struct tm *gmt_tm;
  const char *header_name, *header_value;

  tab = aws_http_default_headers(NULL, NULL);
  fail_unless(tab == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  tab = aws_http_default_headers(p, NULL);
  fail_unless(tab != NULL, "Failed to allocate default headers: %s",
    strerror(errno));

  header_name = AWS_HTTP_HEADER_ACCEPT;
  header_value = pr_table_get(tab, header_name, NULL);
  fail_unless(header_value != NULL, "Failed to get '%s' header value: %s",
    header_name, strerror(errno));

  header_name = AWS_HTTP_HEADER_USER_AGENT;
  header_value = pr_table_get(tab, header_name, NULL);
  fail_unless(header_value != NULL, "Failed to get '%s' header value: %s",
    header_name, strerror(errno));

  header_name = AWS_HTTP_HEADER_X_AMZ_DATE;
  header_value = pr_table_get(tab, header_name, NULL);
  fail_unless(header_value == NULL, "Got '%s' header value unexpectedly",
    header_name);

  pr_table_empty(tab);
  pr_table_free(tab);

  /* Now, provide a date. */
  time(&now);
  gmt_tm = pr_gmtime(p, &now);

  tab = aws_http_default_headers(p, gmt_tm);
  fail_unless(tab != NULL, "Failed to allocate default headers: %s",
    strerror(errno));

  header_name = AWS_HTTP_HEADER_ACCEPT;
  header_value = pr_table_get(tab, header_name, NULL);
  fail_unless(header_value != NULL, "Failed to get '%s' header value: %s",
    header_name, strerror(errno));

  header_name = AWS_HTTP_HEADER_USER_AGENT;
  header_value = pr_table_get(tab, header_name, NULL);
  fail_unless(header_value != NULL, "Failed to get '%s' header value: %s",
    header_name, strerror(errno));

  header_name = AWS_HTTP_HEADER_X_AMZ_DATE;
  header_value = pr_table_get(tab, header_name, NULL);
  fail_unless(header_value != NULL, "Failed to get '%s' header value: %s",
    header_name, strerror(errno));

  pr_table_empty(tab);
  pr_table_free(tab);
}
END_TEST

START_TEST (http_urldecode_test) {
  const char *res, *item;
  size_t item_len, decoded_len;
  void *http;

  res = aws_http_urldecode(NULL, NULL, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_http_urldecode(p, NULL, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  res = aws_http_urldecode(p, http, NULL, 0, NULL);
  fail_unless(res == NULL, "Failed to handle null item");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  item = "foo%20bar";
  res = aws_http_urldecode(p, http, item, 0, NULL);
  fail_unless(res == NULL, "Failed to handle empty item");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  item_len = strlen(item);
  res = aws_http_urldecode(p, http, item, item_len, NULL);
  fail_unless(res == NULL, "Failed to handle null decoded len");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  decoded_len = 0;
  res = aws_http_urldecode(p, http, item, item_len, &decoded_len);
  fail_unless(res != NULL, "Failed to decode item '%s': %s", item,
    strerror(errno));
  fail_unless(decoded_len == 7,
    "Expected %lu, got %lu", 7, (unsigned long) decoded_len);
  fail_unless(strcmp(res, "foo bar") == 0, "Expected 'foo bar', got '%s'", res);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_urlencode_test) {
  const char *res, *item;
  size_t item_len;
  void *http;

  res = aws_http_urlencode(NULL, NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  res = aws_http_urlencode(p, NULL, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  res = aws_http_urlencode(p, http, NULL, 0);
  fail_unless(res == NULL, "Failed to handle null item");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  item = "foo bar";
  res = aws_http_urlencode(p, http, item, 0);
  fail_unless(res != NULL, "Failed to encode item '%s': %s", item,
    strerror(errno));
  fail_unless(strcmp(res, "foo%20bar") == 0,
    "Expected 'foo%%20bar', got '%s'", res);

  item = "foo bar";
  item_len = strlen(item);
  res = aws_http_urlencode(p, http, item, item_len);
  fail_unless(res != NULL, "Failed to encode item '%s': %s", item,
    strerror(errno));
  fail_unless(strcmp(res, "foo%20bar") == 0,
    "Expected 'foo%%20bar', got '%s'", res);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_date2unix_test) {
  time_t res, expected;
  const char *http_date;

  mark_point();
  res = aws_http_date2unix(NULL, NULL);
  fail_unless(res == 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_date2unix(p, NULL);
  fail_unless(res == 0, "Failed to handle null http_date");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_date = "foo";

  mark_point();
  res = aws_http_date2unix(p, http_date);
  fail_unless(res == 0, "Failed to handle invalid date '%s'", http_date);
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http_date = "Fri, 23 Oct 2015 22:18:22 GMT";
  expected = 1445638702;

  mark_point();
  res = aws_http_date2unix(p, http_date);
  fail_unless(res == expected, "Expected %lu, got %lu",
    (unsigned long) expected, (unsigned long) res);
}
END_TEST

START_TEST (http_unix2date_test) {
  time_t t;
  const char *res, *expected;

  mark_point();
  res = aws_http_unix2date(NULL, 0);
  fail_unless(res == 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  t = 0;
  expected = "Thu, 01 Jan 1970 00:00:00 UTC";

  mark_point();
  res = aws_http_unix2date(p, t);
  fail_unless(res != NULL, "Failed to handle epoch %lu: %s",
    (unsigned long) t, strerror(errno));

  if (strcmp(res, expected) != 0) {
    expected = "Thu, 01 Jan 1970 00:00:00 GMT";
  }

  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);

  t = 1445638702;
  expected = "Fri, 23 Oct 2015 22:18:22 GMT";

  mark_point();
  res = aws_http_unix2date(p, t);
  fail_unless(res != NULL, "Failed to handle epoch %lu: %s",
    (unsigned long) t, strerror(errno));

  if (strcmp(res, expected) != 0) {
    expected = "Fri, 23 Oct 2015 22:18:22 UTC";
  }

  fail_unless(strcmp(res, expected) == 0, "Expected '%s', got '%s'",
    expected, res);
}
END_TEST

static size_t resp_cb(char *item, size_t item_len, size_t item_count,
    void *user_data) {
  size_t data_len;

  data_len = item_len * item_count;
  return data_len;
}

START_TEST (http_get_test) {
  int res;
  void *http;
  const char *url, *content_type = NULL;
  long resp_code = 0;
  pr_table_t *resp_headers;

  mark_point();
  res = aws_http_get(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_get(p, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  mark_point();
  res = aws_http_get(p, http, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null URL");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  url = "http://www.google.com";

  mark_point();
  res = aws_http_get(p, http, url, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response callback");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code, NULL, NULL);
  fail_unless(res == 0, "Failed to handle GET request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_OK,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  /* Once more, with the Content-Type. */
  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code,
    &content_type, NULL);
  fail_unless(res == 0, "Failed to handle GET request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_OK,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);
  fail_unless(content_type != NULL, "Failed to get Content-Type of response");
  fail_unless(strstr(content_type, "text/html") != NULL,
    "Expected 'text/html' in Content-Type, got '%s'", content_type);

  /* Once more, with the response headers. */
  resp_headers = pr_table_alloc(p, 0);

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code,
    &content_type, resp_headers);
  fail_unless(res == 0, "Failed to handle GET request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_OK,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);
  fail_unless(content_type != NULL, "Failed to get Content-Type of response");
  fail_unless(strstr(content_type, "text/html") != NULL,
    "Expected 'text/html' in Content-Type, got '%s'", content_type);

  /* Unknown/bad URL */
  url = "http://www.google.com/foo/bar/baz";

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code, NULL, NULL);
  fail_unless(res == 0, "Failed to handle GET request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_NOT_FOUND,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_NOT_FOUND, resp_code);

  /* Unresolvable DNS names. */
  url = "http://my.hostname.at.domain.example.com";

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code, NULL, NULL);
  fail_unless(res < 0, "Handled unresolvable DNS name unexpectedly");
  fail_unless(errno == ESRCH, "Expected ESRCH (%d), got %s (%d)", ESRCH,
    strerror(errno), errno);

  /* Unconnectable IP addresses */
  url = "http://1.2.3.4";

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code, NULL, NULL);
  fail_unless(res < 0, "Handled unreachable IP address unexpectedly");
  fail_unless(errno == ETIMEDOUT, "Expected ETIMEDOUT (%d), got %s (%d)",
    ETIMEDOUT, strerror(errno), errno);

  /* Unsupported URL syntax */
  url = "foo://bar:baz/42";

  mark_point();
  res = aws_http_get(p, http, url, NULL, resp_cb, NULL, &resp_code, NULL, NULL);
  fail_unless(res < 0, "Handled unsupported URL syntax unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_head_test) {
  int res;
  void *http;
  const char *url, *content_type = NULL;
  long resp_code = 0;
  pr_table_t *resp_headers;

  mark_point();
  res = aws_http_head(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_head(p, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  mark_point();
  res = aws_http_head(p, http, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null URL");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  url = "http://www.google.com";

  mark_point();
  res = aws_http_head(p, http, url, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, NULL, NULL);
  fail_unless(res == 0, "Failed to handle HEAD request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_OK,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  /* Once more, with the Content-Type. */
  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, &content_type, NULL);
  fail_unless(res == 0, "Failed to handle HEAD request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_OK,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);
  fail_unless(content_type != NULL, "Failed to get Content-Type of response");
  fail_unless(strstr(content_type, "text/html") != NULL,
    "Expected 'text/html' in Content-Type, got '%s'", content_type);

  /* Once more, with the response headers. */
  resp_headers = pr_table_alloc(p, 0);

  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, &content_type,
    resp_headers);
  fail_unless(res == 0, "Failed to handle HEAD request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_OK,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);
  fail_unless(content_type != NULL, "Failed to get Content-Type of response");
  fail_unless(strstr(content_type, "text/html") != NULL,
    "Expected 'text/html' in Content-Type, got '%s'", content_type);

  /* Unknown/bad URL */
  url = "http://www.google.com/foo/bar/baz";

  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, NULL, NULL);
  fail_unless(res == 0, "Failed to handle HEAD request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code == AWS_HTTP_RESPONSE_CODE_NOT_FOUND,
    "Expected %ld, got %ld", AWS_HTTP_RESPONSE_CODE_NOT_FOUND, resp_code);

  /* Unresolvable DNS names. */
  url = "http://my.hostname.at.domain.example.com";

  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, NULL, NULL);
  fail_unless(res < 0, "Handled unresolvable DNS name unexpectedly");
  fail_unless(errno == ESRCH, "Expected ESRCH (%d), got %s (%d)", ESRCH,
    strerror(errno), errno);

  /* Unconnectable IP addresses */
  url = "http://1.2.3.4";

  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, NULL, NULL);
  fail_unless(res < 0, "Handled unreachable IP address unexpectedly");
  fail_unless(errno == ETIMEDOUT, "Expected ETIMEDOUT (%d), got %s (%d)",
    ETIMEDOUT, strerror(errno), errno);

  /* Unsupported URL syntax */
  url = "foo://bar:baz/42";

  mark_point();
  res = aws_http_head(p, http, url, NULL, &resp_code, NULL, NULL);
  fail_unless(res < 0, "Handled unsupported URL syntax unexpectedly");
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_post_test) {
  int res;
  void *http;
  char *req;
  const char *url;
  long resp_code = 0;
  pr_table_t *req_headers, *resp_headers;

  mark_point();
  res = aws_http_post(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_post(p, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  mark_point();
  res = aws_http_post(p, http, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null URL");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  url = "http://www.google.com";

  mark_point();
  res = aws_http_post(p, http, url, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response callback");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_post(p, http, url, NULL, resp_cb, NULL, NULL, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null request body");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  req = "{ \"test\": true }\n";

  mark_point();
  res = aws_http_post(p, http, url, NULL, resp_cb, NULL, req, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_post(p, http, url, NULL, resp_cb, NULL, req, &resp_code,
    NULL, NULL);
  fail_unless(res == 0, "Failed to handle POST request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  req_headers = aws_http_default_headers(p, NULL);
  pr_table_add_dup(req_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_TYPE),
    "application/json", 0);

  mark_point();
  res = aws_http_post(p, http, url, req_headers, resp_cb, NULL, req, &resp_code,
    NULL, NULL);
  fail_unless(res == 0, "Failed to handle POST request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  resp_headers = pr_table_alloc(p, 0);

  mark_point();
  res = aws_http_post(p, http, url, req_headers, resp_cb, NULL, req, &resp_code,
    NULL, resp_headers);
  fail_unless(res == 0, "Failed to handle POST request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_put_test) {
  int res;
  void *http;
  char *req;
  off_t reqlen;
  const char *url;
  long resp_code = 0;
  pr_table_t *req_headers, *resp_headers;

  mark_point();
  res = aws_http_put(NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_put(p, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  mark_point();
  res = aws_http_put(p, http, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null URL");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  url = "http://www.google.com";

  mark_point();
  res = aws_http_put(p, http, url, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response callback");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_put(p, http, url, NULL, resp_cb, NULL, NULL, 0, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null request body");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  req = "{ \"test\": true }\n";

  mark_point();
  res = aws_http_put(p, http, url, NULL, resp_cb, NULL, req, 0, NULL, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null response code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_put(p, http, url, NULL, resp_cb, NULL, req, 0, &resp_code,
    NULL, NULL);
  fail_unless(res == 0, "Failed to handle PUT request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  req_headers = aws_http_default_headers(p, NULL);
  pr_table_add_dup(req_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_TYPE),
    "application/json", 0);

  mark_point();
  res = aws_http_put(p, http, url, req_headers, resp_cb, NULL, req, 0,
    &resp_code, NULL, NULL);
  fail_unless(res == 0, "Failed to handle PUT request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  mark_point();
  reqlen = strlen(req);
  res = aws_http_put(p, http, url, req_headers, resp_cb, NULL, req, reqlen,
    &resp_code, NULL, NULL);
  fail_unless(res == 0, "Failed to handle PUT request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  resp_headers = pr_table_alloc(p, 0);

  mark_point();
  res = aws_http_put(p, http, url, req_headers, resp_cb, NULL, req, reqlen,
    &resp_code, NULL, resp_headers);
  fail_unless(res == 0, "Failed to handle PUT request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  aws_http_destroy(p, http);
}
END_TEST

START_TEST (http_delete_test) {
  int res;
  void *http;
  const char *url;
  long resp_code = 0;
  pr_table_t *req_headers, *resp_headers;

  mark_point();
  res = aws_http_delete(NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_delete(p, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null handle");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  http = aws_http_alloc(p, 3, 5, NULL);
  fail_unless(http != NULL, "Failed to allocate handle: %s", strerror(errno));

  mark_point();
  res = aws_http_delete(p, http, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null URL");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  url = "http://www.google.com";

  mark_point();
  res = aws_http_delete(p, http, url, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null response code");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_http_delete(p, http, url, NULL, &resp_code, NULL);
  fail_unless(res == 0, "Failed to handle DELETE request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  req_headers = aws_http_default_headers(p, NULL);
  pr_table_add_dup(req_headers, pstrdup(p, AWS_HTTP_HEADER_CONTENT_TYPE),
    "application/json", 0);

  mark_point();
  res = aws_http_delete(p, http, url, req_headers, &resp_code, NULL);
  fail_unless(res == 0, "Failed to handle DELETE request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  resp_headers = pr_table_alloc(p, 0);

  mark_point();
  res = aws_http_delete(p, http, url, req_headers, &resp_code, resp_headers);
  fail_unless(res == 0, "Failed to handle DELETE request to '%s': %s", url,
    strerror(errno));
  fail_unless(resp_code != AWS_HTTP_RESPONSE_CODE_OK,
    "Expected !%ld, got %ld", AWS_HTTP_RESPONSE_CODE_OK, resp_code);

  aws_http_destroy(p, http);
}
END_TEST

Suite *tests_get_http_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("http");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, http_alloc_test);
  tcase_add_test(testcase, http_destroy_test);
  tcase_add_test(testcase, http_default_headers_test);
  tcase_add_test(testcase, http_urldecode_test);
  tcase_add_test(testcase, http_urlencode_test);
  tcase_add_test(testcase, http_date2unix_test);
  tcase_add_test(testcase, http_unix2date_test);
  tcase_add_test(testcase, http_get_test);
  tcase_add_test(testcase, http_head_test);
  tcase_add_test(testcase, http_post_test);
  tcase_add_test(testcase, http_put_test);
  tcase_add_test(testcase, http_delete_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
