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

/* Creds API tests. */

#include "tests.h"

static pool *p = NULL;

static const char *creds_test_path = "/tmp/awstest-creds.properties";

static void set_up(void) {
  (void) unlink(creds_test_path);

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.creds", 1, 20);
    pr_trace_set_levels("fsio", 1, 20);
  }
}

static void tear_down(void) {
  (void) unlink(creds_test_path);

  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.creds", 0, 0);
    pr_trace_set_levels("fsio", 0, 0);
  }

  if (p) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (creds_from_env_test) {
  int res;
  char *access_key_id, *secret_access_key, *expected;

  mark_point();
  res = aws_creds_from_env(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_creds_from_env(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null access_key_id");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_creds_from_env(p, &access_key_id, NULL);
  fail_unless(res < 0, "Failed to handle null secret_access_key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_creds_from_env(p, &access_key_id, &secret_access_key);
  fail_unless(res < 0, "Failed to handle missing credentials");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_env_set(p, "AWS_ACCESS_KEY_ID", "FOO");
  fail_unless(res == 0, "Failed to set AWS_ACCESS_KEY_ID env var: %s",
    strerror(errno));

  mark_point();
  res = aws_creds_from_env(p, &access_key_id, &secret_access_key);
  fail_unless(res < 0, "Failed to handle missing credentials");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = pr_env_set(p, "AWS_SECRET_ACCESS_KEY", "BAR");
  fail_unless(res == 0, "Failed to set AWS_SECRET_ACCESS_KEY env var: %s",
    strerror(errno));

  access_key_id = secret_access_key = NULL;

  mark_point();
  res = aws_creds_from_env(p, &access_key_id, &secret_access_key);
  fail_unless(res == 0, "Failed to get credentials from env vars: %s",
    strerror(errno));

  expected = "FOO";
  fail_unless(access_key_id != NULL, "Expected access_key_id, got null");
  fail_unless(strcmp(access_key_id, expected) == 0, "Expected '%s', got '%s'",
    expected, access_key_id);

  expected = "BAR";
  fail_unless(secret_access_key != NULL,
    "Expected secret_access_key, got null");
  fail_unless(strcmp(secret_access_key, expected) == 0,
   "Expected '%s', got '%s'", expected, secret_access_key);

  (void) pr_env_unset(p, "AWS_ACCESS_KEY_ID");
  (void) pr_env_unset(p, "AWS_SECRET_ACCESS_KEY");
}
END_TEST

static int write_lines(const char *path, unsigned int count, ...) {
  va_list ap;
  FILE *fh;

  fh = fopen(path, "w+");
  if (fh == NULL) {
    return -1;
  }

  va_start(ap, count);

  while (count-- > 0) {
    size_t len;
    char *line;

    line = va_arg(ap, char *);
    len = strlen(line);
    fwrite(line, len, 1, fh);
  }

  return fclose(fh);
}

START_TEST (creds_from_file_test) {
  int res;
  const char *path;
  char *access_key_id, *secret_access_key, *expected;

  (void) unlink(creds_test_path);

  mark_point();
  res = aws_creds_from_file(NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_creds_from_file(p, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_creds_from_file(p, path, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null access_key_id");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = creds_test_path;

  mark_point();
  res = aws_creds_from_file(p, path, NULL, &access_key_id, NULL);
  fail_unless(res < 0, "Failed to handle null secret_access_key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_creds_from_file(p, path, NULL, &access_key_id, &secret_access_key);
  fail_unless(res < 0, "Failed to handle nonexistent file");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  res = write_lines(path, 2,
    "foo\n",
    "bar\n"
  );
  fail_unless(res == 0, "Failed to write creds file '%s': %s", path,
    strerror(errno));

  mark_point();
  res = aws_creds_from_file(p, path, NULL, &access_key_id, &secret_access_key);
  fail_unless(res < 0, "Failed to handle badly formatted file");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(path);
  res = write_lines(path, 2,
    "secretKey = FOO\n",
    "bar\r\n"
  );
  fail_unless(res == 0, "Failed to write creds file '%s': %s", path,
    strerror(errno));

  mark_point();
  res = aws_creds_from_file(p, path, NULL, &access_key_id, &secret_access_key);
  fail_unless(res < 0, "Failed to handle file missing ID");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(path);
  res = write_lines(path, 2,
    "accessKey = FOO\r\n",
    "bar\n"
  );
  fail_unless(res == 0, "Failed to write creds file '%s': %s", path,
    strerror(errno));

  mark_point();
  res = aws_creds_from_file(p, path, NULL, &access_key_id, &secret_access_key);
  fail_unless(res < 0, "Failed to handle file missing secret");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  (void) unlink(path);
  res = write_lines(path, 5,
    "foo=bar\n",
    "accessKey = FOO\n",
    "# Comment here\n",
    "         \n",
    "secretKey=BAR\n"
  );
  fail_unless(res == 0, "Failed to write creds file '%s': %s", path,
    strerror(errno));

  mark_point();
  res = aws_creds_from_file(p, path, NULL, &access_key_id, &secret_access_key);
  fail_unless(res == 0, "Failed to handle properties file '%s': %s", path,
    strerror(errno));

  expected = "FOO";
  fail_unless(access_key_id != NULL, "Expected access_key_id, got null");
  fail_unless(strcmp(access_key_id, expected) == 0, "Expected '%s', got '%s'",
    expected, access_key_id);

  expected = "BAR";
  fail_unless(secret_access_key != NULL,
    "Expected secret_access_key, got null");
  fail_unless(strcmp(secret_access_key, expected) == 0,
   "Expected '%s', got '%s'", expected, secret_access_key);

  (void) unlink(creds_test_path);
}
END_TEST

START_TEST (creds_from_file_using_profile_test) {
  /* Note: Show use case of reading a specific profile, finding none,
   * and falling back to reading profile="default" if needed.
   */
}
END_TEST

START_TEST (creds_from_sql_test) {
}
END_TEST

Suite *tests_get_creds_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("creds");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, creds_from_env_test);
  tcase_add_test(testcase, creds_from_file_test);
  tcase_add_test(testcase, creds_from_file_using_profile_test);
  tcase_add_test(testcase, creds_from_sql_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
