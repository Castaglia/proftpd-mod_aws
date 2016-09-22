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

/* S3 API tests. */

#include "tests.h"

static pool *p = NULL;

static void set_up(void) {
  unsigned long feature_flags = 0UL;

  if (p == NULL) {
    p = permanent_pool = make_sub_pool(NULL);
  }

  init_fs();
  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  aws_xml_init(p);
  aws_http_init(p, &feature_flags, NULL);

  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 1, 20);
    pr_trace_set_levels("aws.s3", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
    pr_trace_set_levels("aws.s3", 0, 0);
  }

  aws_http_free();
  aws_xml_free();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

START_TEST (s3_conn_destroy_test) {
  int res;

  res = aws_s3_conn_destroy(NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (s3_conn_alloc_test) {
  struct s3_conn *s3;

  s3 = aws_s3_conn_alloc(NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(s3 == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);
}
END_TEST

START_TEST (s3_get_buckets_test) {
  int res;
  const char *cacerts, *region, *domain;
  const char *path, *profile, *owner_id, *owner_name;
  char *access_key_id, *secret_access_key, *session_token;
  struct s3_conn *s3;
  array_header *buckets;

  if (getenv("TRAVIS_CI") != NULL) {
    return;
  }

  path = "/Users/tj/.aws/credentials";
  profile = "default";
  access_key_id = secret_access_key = session_token = NULL;

  mark_point();
  res = aws_creds_from_file(p, path, profile, &access_key_id,
    &secret_access_key, &session_token);
  fail_unless(res == 0, "Failed to get '%s' creds from '%s': %s", profile,
    path, strerror(errno));

  /* From the instance metadata. */
  cacerts = "/Users/tj/git/proftpd-mod_aws/aws-cacerts.pem";
  region = "us-west-2";
  domain = "amazonaws.com";

  mark_point();
  s3 = aws_s3_conn_alloc(p, 5, 5, cacerts, region, domain, access_key_id,
    secret_access_key, session_token);

  owner_id = owner_name = NULL;

  mark_point();
  buckets = aws_s3_get_buckets(p, s3, &owner_id, &owner_name);
  fail_unless(buckets != NULL, "Failed to get S3 buckets: %s", strerror(errno));

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

Suite *tests_get_s3_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

#if 0
  tcase_add_test(testcase, s3_conn_destroy_test);
  tcase_add_test(testcase, s3_conn_alloc_test);
#endif
  tcase_add_test(testcase, s3_get_buckets_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
