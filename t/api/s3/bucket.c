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

/* S3 Bucket API tests. */

#include "../tests.h"

static pool *p = NULL;

static unsigned long max_connect_secs = 5;
static unsigned long max_request_secs = 10;

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
    pr_trace_set_levels("aws.s3.bucket", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
    pr_trace_set_levels("aws.s3.bucket", 0, 0);
  }

  aws_http_free();
  aws_xml_free();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

static struct s3_conn *get_s3(pool *p) {
  int res;
  const char *path, *profile, *cacerts, *region, *domain;
  char *access_key_id, *secret_access_key, *session_token;
  struct s3_conn *s3;

  path = "/Users/tj/.aws/credentials";
  profile = "mod_aws";
  access_key_id = secret_access_key = session_token = NULL;

  mark_point();
  res = aws_creds_from_file(p, path, profile, &access_key_id,
    &secret_access_key, &session_token);
  if (res < 0) {
    return NULL;
  }

  fail_unless(res == 0, "Failed to get '%s' creds from '%s': %s", profile,
    path, strerror(errno));

  /* From the instance metadata. */
  cacerts = "/Users/tj/git/proftpd-mod_aws/aws-cacerts.pem";
  region = "us-west-2";
  domain = "amazonaws.com";

  mark_point();
  s3 = aws_s3_conn_alloc(p, max_connect_secs, max_request_secs, cacerts,
    region, domain, access_key_id, secret_access_key, session_token);
  return s3;
}

START_TEST (s3_bucket_get_names_test) {
  const char *owner_id, *owner_name;
  struct s3_conn *s3;
  array_header *bucket_names;

  bucket_names = aws_s3_bucket_get_names(NULL, NULL, NULL, NULL);
  fail_unless(bucket_names == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bucket_names = aws_s3_bucket_get_names(p, NULL, NULL, NULL);
  fail_unless(bucket_names == NULL, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  if (getenv("TRAVIS_CI") != NULL) {
    return;
  }

  s3 = get_s3(p);
  fail_unless(s3 != NULL, "Failed to get S3 connection: %s", strerror(errno));

  owner_id = owner_name = NULL;

  mark_point();
  bucket_names = aws_s3_bucket_get_names(p, s3, &owner_id, &owner_name);
  fail_unless(bucket_names != NULL, "Failed to get S3 bucket names: %s",
    strerror(errno));

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

START_TEST (s3_bucket_get_keys_test) {
  int res;
  pr_table_t *keys;
  struct s3_conn *s3;
  const char *bucket, *prefix;

  mark_point();
  res = aws_s3_bucket_get_keys(NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_bucket_get_keys(p, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  res = aws_s3_bucket_get_keys(p, s3, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null bucket_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bucket = "foo";

  mark_point();
  res = aws_s3_bucket_get_keys(p, s3, bucket, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null keys");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  if (getenv("TRAVIS_CI") != NULL) {
    return;
  }

  s3 = get_s3(p);
  fail_unless(s3 != NULL, "Failed to get S3 connection: %s", strerror(errno));

  bucket = getenv("AWS_S3_BUCKET");
  fail_unless(bucket != NULL,
    "Failed to provide AWS_S3_BUCKET environment variable");

  keys = pr_table_alloc(p, 0);

  mark_point();
  res = aws_s3_bucket_get_keys(p, s3, bucket, NULL, keys, NULL);
  fail_unless(res == 0, "Failed to get all keys for bucket '%s': %s",
    bucket, strerror(errno));

  /* Using a prefix of ".../" leads to an object key of ".../" being among
   * the returned keys.  Just what IS that object?  It has a size = 0.
   */
  prefix = getenv("AWS_S3_BUCKET_PREFIX");
  fail_unless(prefix != NULL,
    "Failed to provide AWS_S3_BUCKET_PREFIX environment variable");

  pr_table_empty(keys);

  mark_point();
  res = aws_s3_bucket_get_keys(p, s3, bucket, prefix, keys, NULL);
  fail_unless(res == 0, "Failed to get '%s' keys for bucket '%s': %s",
    prefix, bucket, strerror(errno));

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

START_TEST (s3_bucket_access_test) {
  int res;
  struct s3_conn *s3;
  const char *bucket;

  mark_point();
  res = aws_s3_bucket_access(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_bucket_access(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  res = aws_s3_bucket_access(p, s3, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  if (getenv("TRAVIS_CI") != NULL) {
    return;
  }

  s3 = get_s3(p);
  fail_unless(s3 != NULL, "Failed to get S3 connection: %s", strerror(errno));

  bucket = getenv("AWS_S3_BUCKET");
  fail_unless(bucket != NULL,
    "Failed to provide AWS_S3_BUCKET environment variable");

  mark_point();
  res = aws_s3_bucket_access(p, s3, bucket);
  fail_unless(res == 0, "Failed to check bucket %s: %s", bucket,
    strerror(errno));

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

Suite *tests_get_s3_bucket_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3.bucket");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, s3_bucket_get_names_test);
  tcase_add_test(testcase, s3_bucket_get_keys_test);
  tcase_add_test(testcase, s3_bucket_access_test);

  /* HTTP calls may need longer timeouts. */
  tcase_set_timeout(testcase, max_connect_secs + max_request_secs);

  suite_add_tcase(suite, testcase);
  return suite;
}
