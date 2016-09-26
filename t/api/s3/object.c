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

/* S3 Object API tests. */

#include "../tests.h"

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
    pr_trace_set_levels("aws.s3.conn", 1, 20);
    pr_trace_set_levels("aws.s3.object", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.http", 0, 0);
    pr_trace_set_levels("aws.s3.conn", 0, 0);
    pr_trace_set_levels("aws.s3.object", 0, 0);
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
  profile = "default";
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
  s3 = aws_s3_conn_alloc(p, 5, 5, cacerts, region, domain, access_key_id,
    secret_access_key, session_token);
  return s3;
}

static int abort_data(pool *p, void *data, off_t data_offset,
    off_t data_len) {
  errno = ENOSPC;
  return -1;
}

static int consume_data(pool *p, void *data, off_t data_offset,
    off_t data_len) {
  return 0;
}

START_TEST (s3_object_get_test) {
  int res;
  struct s3_conn *s3;
  const char *bucket, *key;
  pr_table_t *metadata = NULL;

  res = aws_s3_object_get(NULL, NULL, NULL, NULL, 0, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_object_get(p, NULL, NULL, NULL, 0, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  res = aws_s3_object_get(p, s3, NULL, NULL, 0, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null bucket_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bucket = "xfoo";

  mark_point();
  res = aws_s3_object_get(p, s3, bucket, NULL, 0, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null object_key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  key = "xbar";

  mark_point();
  res = aws_s3_object_get(p, s3, bucket, key, 0, 0, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null consumer");
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
  key = getenv("AWS_S3_OBJECT_KEY");
  fail_unless(key != NULL,
    "Failed to provide AWS_S3_OBJECT_KEY environment variable");

  metadata = pr_table_alloc(p, 0);

  mark_point();

  res = aws_s3_object_get(p, s3, bucket, key, 0, 0, metadata, consume_data);
  fail_unless(res == 0, "Failed to get object %s from bucket %s: %s", key,
    bucket, strerror(errno));

  /* Range requests: just offset */
  res = aws_s3_object_get(p, s3, bucket, key, 1000, 0, metadata,
    consume_data);
  fail_unless(res == 0, "Failed to get object %s from bucket %s: %s", key,
    bucket, strerror(errno));

  /* Range requests: just len */
  res = aws_s3_object_get(p, s3, bucket, key, 0, 1000, metadata,
    consume_data);
  fail_unless(res == 0, "Failed to get object %s from bucket %s: %s", key,
    bucket, strerror(errno));

  /* Range requests: offset+len */
  res = aws_s3_object_get(p, s3, bucket, key, 1000, 1000, metadata,
    consume_data);
  fail_unless(res == 0, "Failed to get object %s from bucket %s: %s", key,
    bucket, strerror(errno));

  /* Aborted/failed download */
  res = aws_s3_object_get(p, s3, bucket, key, 1000, 1000, metadata,
    abort_data);
  fail_unless(res < 0,
    "Failed to handle aborted download of object %s from bucket %s", key,
    bucket);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  /* Do this again, to make sure we re-open the curl handle appropriately. */
  res = aws_s3_object_get(p, s3, bucket, key, 1000, 1000, metadata,
    abort_data);
  fail_unless(res < 0,
    "Failed to handle aborted download of object %s from bucket %s", key,
    bucket);
  fail_unless(errno == EPERM, "Expected EPERM (%d), got %s (%d)", EPERM,
    strerror(errno), errno);

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

START_TEST (s3_object_stat_test) {
  int res, count;
  struct s3_conn *s3;
  const char *bucket, *key;
  pr_table_t *metadata = NULL;

  res = aws_s3_object_stat(NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_object_stat(p, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  res = aws_s3_object_stat(p, s3, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null bucket_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bucket = "xfoo";

  mark_point();
  res = aws_s3_object_stat(p, s3, bucket, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null object_key");
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
  key = getenv("AWS_S3_OBJECT_KEY");
  fail_unless(key != NULL,
    "Failed to provide AWS_S3_OBJECT_KEY environment variable");

  metadata = pr_table_alloc(p, 0);

  /* No such bucket. */

  mark_point();
  res = aws_s3_object_stat(p, s3, "NO_SUCH_BUCKET", key, metadata);
  fail_unless(res < 0, "Failed to handle invalid bucket NO_SUCH_BUCKET");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* No such key. */

  mark_point();
  res = aws_s3_object_stat(p, s3, bucket, "NO_SUCH_KEY", metadata);
  fail_unless(res < 0, "Failed to handle invalid key NO_SUCH_KEY");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* Check for existence; don't care about metadata. */
  pr_table_empty(metadata);

  mark_point();
  res = aws_s3_object_stat(p, s3, bucket, key, NULL);
  fail_unless(res == 0, "Failed to stat object %s from bucket %s: %s", key,
    bucket, strerror(errno));

  /* Get the object metadata, too. */
  pr_table_empty(metadata);

  mark_point();
  res = aws_s3_object_stat(p, s3, bucket, key, metadata);
  fail_unless(res == 0, "Failed to stat object %s from bucket %s: %s", key,
    bucket, strerror(errno));
  count = pr_table_count(metadata);
  fail_unless(count > 0, "Expected >0, got %d", count);

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

START_TEST (s3_object_delete_test) {
  int res;
  struct s3_conn *s3;
  const char *bucket, *key;

  res = aws_s3_object_delete(NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_object_delete(p, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  res = aws_s3_object_delete(p, s3, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null bucket_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bucket = "xfoo";

  mark_point();
  res = aws_s3_object_delete(p, s3, bucket, NULL);
  fail_unless(res < 0, "Failed to handle null object_key");
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

/* XXX Need to be careful with this!  Should use a different env var for the object being deleted */
  key = getenv("AWS_S3_OBJECT_KEY");
  fail_unless(key != NULL,
    "Failed to provide AWS_S3_OBJECT_KEY environment variable");

  /* No such bucket. */

  mark_point();
  res = aws_s3_object_delete(p, s3, "NO_SUCH_BUCKET", key);
  fail_unless(res < 0, "Failed to handle invalid bucket NO_SUCH_BUCKET");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* No such key. */

  mark_point();
  res = aws_s3_object_delete(p, s3, bucket, "NO_SUCH_KEY");
  fail_unless(res < 0, "Failed to handle invalid key NO_SUCH_KEY");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

#if 0
  mark_point();
  res = aws_s3_object_delete(p, s3, bucket, key);
  fail_unless(res == 0, "Failed to delete object %s from bucket %s: %s", key,
    bucket, strerror(errno));
#endif

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

START_TEST (s3_object_copy_test) {
  int res;
  struct s3_conn *s3;
  const char *src_bucket, *src_key, *dst_bucket, *dst_key;
  pr_table_t *dst_metadata;

  res = aws_s3_object_copy(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_object_copy(p, NULL, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null s3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  res = aws_s3_object_copy(p, s3, NULL, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null src_bucket_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  src_bucket = "xfoo";

  mark_point();
  res = aws_s3_object_copy(p, s3, src_bucket, NULL, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null src_object_key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  src_key = "xbar";

  mark_point();
  res = aws_s3_object_copy(p, s3, src_bucket, src_key, NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null dst_bucket_name");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  dst_bucket = "yfoo";

  mark_point();
  res = aws_s3_object_copy(p, s3, src_bucket, src_key, dst_bucket, NULL,
    NULL);
  fail_unless(res < 0, "Failed to handle null dst_object_key");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  if (getenv("TRAVIS_CI") != NULL) {
    return;
  }

  s3 = get_s3(p);
  fail_unless(s3 != NULL, "Failed to get S3 connection: %s", strerror(errno));

  /* No such source bucket. */

  dst_key = "ybar";

  mark_point();
  res = aws_s3_object_copy(p, s3, "NO_SUCH_SRC_BUCKET", src_key, dst_bucket,
    dst_key, NULL);
  fail_unless(res < 0, "Failed to handle invalid bucket NO_SUCH_SRC_BUCKET");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  /* No such source key. */

  mark_point();
  res = aws_s3_object_copy(p, s3, src_bucket, "NO_SUCH_SRC_KEY", dst_bucket,
    dst_key, NULL);
  fail_unless(res < 0, "Failed to handle invalid key NO_SUCH_SRC_KEY");
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

#if 0
  mark_point();
  res = aws_s3_object_copy(p, s3, bucket, key, ...);
  fail_unless(res == 0, "Failed to copy object %s from bucket %s: %s", key,
    bucket, strerror(errno));
#endif

  (void) aws_s3_conn_destroy(p, s3);
}
END_TEST

Suite *tests_get_s3_object_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3.object");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, s3_object_get_test);
  tcase_add_test(testcase, s3_object_stat_test);
  tcase_add_test(testcase, s3_object_delete_test);
  tcase_add_test(testcase, s3_object_copy_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
