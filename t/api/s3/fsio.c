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

/* S3 FSIO API tests. */

#include "../tests.h"

static pool *p = NULL;

static unsigned long max_connect_secs = 5;
static unsigned long max_request_secs = 10;

static const char *fsio_default_mount_point = "/tmp/aws.s3.testsuite";
static const char *fsio_mount_point = NULL;

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
    pr_trace_set_levels("aws.s3.fsio", 1, 20);
    pr_trace_set_levels("fsio", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.s3.fsio", 0, 0);
    pr_trace_set_levels("fsio", 0, 0);
  }

  aws_http_free();
  aws_xml_free();

  pr_fs_statcache_set_policy(PR_TUNABLE_FS_STATCACHE_SIZE,
    PR_TUNABLE_FS_STATCACHE_MAX_AGE, 0);

  (void) pr_unregister_fs(fsio_mount_point);

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
  s3 = aws_s3_conn_alloc(p, max_connect_secs, max_request_secs, cacerts,
    region, domain, access_key_id, secret_access_key, session_token);
  return s3;
}

START_TEST (s3_fsio_get_fs_test) {
  pr_fs_t *fs;
  const char *bucket, *prefix, *path;
  struct s3_conn *s3;

  mark_point();
  fs = aws_s3_fsio_get_fs(NULL, NULL, NULL, NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  fs = aws_s3_fsio_get_fs(p, NULL, NULL, NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null path");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  path = fsio_default_mount_point;

  mark_point();
  fs = aws_s3_fsio_get_fs(p, path, NULL, NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null S3");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  s3 = (struct s3_conn *) 1;

  mark_point();
  fs = aws_s3_fsio_get_fs(p, path, s3, NULL, NULL);
  fail_unless(fs == NULL, "Failed to handle null bucket");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  bucket = "foo";

  mark_point();
  fs = aws_s3_fsio_get_fs(p, path, s3, bucket, NULL);
  fail_unless(fs == NULL, "Failed to handle null prefix");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  prefix = "bar";

  mark_point();
  fs = aws_s3_fsio_get_fs(p, path, s3, bucket, prefix);
  fail_unless(fs != NULL, "Failed to get S3 FS: %s", strerror(errno));

  (void) pr_unregister_fs(fsio_mount_point);
}
END_TEST

static void check_stat_table(pr_table_t *tab, off_t content_len, time_t atime,
    gid_t gid, const char *group, mode_t mode, time_t mtime, const char *owner,
    mode_t perms, uid_t uid) {
  void *k, *v;

  k = AWS_S3_FSIO_METADATA_KEY_SIZE;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((off_t *) v) == content_len,
    "Expected size %" PR_LU ", got %" PR_LU, content_len, *((off_t *) v));

  k = AWS_S3_FSIO_METADATA_KEY_ATIME;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((time_t *) v) == atime,
    "Expected atime %lu, got %lu", (unsigned long) atime,
    (unsigned long) *((time_t *) v));

  k = AWS_S3_FSIO_METADATA_KEY_GID;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((gid_t *) v) == gid,
    "Expected GID %lu, got %lu", (unsigned long) gid,
    (unsigned long) *((gid_t *) v));

  k = AWS_S3_FSIO_METADATA_KEY_GROUP;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(strcmp((const char *) v, group) == 0,
    "Expected group '%s', got '%s'", group, (const char *) v);

  k = AWS_S3_FSIO_METADATA_KEY_MODE;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((mode_t *) v) == mode,
    "Expected mode %04o, got %04o", mode, *((mode_t *) v));

  k = AWS_S3_FSIO_METADATA_KEY_MTIME;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((time_t *) v) == mtime,
    "Expected mtime %lu, got %lu", (unsigned long) mtime,
    (unsigned long) *((time_t *) v));

  k = AWS_S3_FSIO_METADATA_KEY_OWNER;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(strcmp((const char *) v, owner) == 0,
    "Expected owner '%s', got '%s'", owner, (const char *) v);

  k = AWS_S3_FSIO_METADATA_KEY_PERMS;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((mode_t *) v) == perms,
    "Expected perms %04o, got %04o", perms, *((mode_t *) v));

  k = AWS_S3_FSIO_METADATA_KEY_UID;
  v = pr_table_get(tab, k, NULL);
  fail_unless(v != NULL, "Failed to find key %s in stat table",
    (const char *) k);
  fail_unless(*((uid_t *) v) == uid,
    "Expected UID %lu, got %lu", (unsigned long) uid,
    (unsigned long) *((uid_t *) v));
}

START_TEST (s3_fsio_stat2table_test) {
  int res;
  pr_table_t *object_metadata;
  struct stat st;
  void *v;

  mark_point();
  res = aws_s3_fsio_stat2table(NULL, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null pool");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_fsio_stat2table(p, NULL, NULL);
  fail_unless(res < 0, "Failed to handle null stat");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_s3_fsio_stat2table(p, &st, NULL);
  fail_unless(res < 0, "Failed to handle null table");
  fail_unless(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  object_metadata = pr_table_alloc(p, 0);

  memset(&st, 0, sizeof(st));

  mark_point();
  res = aws_s3_fsio_stat2table(p, &st, object_metadata);
  fail_unless(res == 0, "Failed to convert stat to table: %s", strerror(errno));
  check_stat_table(object_metadata, 0, 0, 0, "wheel", "0000", 0, "root",
    "0000", 0);

  pr_table_clear(object_metadata);
}
END_TEST

START_TEST (s3_fsio_table2stat_test) {
}
END_TEST

static void register_s3fs(pool *p, struct s3_conn *s3) {
  int res;
  pr_fs_t *fs;
  const char *bucket, *prefix;
  struct stat st;

  bucket = getenv("AWS_S3_BUCKET");
  fail_unless(bucket != NULL,
    "Failed to provide AWS_S3_BUCKET environment variable");

  prefix = getenv("AWS_S3_BUCKET_PREFIX");
  fail_unless(bucket != NULL,
    "Failed to provide AWS_S3_BUCKET_PREFIX environment variable");

  /* On Mac OSX, because /tmp is often a symlink. */
  res = lstat("/tmp", &st);
  if (res == 0) {
    if (S_ISLNK(st.st_mode)) {
      char dst[4096];

      memset(dst, '\0', sizeof(dst));
      if (readlink("/tmp", dst, sizeof(dst)-1) > 0) {
        fsio_mount_point = pdircat(p, "/", dst, "aws.s3.testsuite", NULL);
      }

    } else {
      fsio_mount_point = fsio_default_mount_point;
    }

  } else {
    fail("Unable to lstat '/tmp': %s", strerror(errno));
  }

  pr_trace_msg("fsio", 1, "mounting S3 FS at '%s'", fsio_mount_point);

  fs = aws_s3_fsio_get_fs(p, fsio_mount_point, s3, bucket, prefix);
  fail_unless(fs != NULL, "Failed to register S3 FS: %s", strerror(errno));

  res = mkdir(fsio_mount_point, 0755);
  if (res < 0 &&
      errno != EEXIST) {
    fail_unless(res < 0, "Failed to create '%s' directory: %s",
      fsio_mount_point, strerror(errno));
  }

  mark_point();
  pr_resolve_fs_map();
}

static void unregister_s3fs(pool *p, struct s3_conn *s3) {
  (void) pr_unregister_fs(fsio_mount_point);
  (void) aws_s3_conn_destroy(p, s3);
  (void) tests_rmpath(p, fsio_mount_point);
  fsio_mount_point = NULL;
}

START_TEST (s3_fsio_stat_test) {
  int res;
  const char *path;
  struct stat st;
  struct s3_conn *s3;

  s3 = get_s3(p);
  fail_unless(s3 != NULL, "Failed to get S3 connection: %s", strerror(errno));

  register_s3fs(p, s3);

  path = pdircat(p, fsio_mount_point, "test.dat", NULL);

  mark_point();
  res = pr_fsio_stat(path, &st);
  fail_unless(res < 0, "Checked '%s' unexpectedly", path);
  fail_unless(errno == ENOENT, "Expected ENOENT (%d), got %s (%d)", ENOENT,
    strerror(errno), errno);

  unregister_s3fs(p, s3);
}
END_TEST

Suite *tests_get_s3_fsio_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("s3.fsio");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  if (getenv("TRAVIS_CI") != NULL) {
    suite_add_tcase(suite, testcase);
    return suite;
  }

  tcase_add_test(testcase, s3_fsio_get_fs_test);
  tcase_add_test(testcase, s3_fsio_stat2table_test);
  tcase_add_test(testcase, s3_fsio_table2stat_test);

  tcase_add_test(testcase, s3_fsio_stat_test);
#if 0
  tcase_add_test(testcase, s3_fsio_fstat_test);
  tcase_add_test(testcase, s3_fsio_lstat_test);
  tcase_add_test(testcase, s3_fsio_rename_test);
  tcase_add_test(testcase, s3_fsio_unlink_test);
  tcase_add_test(testcase, s3_fsio_open_test);
  tcase_add_test(testcase, s3_fsio_close_test);
  tcase_add_test(testcase, s3_fsio_read_test);
  tcase_add_test(testcase, s3_fsio_write_test);
  tcase_add_test(testcase, s3_fsio_lseek_test);
  tcase_add_test(testcase, s3_fsio_link_test);
  tcase_add_test(testcase, s3_fsio_readlink_test);
  tcase_add_test(testcase, s3_fsio_symlink_test);
  tcase_add_test(testcase, s3_fsio_ftruncate_test);
  tcase_add_test(testcase, s3_fsio_truncate_test);
  tcase_add_test(testcase, s3_fsio_chmod_test);
  tcase_add_test(testcase, s3_fsio_fchmod_test);
  tcase_add_test(testcase, s3_fsio_chown_test);
  tcase_add_test(testcase, s3_fsio_fchown_test);
  tcase_add_test(testcase, s3_fsio_lchown_test);
  tcase_add_test(testcase, s3_fsio_access_test);
  tcase_add_test(testcase, s3_fsio_faccess_test);
  tcase_add_test(testcase, s3_fsio_utimes_test);
  tcase_add_test(testcase, s3_fsio_futimes_test);
  tcase_add_test(testcase, s3_fsio_fsync_test);

  tcase_add_test(testcase, s3_fsio_getxattr_test);
  tcase_add_test(testcase, s3_fsio_lgetxattr_test);
  tcase_add_test(testcase, s3_fsio_fgetxattr_test);
  tcase_add_test(testcase, s3_fsio_listxattr_test);
  tcase_add_test(testcase, s3_fsio_llistxattr_test);
  tcase_add_test(testcase, s3_fsio_flistxattr_test);
  tcase_add_test(testcase, s3_fsio_removexattr_test);
  tcase_add_test(testcase, s3_fsio_lremovexattr_test);
  tcase_add_test(testcase, s3_fsio_fremovexattr_test);
  tcase_add_test(testcase, s3_fsio_setxattr_test);
  tcase_add_test(testcase, s3_fsio_lsetxattr_test);
  tcase_add_test(testcase, s3_fsio_fsetxattr_test);

  tcase_add_test(testcase, s3_fsio_chdir_test);
  tcase_add_test(testcase, s3_fsio_chroot_test);
  tcase_add_test(testcase, s3_fsio_opendir_test);
  tcase_add_test(testcase, s3_fsio_closedir_test);
  tcase_add_test(testcase, s3_fsio_readdir_test);
  tcase_add_test(testcase, s3_fsio_mkdir_test);
  tcase_add_test(testcase, s3_fsio_rmdir_test);
#endif

  suite_add_tcase(suite, testcase);
  return suite;
}
