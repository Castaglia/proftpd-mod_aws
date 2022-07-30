/*
 * ProFTPD - mod_aws testsuite
 * Copyright (c) 2017-2022 TJ Saunders <tj@castaglia.org>
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

/* CloudWatch Metric API tests. */

#include "../tests.h"
#include "cloudwatch/metric.h"

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
    pr_trace_set_levels("aws.cloudwatch.conn", 1, 20);
    pr_trace_set_levels("aws.cloudwatch.error", 1, 20);
    pr_trace_set_levels("aws.cloudwatch.metric", 1, 20);
    pr_trace_set_levels("aws.creds", 1, 20);
    pr_trace_set_levels("aws.http", 1, 20);
  }
}

static void tear_down(void) {
  if (getenv("TEST_VERBOSE") != NULL) {
    pr_trace_set_levels("aws.cloudwatch.conn", 0, 0);
    pr_trace_set_levels("aws.cloudwatch.error", 0, 0);
    pr_trace_set_levels("aws.cloudwatch.metric", 0, 0);
    pr_trace_set_levels("aws.creds", 0, 0);
    pr_trace_set_levels("aws.http", 0, 0);
  }

  aws_http_free();
  aws_xml_free();

  if (p != NULL) {
    destroy_pool(p);
    p = permanent_pool = NULL;
  } 
}

static struct cloudwatch_conn *get_cloudwatch(pool *cw_pool) {
  const char *cacerts, *region, *domain;
  array_header *credential_providers;
  struct aws_credential_info *credential_info;
  struct cloudwatch_conn *cw;

  credential_providers = make_array(cw_pool, 1, sizeof(char *));
  *((char **) push_array(credential_providers)) = pstrdup(cw_pool,
    AWS_CREDS_PROVIDER_NAME_PROFILE);
  credential_info = pcalloc(cw_pool, sizeof(struct aws_credential_info));
  credential_info->profile = "default";

  pr_env_set(cw_pool, "AWS_CREDENTIAL_PROFILES_FILE", "/Users/tj/.aws/credentials");

  /* From the instance metadata. */
  cacerts = "/Users/tj/tmp/proftpd-mod_aws/aws-cacerts.pem";
  region = "us-west-2";
  domain = "amazonaws.com";

  mark_point();
  cw = aws_cloudwatch_conn_alloc(cw_pool, max_connect_secs, max_request_secs,
    cacerts, region, domain, credential_providers, credential_info, NULL);
  return cw;
}

START_TEST (cloudwatch_metric_counter_test) {
  int res;
  char *name;
  double incr;
  struct cloudwatch_conn *cw;

  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  mark_point();
  res = aws_cloudwatch_metric_counter(NULL, NULL, NULL, 0.0, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_cloudwatch_metric_counter(p, NULL, NULL, 0.0, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null cloudwatch");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cw = get_cloudwatch(p);
  ck_assert_msg(cw != NULL, "Failed to get CloudWatch connection: %s",
    strerror(errno));

  mark_point();
  res = aws_cloudwatch_metric_counter(p, cw, NULL, 0.0, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null name");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";
  incr = 7.62;

  mark_point();
  res = aws_cloudwatch_metric_counter(p, cw, name, incr, NULL, 0);
  ck_assert_msg(res == 0, "Failed to set counter value: %s", strerror(errno));

  (void) aws_cloudwatch_conn_destroy(p, cw);
}
END_TEST

START_TEST (cloudwatch_metric_timer_test) {
  int res;
  char *name;
  double ms;
  struct cloudwatch_conn *cw;

  if (getenv("CI") != NULL ||
      getenv("TRAVIS") != NULL) {
    return;
  }

  mark_point();
  res = aws_cloudwatch_metric_timer(NULL, NULL, NULL, 0.0, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null pool");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  mark_point();
  res = aws_cloudwatch_metric_timer(p, NULL, NULL, 0.0, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null cloudwatch");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  cw = get_cloudwatch(p);
  ck_assert_msg(cw != NULL, "Failed to get CloudWatch connection: %s",
    strerror(errno));

  mark_point();
  res = aws_cloudwatch_metric_timer(p, cw, NULL, 0.0, NULL, 0);
  ck_assert_msg(res < 0, "Failed to handle null name");
  ck_assert_msg(errno == EINVAL, "Expected EINVAL (%d), got %s (%d)", EINVAL,
    strerror(errno), errno);

  name = "foo.bar";
  ms = 7.62;

  mark_point();
  res = aws_cloudwatch_metric_timer(p, cw, name, ms, NULL, 0);
  ck_assert_msg(res == 0, "Failed to set timing value: %s", strerror(errno));

  (void) aws_cloudwatch_conn_destroy(p, cw);
}
END_TEST

Suite *tests_get_cloudwatch_metric_suite(void) {
  Suite *suite;
  TCase *testcase;

  suite = suite_create("cloudwatch.metric");
  testcase = tcase_create("base");

  tcase_add_checked_fixture(testcase, set_up, tear_down);

  tcase_add_test(testcase, cloudwatch_metric_counter_test);
  tcase_add_test(testcase, cloudwatch_metric_timer_test);

  suite_add_tcase(suite, testcase);
  return suite;
}
