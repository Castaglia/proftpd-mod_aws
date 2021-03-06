/*
 * ProFTPD - mod_aws API testsuite
 * Copyright (c) 2016-2020 TJ Saunders <tj@castaglia.org>
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

/* Testsuite management */

#ifndef MOD_AWS_TESTS_H
#define MOD_AWS_TESTS_H

#include "mod_aws.h"

#include "xml.h"
#include "error.h"
#include "http.h"
#include "instance.h"
#include "creds.h"
#include "sign.h"
#include "utils.h"

/* CloudWatch API tests */
#include "cloudwatch/conn.h"
#include "cloudwatch/error.h"
#include "cloudwatch/dimension.h"
#include "cloudwatch/metric.h"

#ifdef HAVE_CHECK_H
# include <check.h>
#else
# error "Missing Check installation; necessary for ProFTPD testsuite"
#endif

Suite *tests_get_xml_suite(void);
Suite *tests_get_error_suite(void);
Suite *tests_get_http_suite(void);
Suite *tests_get_instance_suite(void);
Suite *tests_get_creds_suite(void);
Suite *tests_get_sign_suite(void);
Suite *tests_get_utils_suite(void);

/* CloudWatch API tests */
Suite *tests_get_cloudwatch_conn_suite(void);
Suite *tests_get_cloudwatch_error_suite(void);
Suite *tests_get_cloudwatch_dimension_suite(void);
Suite *tests_get_cloudwatch_metric_suite(void);

extern volatile unsigned int recvd_signal_flags;
extern pid_t mpid;
extern server_rec *main_server;

#endif /* MOD_AWS_TESTS_H */
