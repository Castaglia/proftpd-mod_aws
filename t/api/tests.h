/*
 * ProFTPD - mod_aws API testsuite
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

/* S3 API tests */
#include "s3/conn.h"
#include "s3/error.h"
#include "s3/utils.h"
#include "s3/bucket.h"
#include "s3/object.h"
#include "s3/fsio.h"

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

Suite *tests_get_s3_conn_suite(void);
Suite *tests_get_s3_error_suite(void);
Suite *tests_get_s3_utils_suite(void);
Suite *tests_get_s3_bucket_suite(void);
Suite *tests_get_s3_object_suite(void);
Suite *tests_get_s3_fsio_suite(void);

unsigned int recvd_signal_flags;
extern pid_t mpid;
extern server_rec *main_server;

#endif /* MOD_AWS_TESTS_H */
