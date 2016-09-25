/*
 * ProFTPD - mod_aws AWS Errors
 * Copyright (c) 2016 TJ Saunders
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

#ifndef MOD_AWS_ERROR_H
#define MOD_AWS_ERROR_H

#include "mod_aws.h"

/* For more on these error code, see:
 *   http://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
 */

/* General client errors */
#define AWS_ERROR_CODE_UNKNOWN					0
#define AWS_ERROR_CODE_AUTH_FAILURE				1
#define AWS_ERROR_CODE_BLOCKED					2
#define AWS_ERROR_CODE_DRY_RUN_OPERATION			3
#define AWS_ERROR_CODE_PARAMETER_MISMATCH			4
#define AWS_ERROR_CODE_INCOMPLETE_SIGNATURE			5
#define AWS_ERROR_CODE_INVALID_ACTION				6
#define AWS_ERROR_CODE_INVALID_CLIENT_TOKEN_ID			7
#define AWS_ERROR_CODE_INVALID_PAGING_TOKEN			8
#define AWS_ERROR_CODE_INVALID_PARAMETER			9
#define AWS_ERROR_CODE_INVALID_PARAMETER_COMBINATION		10
#define AWS_ERROR_CODE_INVALID_PARAMETER_VALUE			11
#define AWS_ERROR_CODE_MALFORMED_QUERY_STRING			12
#define AWS_ERROR_CODE_MISSING_ACTION				13
#define AWS_ERROR_CODE_MISSING_AUTH_TOKEN			14
#define AWS_ERROR_CODE_MISSING_PARAMETER			15
#define AWS_ERROR_CODE_OPT_IN_REQUIRED				16
#define AWS_ERROR_CODE_PENDING_VERIFICATION			17
#define AWS_ERROR_CODE_REQUEST_EXPIRED				18
#define AWS_ERROR_CODE_REQUEST_LIMIT_EXCEEDED			19
#define AWS_ERROR_CODE_UNAUTHORIZED_OPERATION			20
#define AWS_ERROR_CODE_UNKNOWN_PARAMETER			21
#define AWS_ERROR_CODE_UNSUPPORTED_PROTOCOL			22
#define AWS_ERROR_CODE_VALIDATION_ERROR				23

/* General server errors */
#define AWS_ERROR_CODE_INTERNAL_ERROR				51
#define AWS_ERROR_CODE_INTERNAL_FAILURE				52
#define AWS_ERROR_CODE_SERVICE_UNAVAIL				53
#define AWS_ERROR_CODE_UNAVAIL					54

/* Error code specific to EC2 actions */
#define AWS_ERROR_CODE_EC2_FILTER_LIMIT_EXCEEDED		101
#define AWS_ERROR_CODE_EC2_INCORRECT_STATE			102
#define AWS_ERROR_CODE_EC2_INVALID_ASSOC_ID_NOT_FOUND		103
#define AWS_ERROR_CODE_EC2_INVALID_FILTER			104
#define AWS_ERROR_CODE_EC2_INVALID_GROUP_NOT_FOUND		105
#define AWS_ERROR_CODE_EC2_INVALID_ID				106
#define AWS_ERROR_CODE_EC2_INVALID_INPUT			107
#define AWS_ERROR_CODE_EC2_INVALID_INSTANCE_ID			108
#define AWS_ERROR_CODE_EC2_INVALID_INSTANCE_ID_MALFORMED	109
#define AWS_ERROR_CODE_EC2_INVALID_INSTANCE_ID_NOT_FOUND	110
#define AWS_ERROR_CODE_EC2_INVALID_NET_ACL_ENTRY_NOT_FOUND	111
#define AWS_ERROR_CODE_EC2_INVALID_NET_ACL_ID_NOT_FOUND		112
#define AWS_ERROR_CODE_EC2_INVALID_PERMISSION_DUPLICATE		113
#define AWS_ERROR_CODE_EC2_INVALID_PERMISSION_MALFORMED		114
#define AWS_ERROR_CODE_EC2_INVALID_PERMISSION_NOT_FOUND		115
#define AWS_ERROR_CODE_EC2_INVALID_REQUEST			116
#define AWS_ERROR_CODE_EC2_INVALID_SECURITY_GROUP_ID_NOT_FOUND	117
#define AWS_ERROR_CODE_EC2_INVALID_SECURITY_HAS_EXPIRED		118
#define AWS_ERROR_CODE_EC2_INVALID_SERVICE_NAME			119
#define AWS_ERROR_CODE_EC2_INVALID_STATE			120
#define AWS_ERROR_CODE_EC2_NET_ACL_ENTRY_ALREADY_EXISTS		121
#define AWS_ERROR_CODE_EC2_NET_ACL_ENTRY_LIMIT_EXCEEDED		122
#define AWS_ERROR_CODE_EC2_NET_ACL_LIMIT_EXCEEDED		123
#define AWS_ERROR_CODE_EC2_OPERATION_NOT_PERMITTED		124
#define AWS_ERROR_CODE_EC2_RESOURCE_COUNT_EXCEEDED		125
#define AWS_ERROR_CODE_EC2_RESOURCE_LIMIT_EXCEEDED		126
#define AWS_ERROR_CODE_EC2_RULES_PER_SECURITY_GROUP_EXCEEDED	127
#define AWS_ERROR_CODE_EC2_SECURITY_GROUP_LIMIT_EXCEEDED	128
#define AWS_ERROR_CODE_EC2_SIGNATURE_DOES_NOT_MATCH		129
#define AWS_ERROR_CODE_EC2_UNSUPPORTED				130
#define AWS_ERROR_CODE_EC2_UNSUPPORTED_OPERATION		131
#define AWS_ERROR_CODE_EC2_VPC_ID_NOT_SPECIFIED			132

struct aws_error {
  pool *pool;

  unsigned int err_code;
  const char *err_msg;

  /* Some errors (e.g. S3) might have extra elements in their errors
   * (e.g. <Resource>); this is the space for that data.
   */
  const char *err_extra;

  const char *req_id;
};

/* Look up the appropriate error code for the given error name string. */
unsigned int aws_error_get_code(pool *p, const char *err_name);

/* Return the error name for a given error code. */
const char *aws_error_get_name(unsigned int err_code);

/* Parse an error response XML document into an error object. */
struct aws_error *aws_error_parse_xml(pool *p, const char *data, size_t datasz);

#endif /* MOD_AWS_ERROR_H */
