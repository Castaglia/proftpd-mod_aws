/*
 * ProFTPD - mod_aws S3 Error API
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

#include "mod_aws.h"
#include "../error.h"

#ifndef MOD_AWS_S3_ERROR_H
#define MOD_AWS_S3_ERROR_H

/* S3 Errors */

/* Error code specific to S3 actions */
#define AWS_S3_ERROR_CODE_ACCESS_DENIED				1000
#define AWS_S3_ERROR_CODE_ACCOUNT_PROBLEM			1001
#define AWS_S3_ERROR_CODE_BAD_DIGEST				1002
#define AWS_S3_ERROR_CODE_BUCKET_ALREADY_EXISTS			1003
#define AWS_S3_ERROR_CODE_BUCKET_NOT_EMPTY			1004
#define AWS_S3_ERROR_CODE_CREDENTIALS_NOT_SUPPORTED		1005
#define AWS_S3_ERROR_CODE_ENTITY_TOO_SMALL			1006
#define AWS_S3_ERROR_CODE_ENTITY_TOO_LARGE			1007
#define AWS_S3_ERROR_CODE_EXPIRED_TOKEN				1008
#define AWS_S3_ERROR_CODE_INCOMPLETE_BODY			1009
#define AWS_S3_ERROR_CODE_INLINE_DATA_TOO_LARGE			1010
#define AWS_S3_ERROR_CODE_INTERNAL_ERROR			1011
#define AWS_S3_ERROR_CODE_INVALID_ACCESS_KEY_ID			1012
#define AWS_S3_ERROR_CODE_INVALID_ARGUMENT			1013
#define AWS_S3_ERROR_CODE_INVALID_BUCKET_NAME			1014
#define AWS_S3_ERROR_CODE_INVALID_BUCKET_STATE			1015
#define AWS_S3_ERROR_CODE_INVALID_DIGEST			1016
#define AWS_S3_ERROR_CODE_INVALID_ENCRYPTION_ALGO		1017
#define AWS_S3_ERROR_CODE_INVALID_OBJECT_STATE			1018
#define AWS_S3_ERROR_CODE_INVALID_PART				1019
#define AWS_S3_ERROR_CODE_INVALID_PART_ORDER			1020
#define AWS_S3_ERROR_CODE_INVALID_PAYER				1021
#define AWS_S3_ERROR_CODE_INVALID_RANGE				1022
#define AWS_S3_ERROR_CODE_INVALID_REQUEST			1023
#define AWS_S3_ERROR_CODE_INVALID_SECURITY			1024
#define AWS_S3_ERROR_CODE_INVALID_STORAGE_CLASS			1025
#define AWS_S3_ERROR_CODE_INVALID_TOKEN				1026
#define AWS_S3_ERROR_CODE_KEY_TOO_LONG				1027
#define AWS_S3_ERROR_CODE_MAX_MESSAGE_SIZE_EXCEEDED		1028
#define AWS_S3_ERROR_CODE_METADATA_TOO_LARGE			1029
#define AWS_S3_ERROR_CODE_METHOD_NOT_ALLOWED			1030
#define AWS_S3_ERROR_CODE_MISSING_CONTENT_LEN			1031
#define AWS_S3_ERROR_CODE_MISSING_REQUEST_BODY			1032
#define AWS_S3_ERROR_CODE_MISSING_SECURITY_HEADER		1033
#define AWS_S3_ERROR_CODE_NO_SUCH_BUCKET			1034
#define AWS_S3_ERROR_CODE_NO_SUCH_KEY				1035
#define AWS_S3_ERROR_CODE_NO_SUCH_UPLOAD			1036
#define AWS_S3_ERROR_CODE_NOT_IMPLEMENTED			1037
#define AWS_S3_ERROR_CODE_NOT_SIGNED_UP				1038
#define AWS_S3_ERROR_CODE_OPERATION_ABORTED			1039
#define AWS_S3_ERROR_CODE_PERMANENT_REDIRECT			1040
#define AWS_S3_ERROR_CODE_PRECONDITION_FAILED			1041
#define AWS_S3_ERROR_CODE_REDIRECT				1042
#define AWS_S3_ERROR_CODE_REQUEST_TIMEOUT			1043
#define AWS_S3_ERROR_CODE_REQUEST_TIME_TOO_SKEWED		1044
#define AWS_S3_ERROR_CODE_SIGNATURE_DOES_NOT_MATCH		1045
#define AWS_S3_ERROR_CODE_SERVICE_UNAVAILABLE			1046
#define AWS_S3_ERROR_CODE_SLOW_DOWN				1047
#define AWS_S3_ERROR_CODE_TEMPORARY_REDIRECT			1048
#define AWS_S3_ERROR_CODE_TOKEN_REFRESH_REQUIRED		1049
#define AWS_S3_ERROR_CODE_TOO_MANY_BUCKETS			1050
#define AWS_S3_ERROR_CODE_UNEXPECTED_CONTENT			1051

/* Look up the appropriate error code for the given error name string. */
unsigned int aws_s3_error_get_code(pool *p, const char *err_name);

/* Return the error name for a given error code. */
const char *aws_s3_error_get_name(unsigned int err_code);

struct aws_error *aws_s3_error_parse_xml(pool *p, const char *data,
  size_t datasaz);

#endif /* MOD_AWS_S3_ERROR_H */
