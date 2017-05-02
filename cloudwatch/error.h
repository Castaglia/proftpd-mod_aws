/*
 * ProFTPD - mod_aws CloudWatch Error API
 * Copyright (c) 2017 TJ Saunders
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

#ifndef MOD_AWS_CLOUDWATCH_ERROR_H
#define MOD_AWS_CLOUDWATCH_ERROR_H

#include "mod_aws.h"
#include "../error.h"

/* CloudWatch Errors */

/* Error code specific to S3 actions */
#define AWS_CLOUDWATCH_ERROR_CODE_INCOMPLETE_SIGNATURE		2000
#define AWS_CLOUDWATCH_ERROR_CODE_INTERNAL_FAILURE		2001
#define AWS_CLOUDWATCH_ERROR_CODE_BAD_ACTION			2002
#define AWS_CLOUDWATCH_ERROR_CODE_BAD_CLIENT_TOKEN_ID		2003
#define AWS_CLOUDWATCH_ERROR_CODE_BAD_PARAM_COMBINATION		2004
#define AWS_CLOUDWATCH_ERROR_CODE_BAD_PARAM_VALUE		2005
#define AWS_CLOUDWATCH_ERROR_CODE_BAD_QUERY_PARAM		2006
#define AWS_CLOUDWATCH_ERROR_CODE_BAD_QUERY_STRING		2007
#define AWS_CLOUDWATCH_ERROR_CODE_MISSING_ACTION		2008
#define AWS_CLOUDWATCH_ERROR_CODE_MISSING_AUTH_TOKEN		2009
#define AWS_CLOUDWATCH_ERROR_CODE_MISSING_PARAM			2010
#define AWS_CLOUDWATCH_ERROR_CODE_OPT_IN_REQUIRED		2011
#define AWS_CLOUDWATCH_ERROR_CODE_REQUEST_EXPIRED		2012
#define AWS_CLOUDWATCH_ERROR_CODE_SERVICE_UNAVAIL		2013
#define AWS_CLOUDWATCH_ERROR_CODE_THROTTLING			2014
#define AWS_CLOUDWATCH_ERROR_CODE_VALIDATION_ERROR		2015

/* Look up the appropriate error code for the given error name string. */
unsigned int aws_cloudwatch_error_get_code(pool *p, const char *err_name);

/* Return the error name for a given error code. */
const char *aws_cloudwatch_error_get_name(unsigned int err_code);

struct aws_error *aws_cloudwatch_error_parse_xml(pool *p, const char *data,
  size_t datasaz);

#endif /* MOD_AWS_CLOUDWATCH_ERROR_H */
