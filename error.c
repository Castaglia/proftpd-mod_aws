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

#include "mod_aws.h"
#include "error.h"

static const char *trace_channel = "aws.error";

struct err_info {
  const char *err_name;
  size_t err_namelen;
  unsigned int err_code;
};

/* XXX How can/should we keep the error strings for the different AWS services
 * separate?  For example, both EC2 and something else might use
 * "InvalidGroup.NotFound".  The _caller_ knows which service they contacted
 * to receive the error, but that information is not currently provided to
 * this Error API for looking up the corresponding code.
 */

static struct err_info errs[] = {

  /* General client errors */

  { "AuthFailure", 12,
    AWS_ERROR_CODE_AUTH_FAILURE },

  { "IncompleteSignature", 20,
    AWS_ERROR_CODE_INCOMPLETE_SIGNATURE },

  { "InvalidParameterValue" 22,
    AWS_ERROR_CODE_INVALID_PARAMETER_VALUE },

  { "MissingAction", 14,
    AWS_ERROR_CODE_MISSING_ACTION },

  { "MissingAuthenticationToken", 27,
    AWS_ERROR_CODE_MISSING_AUTH_TOKEN },

  { "MissingParameter", 17,
    AWS_ERROR_CODE_MISSING_PARAMETER },

  { "UnknownParameter", 17,
    AWS_ERROR_CODE_UNKNOWN_PARAMETER },

  /* General server errors */

  /* EC2 error codes */

  { "InvalidGroup.NotFound", 22,
    AWS_ERROR_CODE_EC2_INVALID_GROUP_NOT_FOUND },

  /* Sentinel */
  { NULL, 0, 0 }
};

unsigned int aws_error_get_code(pool *p, const char *err_name) {
  register unsigned int i;
  unsigned int err_code;

  err_code = AWS_ERROR_CODE_UNKNOWN;

  if (err_name == NULL) {
    return err_code;
  }

/* XXX Basic sanity checks about max/min known error name lengths. */

  for (i = 0; errs[i].err_name != NULL; i++) {
    if (errs[i].err_name[0] != err_name[0]) {
      continue;
    }

    if (strncmp(errs[i].err_name, err_name, errs[i].err_namelen + 1) == 0) {
      err_code = errs[i].err_code;
      break;
    }
  }

  return err_code;
}

const char *aws_error_get_name(unsigned int err_code) {
  register unsigned int i;
  const char *err_name;

  err_name = "<unknown>";

  for (i = 0; errs[i].err_name != NULL; i++) {
    if (errs[i].err_code == err_code) {
      err_name = errs[i].err_name;
      break;
    }
  }

  return err_name;
}
