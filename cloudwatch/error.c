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

#include "mod_aws.h"
#include "error.h"
#include "xml.h"
#include "cloudwatch/error.h"

static const char *trace_channel = "aws.cloudwatch.error";

struct err_info {
  const char *err_name;
  size_t err_namelen;
  unsigned int err_code;

  /* Consider adding a notes table here, for additional service-specific
   * information?
   */
};

/* The errors below are for CloudWatch:
 *
 *  http://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/CommonErrors.html
 */

static struct err_info errs[] = {
  { "IncompleteSignature", 19,
    AWS_CLOUDWATCH_ERROR_CODE_INCOMPLETE_SIGNATURE },

  { "InternalFailure", 15,
    AWS_CLOUDWATCH_ERROR_CODE_INTERNAL_FAILURE },

  { "InvalidAction", 13,
    AWS_CLOUDWATCH_ERROR_CODE_BAD_ACTION },

  { "InvalidClientTokenId", 20,
    AWS_CLOUDWATCH_ERROR_CODE_BAD_CLIENT_TOKEN_ID },

  { "InvalidParameterCombination", 27,
    AWS_CLOUDWATCH_ERROR_CODE_BAD_PARAM_COMBINATION },

  { "InvalidParameterValue", 21,
    AWS_CLOUDWATCH_ERROR_CODE_BAD_PARAM_VALUE },

  { "InvalidQueryParameter", 21,
    AWS_CLOUDWATCH_ERROR_CODE_BAD_QUERY_PARAM },

  { "MalformedQueryString", 20,
    AWS_CLOUDWATCH_ERROR_CODE_BAD_QUERY_STRING },

  { "MissingAction", 13,
    AWS_CLOUDWATCH_ERROR_CODE_MISSING_ACTION },

  { "MissingAuthenticationToken", 26,
    AWS_CLOUDWATCH_ERROR_CODE_MISSING_AUTH_TOKEN },

  { "MissingParameter", 16,
    AWS_CLOUDWATCH_ERROR_CODE_MISSING_PARAM },

  { "OptInRequired", 13,
    AWS_CLOUDWATCH_ERROR_CODE_OPT_IN_REQUIRED },

  { "RequestExpired", 14,
    AWS_CLOUDWATCH_ERROR_CODE_REQUEST_EXPIRED },

  { "ServiceUnavailable", 18,
    AWS_CLOUDWATCH_ERROR_CODE_SERVICE_UNAVAIL },

  { "Throttling", 10,
    AWS_CLOUDWATCH_ERROR_CODE_THROTTLING },

  { "ValidationError", 15,
    AWS_CLOUDWATCH_ERROR_CODE_VALIDATION_ERROR },

  /* Sentinel */
  { NULL, 0, 0 }
};

unsigned int aws_cloudwatch_error_get_code(pool *p, const char *err_name) {
  register unsigned int i;
  unsigned int err_code;

  err_code = AWS_ERROR_CODE_UNKNOWN;

  if (p == NULL ||
      err_name == NULL) {
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

  /* If not found, try one of the general error codes. */
  if (err_code == AWS_ERROR_CODE_UNKNOWN) {
    err_code = aws_error_get_code(p, err_name);
  }

  return err_code;
}

const char *aws_cloudwatch_error_get_name(unsigned int err_code) {
  register unsigned int i;
  const char *err_name = NULL;

  for (i = 0; errs[i].err_name != NULL; i++) {
    if (errs[i].err_code == err_code) {
      err_name = errs[i].err_name;
      break;
    }
  }

  /* If not found, try one of the general error names. */
  if (err_name == NULL) {
    err_name = aws_error_get_name(err_code);
  }

  return err_name;
}

struct aws_error *aws_cloudwatch_error_parse_xml(pool *p, const char *data,
    size_t datasz) {
  void *doc, *root, *error, *elt, *req_id;
  pool *err_pool;
  struct aws_error *err;
  const char *elt_name;
  size_t elt_namelen;

  if (data == NULL ||
      datasz == 0) {
    errno = EINVAL;
    return NULL;
  }

  pr_trace_msg(trace_channel, 15,
    "parsing XML error document: '%.*s'", (int) datasz, data);

  doc = aws_xml_doc_parse(p, data, (int) datasz);
  if (doc == NULL) {
    return NULL;
  }

  root = aws_xml_doc_get_root_elt(p, doc);
  if (root == NULL) {
    /* Malformed XML. */
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9, "malformed XML: missing root element");
    errno = EINVAL;
    return NULL;
  }

  elt_name = aws_xml_elt_get_name(p, root, &elt_namelen);
  if (elt_namelen != 13 ||
      strncmp(elt_name, "ErrorResponse", elt_namelen + 1) != 0) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: root element lacks <ErrorResponse> "
      "element (found <%.*s>)", (int) elt_namelen, elt_name);
    errno = EINVAL;
    return NULL;
  }

  elt = aws_xml_elt_get_child(p, root, "Error", 5);
  if (elt == NULL) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <ErrorResponse> element lacks <Error> element");
    errno = EINVAL;
    return NULL;
  }

  error = elt;

  elt = aws_xml_elt_get_child(p, error, "Code", 4);
  if (elt == NULL) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Error> element lacks <Code> element");
    errno = EINVAL;
    return NULL;
  }

  err_pool = make_sub_pool(p);
  pr_pool_tag(err_pool, "AWS CloudWatch Error Pool");
  err = pcalloc(err_pool, sizeof(struct aws_error));
  err->pool = err_pool;

  err->err_code = aws_cloudwatch_error_get_code(err->pool,
    aws_xml_elt_get_text(err->pool, elt));

  elt = aws_xml_elt_get_child(p, error, "Message", 7);
  if (elt == NULL) {
    destroy_pool(err->pool);
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Error> element lacks <Message> element");
    errno = EINVAL;
    return NULL;
  }

  err->err_msg = aws_xml_elt_get_text(err->pool, elt);

  elt = aws_xml_elt_get_child(p, error, "Resource", 8);
  if (elt != NULL) {
    err->err_extra = aws_xml_elt_get_text(err->pool, elt);
  }

  req_id = aws_xml_elt_get_child(p, root, "RequestId", 9);
  if (req_id == NULL) {
    destroy_pool(err->pool);
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <ErrorResponse> element lacks <RequestId> element");
    errno = EINVAL;
    return NULL;
  }

  err->req_id = aws_xml_elt_get_text(err->pool, req_id);

  aws_xml_doc_free(p, doc);
  return err;
}
