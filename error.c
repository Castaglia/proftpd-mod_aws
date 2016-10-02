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
#include "xml.h"

static const char *trace_channel = "aws.error";

struct err_info {
  const char *err_name;
  size_t err_namelen;
  unsigned int err_code;

  /* Consider adding a notes table here, for additional service-specific
   * information?
   */
};

/* XXX How can/should we keep the error strings for the different AWS services
 * separate?  For example, both EC2 and something else might use
 * "InvalidGroup.NotFound".  The _caller_ knows which service they contacted
 * to receive the error, but that information is not currently provided to
 * this Error API for looking up the corresponding code.
 *
 * Could do this by having service-specific error get_code/get_name
 * functions, such as "aws_ec2_error_get_code".  That function would first
 * do the lookup of EC2-specific error strings, and only then fallback to
 * this general Error API.
 *
 * The errors below are, for example, EC2-specific:
 *
 *  http://docs.aws.amazon.com/AWSEC2/latest/APIReference/errors-overview.html
 *
 * SQS provides errrors with code, message, detail, and type:
 *
 *  http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/UnderstandingResponses.html#UnderstandingResponses-structure-of-an-error-response
 *
 * And Route53's error might look different, too.  S3's errors DO look
 * different.
 */

static struct err_info errs[] = {

  /* General client errors */

  { "AuthFailure", 12,
    AWS_ERROR_CODE_AUTH_FAILURE },

  { "IncompleteSignature", 20,
    AWS_ERROR_CODE_INCOMPLETE_SIGNATURE },

  { "InvalidParameterValue", 22,
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

  /* S3 error codes */

  { "DryRunOperation", 15,
    AWS_ERROR_CODE_DRY_RUN_OPERATION },

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

struct aws_error *aws_error_parse_xml(pool *p, const char *data,
    size_t datasz) {
  void *doc, *root, *errors, *error, *elt, *req_id;
  pool *err_pool;
  struct aws_error *err;
  unsigned long count;
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
  if (elt_namelen != 8 ||
      strncmp(elt_name, "Response", elt_namelen + 1) != 0) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: root element lacks <Response> element (found <%.*s>)",
      (int) elt_namelen, elt_name);
    errno = EINVAL;
    return NULL;
  }

  /* We expect only 2 child elements: <Errors> and <RequestID> */
  (void) aws_xml_elt_get_child_count(p, root, &count);
  if (count != 2) {
    pr_trace_msg(trace_channel, 2,
      "unexpected count of <Response> child elements (%lu != 2)", count);

    aws_xml_doc_free(p, doc);

    errno = EINVAL;
    return NULL;
  }

  errors = aws_xml_elt_get_child(p, root, "Errors", 6);
  if (errors == NULL) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Response> element lacks <Errors> element");
    errno = EINVAL;
    return NULL;
  }

  (void) aws_xml_elt_get_child_count(p, errors, &count);
  if (count != 1) {
    pr_trace_msg(trace_channel, 5,
      "expected 1 error element, found %lu", count);
  }

  error = aws_xml_elt_get_child(p, errors, "Error", 5);
  if (error == NULL) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Errors> element lacks <Error> element");
    errno = EINVAL;
    return NULL;
  }

  elt = aws_xml_elt_get_child(p, error, "Code", 4);
  if (elt == NULL) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Error> element lacks <Code> element");
    errno = EINVAL;
    return NULL;
  }

  err_pool = make_sub_pool(p);
  pr_pool_tag(err_pool, "AWS Error Pool");
  err = pcalloc(err_pool, sizeof(struct aws_error));
  err->pool = err_pool;

  err->err_code = aws_error_get_code(err->pool,
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

  req_id = aws_xml_elt_get_child(p, root, "RequestID", 9);
  if (req_id == NULL) {
    destroy_pool(err->pool);
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Response> element lacks <RequestID> element");
    errno = EINVAL;
    return NULL;
  }

  err->req_id = aws_xml_elt_get_text(err->pool, req_id);

  aws_xml_doc_free(p, doc);
  return err;
}
