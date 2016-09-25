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
#include "error.h"
#include "xml.h"
#include "s3/error.h"

static const char *trace_channel = "aws.s3.error";

struct err_info {
  const char *err_name;
  size_t err_namelen;
  unsigned int err_code;

  /* Consider adding a notes table here, for additional service-specific
   * information?
   */
};

/* The errors below are for S3:
 *
 *  http://docs.aws.amazon.com/AmazonS3/latest/API/ErrorResponses.html
 */

static struct err_info errs[] = {
  { "AccessDenied", 12,
    AWS_S3_ERROR_CODE_ACCESS_DENIED },

  { "AccountProblem", 14,
    AWS_S3_ERROR_CODE_ACCOUNT_PROBLEM },

  { "BadDigest", 9,
    AWS_S3_ERROR_CODE_BAD_DIGEST },

  { "BucketAlreadyExists", 19,
    AWS_S3_ERROR_CODE_BUCKET_ALREADY_EXISTS },

  { "BucketNotEmpty", 14,
    AWS_S3_ERROR_CODE_BUCKET_NOT_EMPTY },

  { "CredentialsNotSupported", 23,
    AWS_S3_ERROR_CODE_CREDENTIALS_NOT_SUPPORTED },

  { "EntityTooSmall", 14,
    AWS_S3_ERROR_CODE_ENTITY_TOO_SMALL },

  { "EntityTooLarge", 14, 
    AWS_S3_ERROR_CODE_ENTITY_TOO_LARGE },

  { "ExpiredToken", 12,
    AWS_S3_ERROR_CODE_EXPIRED_TOKEN },

  { "IncompleteBody", 14,
    AWS_S3_ERROR_CODE_INCOMPLETE_BODY },

  { "InlineDataTooLarge", 18,
    AWS_S3_ERROR_CODE_INLINE_DATA_TOO_LARGE },

  { "InternalError", 13,
    AWS_S3_ERROR_CODE_INTERNAL_ERROR },

  { "InvalidAccessKeyId", 18,
    AWS_S3_ERROR_CODE_INVALID_ACCESS_KEY_ID },

  { "InvalidArgument", 15,
    AWS_S3_ERROR_CODE_INVALID_ARGUMENT },

  { "InvalidBucketName", 17,
    AWS_S3_ERROR_CODE_INVALID_BUCKET_NAME },

  { "InvalidBucketState", 18,
    AWS_S3_ERROR_CODE_INVALID_BUCKET_STATE },

  { "InvalidDigest", 13,
    AWS_S3_ERROR_CODE_INVALID_DIGEST },

  { "InvalidEncryptionAlgorithmError", 31,
    AWS_S3_ERROR_CODE_INVALID_ENCRYPTION_ALGO },

  { "InvalidObjectState", 18,
    AWS_S3_ERROR_CODE_INVALID_OBJECT_STATE },

  { "InvalidPart", 11,
    AWS_S3_ERROR_CODE_INVALID_PART },

  { "InvalidPartOrder", 16,
    AWS_S3_ERROR_CODE_INVALID_PART_ORDER },

  { "InvalidPayer", 12,
    AWS_S3_ERROR_CODE_INVALID_PAYER },

  { "InvalidRange", 12,
    AWS_S3_ERROR_CODE_INVALID_RANGE },

  { "InvalidRequest", 14,
    AWS_S3_ERROR_CODE_INVALID_REQUEST },

  { "InvalidSecurity", 15,
    AWS_S3_ERROR_CODE_INVALID_SECURITY },

  { "InvalidStorageClass", 19,
    AWS_S3_ERROR_CODE_INVALID_STORAGE_CLASS },

  { "InvalidToken", 12,
    AWS_S3_ERROR_CODE_INVALID_TOKEN },

  { "KeyTooLong", 10,
    AWS_S3_ERROR_CODE_KEY_TOO_LONG },

  { "MaxMessageLengthExceeded", 24,
    AWS_S3_ERROR_CODE_MAX_MESSAGE_SIZE_EXCEEDED },

  { "MetadataTooLarge", 16,
    AWS_S3_ERROR_CODE_METADATA_TOO_LARGE },

  { "MethodNotAllowed", 16,
    AWS_S3_ERROR_CODE_METHOD_NOT_ALLOWED },

  { "MissingContentLength", 20,
    AWS_S3_ERROR_CODE_MISSING_CONTENT_LEN },

  { "MissingRequestBodyError", 23, 
    AWS_S3_ERROR_CODE_MISSING_REQUEST_BODY },

  { "MissingSecurityHeader", 21,
    AWS_S3_ERROR_CODE_MISSING_SECURITY_HEADER },

  { "NoSuchBucket", 12,
    AWS_S3_ERROR_CODE_NO_SUCH_BUCKET },

  { "NoSuchKey", 9,
    AWS_S3_ERROR_CODE_NO_SUCH_KEY },

  { "NoSuchUpload", 12,
    AWS_S3_ERROR_CODE_NO_SUCH_UPLOAD },

  { "NotImplemented", 14,
    AWS_S3_ERROR_CODE_NOT_IMPLEMENTED },

  { "NotSignedUp", 11,
    AWS_S3_ERROR_CODE_NOT_SIGNED_UP },

  { "OperationAborted", 16,
    AWS_S3_ERROR_CODE_OPERATION_ABORTED },

  { "PermanentRedirect", 17,
    AWS_S3_ERROR_CODE_PERMANENT_REDIRECT },

  { "PreconditionFailed", 18,
    AWS_S3_ERROR_CODE_PRECONDITION_FAILED },

  { "Redirect", 8,
    AWS_S3_ERROR_CODE_REDIRECT },

  { "RequestTimeout", 14,
    AWS_S3_ERROR_CODE_REQUEST_TIMEOUT },

  { "RequestTimeTooSkewed", 20,
    AWS_S3_ERROR_CODE_REQUEST_TIME_TOO_SKEWED },

  { "SignatureDoesNotMatch", 21,
    AWS_S3_ERROR_CODE_SIGNATURE_DOES_NOT_MATCH },

  { "ServiceUnavailable", 18,
    AWS_S3_ERROR_CODE_SERVICE_UNAVAILABLE },

  { "SlowDown", 8,
    AWS_S3_ERROR_CODE_SLOW_DOWN },

  { "TemporaryRedirect", 17,
    AWS_S3_ERROR_CODE_TEMPORARY_REDIRECT },

  { "TokenRefreshRequired", 20,
    AWS_S3_ERROR_CODE_TOKEN_REFRESH_REQUIRED },

  { "TooManyBuckets", 14,
    AWS_S3_ERROR_CODE_TOO_MANY_BUCKETS },

  { "UnexpectedContent", 17,
    AWS_S3_ERROR_CODE_UNEXPECTED_CONTENT },

  /* Sentinel */
  { NULL, 0, 0 }
};

unsigned int aws_s3_error_get_code(pool *p, const char *err_name) {
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

const char *aws_s3_error_get_name(unsigned int err_code) {
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

struct aws_error *aws_s3_error_parse_xml(pool *p, const char *data,
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
  if (elt_namelen != 5 ||
      strncmp(elt_name, "Error", elt_namelen + 1) != 0) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: root element lacks <Error> element (found <%.*s>)",
      (int) elt_namelen, elt_name);
    errno = EINVAL;
    return NULL;
  }

  error = root;

  elt = aws_xml_elt_get_child(p, error, "Code", 4);
  if (elt == NULL) {
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Error> element lacks <Code> element");
    errno = EINVAL;
    return NULL;
  }

  err_pool = make_sub_pool(p);
  pr_pool_tag(err_pool, "AWS S3 Error Pool");
  err = palloc(err_pool, sizeof(struct aws_error));
  err->pool = err_pool;

  err->err_code = aws_s3_error_get_code(err->pool,
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

  /* What about the <HostId> element I've seen in S3 errror responses? */

  req_id = aws_xml_elt_get_child(p, error, "RequestId", 9);
  if (req_id == NULL) {
    destroy_pool(err->pool);
    aws_xml_doc_free(p, doc);

    pr_trace_msg(trace_channel, 9,
      "malformed XML: <Error> element lacks <RequestId> element");
    errno = EINVAL;
    return NULL;
  }

  err->req_id = aws_xml_elt_get_text(err->pool, req_id);

  aws_xml_doc_free(p, doc);
  return err;
}
