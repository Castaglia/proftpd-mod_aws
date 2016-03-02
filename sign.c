/*
 * ProFTPD - mod_aws AWS signatures
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
#include "sign.h"
#include "http.h"
#include "utils.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

static const char *sign_v4_algo = "AWS4-HMAC-SHA256";

static const char *trace_channel = "aws.sign";

static const char *get_errors(pool *p) {
  unsigned int count = 0;
  unsigned long error_code;
  BIO *bio = NULL;
  char *data = NULL;
  long datalen;
  const char *error_data = NULL, *str = "(unknown)";
  int error_flags = 0;

  /* Use ERR_print_errors() and a memory BIO to build up a string with
   * all of the error messages from the error queue.
   */

  error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  if (error_code) {
    bio = BIO_new(BIO_s_mem());
  }

  while (error_code) {
    pr_signals_handle();

    if (error_flags & ERR_TXT_STRING) {
      BIO_printf(bio, "\n  (%u) %s [%s]", ++count,
        ERR_error_string(error_code, NULL), error_data);

    } else {
      BIO_printf(bio, "\n  (%u) %s", ++count,
        ERR_error_string(error_code, NULL));
    }

    error_data = NULL;
    error_flags = 0;
    error_code = ERR_get_error_line_data(NULL, NULL, &error_data, &error_flags);
  }

  datalen = BIO_get_mem_data(bio, &data);
  if (data) {
    data[datalen] = '\0';
    str = pstrdup(p, data);
  }

  if (bio != NULL) {
    BIO_free(bio);
  }

  return str;
}

/* Step 1: Create canonical request
 *   http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 */

static const char *create_canon_uri(pool *p, void *http, const char *uri) {
  size_t urisz;
  const char *canon_uri;

  urisz = strlen(uri);
  if (urisz == 1) {
    return uri;
  }

  canon_uri = aws_http_urlencode(p, http, uri, urisz);
  if (canon_uri == NULL) {
    return NULL;
  }

  return canon_uri;
}

static int ascii_cmp(const void *a, const void *b) {
  return strcmp(*((const char **) a), *((const char **) b));
}

static const char *create_canon_query(pool *p, array_header *query_params) {
  register unsigned int i, last_idx;
  char *canon_query = NULL, **elts;

  if (query_params->nelts == 0) {
    return pstrdup(p, "");
  }

  qsort(query_params->elts, query_params->nelts, sizeof(char *), ascii_cmp);

  elts = query_params->elts;
  last_idx = query_params->nelts - 1;

  for (i = 0; i < query_params->nelts; i++) {
    pr_signals_handle();

    canon_query = pstrcat(p,
      canon_query != NULL ? canon_query : "", elts[i],
      i != last_idx ? "&" : "", NULL);
  }

  return canon_query;
}

static const char *create_canon_headers(pool *p, pr_table_t *headers) {
  register unsigned int i;
  int header_count;
  array_header *http_headers;
  char *canon_headers = NULL, **elts;
  void *key;

  header_count = pr_table_count(headers);
  if (header_count == 0) {
    return pstrdup(p, "");
  }

  http_headers = make_array(p, header_count, sizeof(char *));

  pr_table_rewind(headers);
  key = pr_table_next(headers);
  while (key != NULL) {
    void *value;
    char *name, *header_name, *header_value;

    pr_signals_handle();

    value = pr_table_get(headers, key, NULL);
    if (value == NULL) {
      key = pr_table_next(headers);
      continue;
    }

    /* Convert this header name to all lowercase, per the AWS docs. */
    name = (char *) key;
    header_name = pstrdup(p, name);
    for (i = 0; name[i]; i++) {
      header_name[i] = tolower((int) name[i]);
    }

    /* Trim off leading/trailing whitespace on the value, per the AWS docs. */
    header_value = aws_utils_str_trim(p, (const char *) value);
    pr_trace_msg(trace_channel, 19, "trimmed '%s' value '%s' to '%s'",
      name, (const char *) value, header_value);

    *((char **) push_array(http_headers)) = pstrcat(p,
      header_name, ":", header_value, NULL);
    key = pr_table_next(headers);
  }

  qsort(http_headers->elts, http_headers->nelts, sizeof(char *), ascii_cmp);

  elts = http_headers->elts;
  for (i = 0; i < http_headers->nelts; i++) {
    pr_signals_handle();

    canon_headers = pstrcat(p,
      canon_headers != NULL ? canon_headers : "", elts[i], "\n", NULL);
  }

  return canon_headers;
}

static const char *create_signed_headers(pool *p, pr_table_t *headers) {
  register unsigned int i, last_idx;
  int header_count;
  array_header *header_names;
  char *signed_headers = NULL, **elts;
  void *key;

  header_count = pr_table_count(headers);
  if (header_count == 0) {
    return pstrdup(p, "");
  }

  header_names = make_array(p, header_count, sizeof(char *));

  pr_table_rewind(headers);
  key = pr_table_next(headers);
  while (key != NULL) {
    char *name, *header;

    pr_signals_handle();

    /* Convert this header name to all lowercase, per the AWS docs. */
    name = (char *) key;
    header = pstrdup(p, name);
    for (i = 0; name[i]; i++) {
      header[i] = tolower((int) name[i]);
    }

    *((char **) push_array(header_names)) = header;
    key = pr_table_next(headers);
  }

  qsort(header_names->elts, header_names->nelts, sizeof(char *), ascii_cmp);

  elts = header_names->elts;
  last_idx = header_names->nelts - 1;

  for (i = 0; i < header_names->nelts; i++) {
    pr_signals_handle();

    signed_headers = pstrcat(p,
      signed_headers != NULL ? signed_headers : "", elts[i],
      i != last_idx ? ";" : "", NULL);
  }

  return signed_headers;
}

static const char *create_canon_request(pool *p, void *http,
    const char *http_method, const char *http_path, array_header *query_params,
    pr_table_t *http_headers, const char *http_body,
    const char **signed_headers, const char **canon_request_hash) {
  char *canon_request;
  unsigned char buf[SHA256_DIGEST_LENGTH];
  size_t canon_requestlen, http_bodylen;
  const char *canon_uri, *canon_query, *canon_headers, *payload_hash;

  canon_uri = create_canon_uri(p, http, http_path);
  if (canon_uri == NULL) {
    return NULL;
  }
  pr_trace_msg(trace_channel, 19, "canonical URI: '%s'", canon_uri);

  canon_query = create_canon_query(p, query_params);
  if (canon_query == NULL) {
    return NULL;
  }
  pr_trace_msg(trace_channel, 19, "canonical query: '%s'", canon_query);

  canon_headers = create_canon_headers(p, http_headers);
  if (canon_headers == NULL) {
    return NULL;
  }
  pr_trace_msg(trace_channel, 19, "canonical headers: '%s'", canon_headers);

  *signed_headers = create_signed_headers(p, http_headers);
  if (*signed_headers == NULL) {
    return NULL;
  }
  pr_trace_msg(trace_channel, 19, "signed headers: '%s'", *signed_headers);

  /* Note: If/when the body length exceeds a certain size, we'll need to
   * use SHA256_{Init,Update,Final} in a more streamy fashion, rather than
   * using this oneshot SHA256() function.  Also, for such large payloads,
   * consider streaming it from a file descriptor/handle, rather than having
   * callers load it all into memory.
   */

  http_bodylen = strlen(http_body);
  if (SHA256((unsigned char *) http_body, http_bodylen, buf) == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error calculating SHA256 digest of request payload: %s", get_errors(p));
    errno = EINVAL;
    return NULL;
  }

  payload_hash = pr_str_bin2hex(p, buf, sizeof(buf), PR_STR_FL_HEX_USE_LC);
  if (payload_hash == NULL) {
    pr_trace_msg(trace_channel, 1, "error hex-encoding payload digest: %s",
      strerror(errno));
    errno = EINVAL;
    return NULL;
  }
  pr_trace_msg(trace_channel, 19, "payload hash: '%s'", payload_hash);

  canon_request = pstrcat(p,
    http_method, "\n",
    canon_uri, "\n",
    canon_query, "\n",
    canon_headers, "\n",
    *signed_headers, "\n",
    payload_hash, NULL);

  canon_requestlen = strlen(canon_request);
  if (SHA256((unsigned char *) canon_request, canon_requestlen, buf) == NULL) {
    pr_trace_msg(trace_channel, 2,
      "error calculating SHA256 digest of canonical request: %s",
      get_errors(p));
    errno = EINVAL;
    return NULL;
  }

  *canon_request_hash = pr_str_bin2hex(p, buf, sizeof(buf),
    PR_STR_FL_HEX_USE_LC);
  if (*canon_request_hash == NULL) {
    pr_trace_msg(trace_channel, 1,
      "error hex-encoding canonical request digest: %s", strerror(errno));
    errno = EINVAL;
    return NULL;
  }
  pr_trace_msg(trace_channel, 19, "canonical request hash: '%s'",
    *canon_request_hash);

  return canon_request;
}

/* Step 2: Create string-to-sign
 *   http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
 */
static const char *create_string_to_sign(pool *p, time_t request_time,
    const char *region, const char *service, const char *request_hash,
    const char **credential_scope) {
  const char *string_to_sign;
  char *iso_date, *utc_date;
  size_t iso_datesz, utc_datesz;
  struct tm *gmt_tm;

  /* Format the given timestamp as YYYYMMDD, per AWS docs. */
  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  iso_datesz = 18;
  iso_date = pcalloc(p, iso_datesz + 1);
  (void) strftime(iso_date, iso_datesz, "%Y%m%dT%H%M%SZ", gmt_tm);

  utc_datesz = 10;
  utc_date = pcalloc(p, utc_datesz + 1);
  (void) strftime(utc_date, utc_datesz, "%Y%m%d", gmt_tm);

  *credential_scope = pstrcat(p, utc_date, "/", region, "/", service,
    "/aws4_request", NULL);
  pr_trace_msg(trace_channel, 19, "credential scope: '%s'", *credential_scope);

  string_to_sign = pstrcat(p, sign_v4_algo, "\n", iso_date, "\n",
    *credential_scope, "\n", request_hash, NULL);

  return string_to_sign;
}

/* Step 3: Calculate signature
 *   http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
 */
static const char *calculate_signature(pool *p, time_t request_time,
    const char *region, const char *service, const char *string_to_sign,
    const char *secret_access_key) {
  const EVP_MD *md = EVP_sha256();
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned int buflen;
  char *utc_date;
  size_t utc_datesz;
  struct tm *gmt_tm;
  unsigned char *secret_key, *date_key, *region_key, *service_key, *signing_key;
  char *signature;

  /* Format the given timestamp as YYYYMMDD, per AWS docs. */
  gmt_tm = pr_gmtime(p, &request_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  utc_datesz = 10;
  utc_date = pcalloc(p, utc_datesz + 1);
  (void) strftime(utc_date, utc_datesz, "%Y%m%d", gmt_tm);

  secret_key = (unsigned char *) pstrcat(p, "AWS4", secret_access_key, NULL);

  /* Calculate the date key */
  date_key = HMAC(md, secret_key, strlen((char *) secret_key),
    (const unsigned char *) utc_date, strlen(utc_date), buf, &buflen);
  if (date_key == NULL) {
    pr_trace_msg(trace_channel, 1,
      "HMAC-SHA256 error deriving date key: %s", get_errors(p));
    errno = EPERM;
    return NULL;
  }

  /* Calculate the region key */
  region_key = HMAC(md, (unsigned char *) date_key, buflen,
    (const unsigned char *) region, strlen(region), buf, &buflen);
  if (region_key == NULL) {
    pr_trace_msg(trace_channel, 1,
      "HMAC-SHA256 error deriving region key: %s", get_errors(p));
    errno = EPERM;
    return NULL;
  }

  /* Calculate the service key */
  service_key = HMAC(md, (unsigned char *) region_key, buflen,
    (const unsigned char *) service, strlen(service), buf, &buflen);
  if (service_key == NULL) {
    pr_trace_msg(trace_channel, 1,
      "HMAC-SHA256 error deriving service key: %s", get_errors(p));
    errno = EPERM;
    return NULL;
  }

  /* Calculate the signing key */
  signing_key = HMAC(md, service_key, buflen,
    (const unsigned char *) "aws4_request", 12, buf, &buflen);
  if (signing_key == NULL) {
    pr_trace_msg(trace_channel, 1,
      "HMAC-SHA256 error deriving signing key: %s", get_errors(p));
    errno = EPERM;
    return NULL;
  }

  /* Use the signing key on our string to sign, to get the signature. */
  if (HMAC(md, signing_key, buflen, (const unsigned char *) string_to_sign,
      strlen(string_to_sign), buf, &buflen) == NULL) {
    pr_trace_msg(trace_channel, 1,
      "HMAC-SHA256 error calculating signature: %s", get_errors(p));
    errno = EPERM;
    return NULL;
  }

  signature = pr_str_bin2hex(p, buf, buflen, PR_STR_FL_HEX_USE_LC);
  if (signature == NULL) {
    pr_trace_msg(trace_channel, 1,
      "error hex-encoding signature: %s", strerror(errno));
    errno = EPERM;
    return NULL;
  }

  return signature;
}

int aws_sign_v4_generate(pool *p, const char *access_key_id,
    const char *secret_access_key, const char *token,
    const char *region, const char *service,
    void *http, const char *http_method, const char *http_path,
    array_header *query_params, pr_table_t *http_headers,
    const char *http_body, time_t request_time) {
  int res;
  const char *credential_scope, *canon_request, *canon_request_hash;
  const char *signature, *signed_headers;
  const char *string_to_sign;
  char *authz;

  if (p == NULL ||
      access_key_id == NULL ||
      secret_access_key == NULL ||
      region == NULL ||
      service == NULL ||
      http_method == NULL ||
      http_path == NULL ||
      query_params == NULL ||
      http_headers == NULL ||
      http_body == NULL) {
    errno = EINVAL;
    return -1;
  }

  canon_request = create_canon_request(p, http, http_method, http_path,
    query_params, http_headers, http_body, &signed_headers,
    &canon_request_hash);
  if (canon_request == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error creating canonical request: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }
  pr_trace_msg(trace_channel, 19, "canonical request: '%s'", canon_request);

  string_to_sign = create_string_to_sign(p, request_time, region, service,
    canon_request_hash, &credential_scope);
  if (string_to_sign == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error creating string-to-sign: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }
  pr_trace_msg(trace_channel, 19, "string to sign: '%s'", string_to_sign);

  signature = calculate_signature(p, request_time, region, service,
    string_to_sign, secret_access_key);
  if (signature == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error calculating signature: %s",
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }
  pr_trace_msg(trace_channel, 19, "v4 signature: '%s'", signature);

  /* Now we can finally construct and add an Authorization header with
   * our calculated signature et al.
   */

  authz = pstrcat(p, sign_v4_algo,
    " Credential=", access_key_id, "/", credential_scope,
    ", SignedHeaders=", signed_headers, ", Signature=", signature, NULL);

  res = pr_table_add(http_headers, pstrdup(p, AWS_HTTP_HEADER_AUTHZ), authz, 0);
  if (res < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3, "error adding %s header: %s",
      AWS_HTTP_HEADER_AUTHZ, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (token != NULL) {
    res = pr_table_add(http_headers,
      pstrdup(p, AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN), (char *) token, 0);
    if (res < 0) {
      int xerrno = errno;

      pr_trace_msg(trace_channel, 3, "error adding %s header: %s",
        AWS_HTTP_HEADER_X_AMZ_SECURITY_TOKEN, strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  return 0;
}
