/*
 * ProFTPD - mod_aws EC2 instance info
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
#include "instance.h"

static char curl_errorbuf[CURL_ERROR_SIZE];

static const char *trace_channel = "aws.instance";

/* To discover the EC2 instance metadata for this instance, we query/use the
 * information available via:
 *
 *  http://169.254.169.254/latest/meta-data/
 *  http://169.254.169.254/latest/dynamic/instance-identity/document
 *
 */

#define AWS_HTTP_RESPONSE_CODE_OK	200L
#define AWS_INSTANCE_METADATA_URI	"http://169.254.169.254/latest"

/* XXX Refactor this into a more generic "GET this URL" function, for better
 * reuse of the error checking, etc.
 */

static size_t aws_domain_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct aws_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->aws_domainsz == 0) {
    info->aws_domainsz = datasz;
    ptr = info->aws_domain = palloc(info->pool, info->aws_domainsz);

  } else {
    ptr = info->aws_domain;
    info->aws_domain = palloc(info->pool, info->aws_domainsz + datasz);
    memcpy(info->aws_domain, ptr, info->aws_domainsz);

    ptr = info->aws_domain + info->aws_domainsz;
    info->aws_domainsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_aws_domain(pool *p, CURL *curl, struct aws_info *info) {
  CURLcode curl_code;
  const char *url;
  long resp_code;
  double content_len, rcvd_bytes, total_secs;
  char *content_type = NULL;

  url = AWS_INSTANCE_METADATA_URI "/services/domain";

  curl_code = curl_easy_setopt(curl, CURLOPT_CURL, url);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_URL '%s': %s", url, curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  curl_code = curl_easy_setopt(curl, CURL_WRITEFUNCTION, aws_domain_write_cb);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_WRITEFUNCTION: %s", curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  curl_code = curl_easy_setopt(curl, CURL_WRITEDATA, info);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_WRITEDATA: %s", curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  /* Clear error buffer, response message before performing request,
   * per docs.
   */
  curl_errorbuf[0] = '\0';
  info->last_resp_msg = NULL;

  curl_code = curl_easy_perform(curl);
  if (curl_code != CURLE_OK) {
    size_t error_len;

    error_len = strlen(curl_errorbuf);
    if (error_len > 0) {
      pr_trace_msg(trace_channel, 1,
        "'%s' request error: %s", url, curl_errorbuf);

    } else {
      pr_trace_msg(trace_channel, 1,
        "'%s' request error: %s", url, curl_easy_strerror(curl_code));
    }

    errno = EPERM;
    return -1;
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
  if (curl_code == CURLE_UNKNOWN_OPTION) {
    /* Use the older option name. */
    curl_code = curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &resp_code);
  }

  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 2,
      "unable to get '%s' response code: %s", url,
      curl_easy_strerror(curl_code));

    errno = EPERM;
    return -1;
  }

  if (info->last_resp_msg != NULL) {
    pr_trace_msg(trace_channel, 15,
      "received response '%ld %s' for '%s' request", resp_code,
      info->last_resp_msg, url);

  } else {
    pr_trace_msg(trace_channel, 15,
      "received response code %ld for '%s' request", resp_code, url);
  }

  if (resp_code != AWS_HTTP_RESPONSE_CODE_OK) {
    pr_trace_msg(trace_channel, 2,
      "received %ld response code for '%s' request", resp_code, url);
    errno = EPERM;
    return -1;
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
    &content_len);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_CONTENT_LENGTH_DOWNLOAD: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);
  if (curl_code == CURLE_OK) {
    if (content_type != NULL) {
      pr_trace_msg(trace_channel, 15,
        "received Content-Type '%s' for '%s' request", content_type, url);
    }

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_CONTENT_TYPE: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_secs);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "'%s' request took %0.3lf secs", total_secs);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_TOTAL_TIME: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &rcvd_bytes);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "received %0.3lf bytes for '%s' request", rcvd_bytes);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_SIZE_DOWNLOAD: %s",
      curl_easy_strerror(curl_code));
  }

  return 0;
}

static int get_info(pool *p, CURL *curl, struct aws_info *info) {
  int res;

  /* Some resources provide only a single bit of metadata, and some provide
   * a blob of metadata.
   *
   * XXX Start by calling the document, and parsing the JSON.  If that
   * doesn't work, fall back to doing the individual calls.
   */
  res = get_aws_domain(p, curl, info);

  return 0;
}

static size_t curl_header_cb(char *data, size_t itemsz, size_t item_count,
    void *user_data) {
  CURL *curl;
  size_t datasz;

  curl = user_data;
  datasz = itemsz * item_count;

  /* Fortunately, only COMPLETE headers are passed to us, so that we do not
   * need to do any buffering.  Be aware that the header data may NOT be
   * NUL-terminated.
   */

  if (strncmp(data, "HTTP/1.0 ", 9) == 0 ||
      strncmp(data, "HTTP/1.1 ", 9) == 0) {
    struct aws_info *info = NULL;
    CURLcode curl_code;

    /* We're receiving the HTTP response status line. */

    curl_code = curl_easy_getinfo(curl, CURLINFO_PRIVATE, &info);
    if (curl_code == CURLE_OK &&
        info != NULL) {
      char *resp_msg;
      size_t resp_msglen;

      /* Advance the pointer past "HTTP/1.x NNNN "(13). */
      resp_msg = data + 13;
      resp_msglen = datasz - 13;

      info->last_resp_msg = pstrndup(info->pool, resp_msg, resp_msglen);

    } else {
      pr_trace_msg(trace_channel, 3,
        "unable to get CURLINFO_PRIVATE: %s",
        curl_easy_strerror(curl_code));
    }
  }

  return datasz;
}

static int curl_debug_cb(CURL *curl, curl_infotype data_type, char *data,
    size_t datasz, void *user_data) {

  /* Tell the compiler we won't be using this argument. */
  (void) curl;

  switch (data_type) {
    case CURLINFO_TEXT:
      pr_trace_msg(trace_channel, 15,
        "[debug] TEXT: %s (%ld bytes)", data, datasz);
      break;

    case CURLINFO_HEADER_IN:
      pr_trace_msg(trace_channel, 15,
        "[debug] HEADER IN: %s (%ld bytes)", data, datasz);
      break;

    case CURLINFO_HEADER_OUT:
      pr_trace_msg(trace_channel, 15,
        "[debug] HEADER OUT: %s (%ld bytes)", data, datasz);
      break;

    case CURLINFO_DATA_IN:
      pr_trace_msg(trace_channel, 15,
        "[debug] DATA IN: (%ld bytes)", datasz);
      break;

    case CURLINFO_DATA_OUT:
      pr_trace_msg(trace_channel, 15,
        "[debug] DATA OUT: (%ld bytes)", datasz);
      break;

    case CURLINFO_SSL_DATA_IN:
      pr_trace_msg(trace_channel, 15,
        "[debug] SSL DATA IN: (%ld bytes)", datasz);
      break;

    case CURLINFO_SSL_DATA_OUT:
      pr_trace_msg(trace_channel, 15,
        "[debug] SSL DATA OUT: (%ld bytes)", datasz);
      break;

    default:
      pr_trace_msg(trace_channel, 3,
        "[debug] UNKNOWN DEBUG DATA: %d", (int) data_type);
      break;
  }

  return 0;
}

struct aws_info *aws_instance_get_info(pool *p) {
  int res;
  pool *info_pool;
  struct aws_info *info;
  CURL *curl;
  CURLcode curl_code;
  struct curl_slist *headers = NULL;

  /* XXX use an easy handle, then clean it up when we're done; we don't need
   * to keep persistent connections open to the metadata service after
   * discovery.
   */

  curl = curl_easy_init();
  if (curl == NULL) {
    pr_trace_msg(trace_channel, 3,
      "error initializing curl easy handle");
    errno = ENOMEM;
    return NULL;
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_FOLLOWLOCATION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_NOPROGRESS: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_NOSIGNAL: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_TCP_NODELAY: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_TCP_KEEPALIVE: %s",
      curl_easy_strerror(curl_code));
  }

  headers = curl_slist_append(headers, "Host: 169.254.169.254");
  headers = curl_slist_append(headers, "Accept: */*");
  curl_code = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HTTPHEADER: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_USERAGENT, MOD_AWS_VERSION);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_USERAGENT: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, curl_header_cb);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HEADERFUNCTION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_HEADERDATA, curl);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HEADERDATA: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_cb);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_DEBUGFUNCTION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_DEBUGDATA, NULL);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_DEBUGDATA: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_VERBOSE: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errorbuf);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_ERRORBUFFER: %s",
      curl_easy_strerror(curl_code));
  }

  info_pool = make_sub_pool(p);
  pr_pool_tag(info_pool, "Instance info pool");

  info = pcalloc(info_pool, sizeof(struct aws_info));
  info->pool = info_pool;

  curl_code = curl_easy_setopt(curl, CURLOPT_PRIVATE, info);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_PRIVATE: %s",
      curl_easy_strerror(curl_code));
  }

  res = get_info(p, curl, info);

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  if (res < 0) {
    info = NULL;
  }

  return info;
}
