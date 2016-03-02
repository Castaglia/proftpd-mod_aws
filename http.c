/*
 * ProFTPD - mod_aws HTTP API
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
#include "http.h"
#include "utils.h"

#ifdef HAVE_CURL_CURL_H
# include <curl/curl.h>
#endif

static char curl_errorbuf[CURL_ERROR_SIZE];
static CURLSH *curl_share = NULL;

static char *http_resp_msg = NULL;
static pool *http_resp_pool = NULL;

static const char *trace_channel = "aws.http";

const char *aws_http_urldecode(pool *p, void *http, const char *item,
    size_t item_len, size_t *decoded_len) {
  CURL *curl;
  char *decoded_item, *ptr;

  curl = http;
  ptr = curl_easy_unescape(curl, item, (int) item_len, (int *) decoded_len);
  if (ptr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  decoded_item = palloc(p, *decoded_len + 1);
  memcpy(decoded_item, ptr, *decoded_len);
  decoded_item[*decoded_len] = '\0';
  curl_free(ptr);

  return decoded_item;
}

const char *aws_http_urlencode(pool *p, void *http, const char *item,
    size_t item_len) {
  CURL *curl;
  char *encoded_item, *ptr;
  size_t encoded_len;

  curl = http;
  ptr = curl_easy_escape(curl, item, (int) item_len);
  if (ptr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  encoded_len = strlen(ptr);
  encoded_item = palloc(p, encoded_len + 1);
  memcpy(encoded_item, ptr, encoded_len);
  encoded_item[encoded_len] = '\0';
  curl_free(ptr);

  pr_trace_msg(trace_channel, 15,
    "'%s' URL-encoded as '%s'", item, encoded_item);
  return encoded_item;
}

static void clear_http_response(void) {
  if (http_resp_pool != NULL) {
    destroy_pool(http_resp_pool);
    http_resp_pool = NULL;
  }
  http_resp_msg = NULL;
}

int aws_http_get(pool *p, void *http, const char *url, pr_table_t *headers,
    size_t (*resp_body)(char *, size_t, size_t, void *), void *user_data,
    long *resp_code, const char **content_type) {
  CURL *curl;
  CURLcode curl_code;
  struct curl_slist *slist = NULL;
  double content_len, rcvd_bytes, total_secs;

  curl = http;

  curl_code = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HTTPGET: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_URL, url);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_URL '%s': %s", url, curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_body);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_WRITEFUNCTION: %s", curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_WRITEDATA, user_data);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_WRITEDATA: %s", curl_easy_strerror(curl_code));
    errno = EINVAL;
    return -1;
  }

  if (headers != NULL) {
    register unsigned int i;
    array_header *http_headers;
    char **elts;

    http_headers = aws_utils_table2array(p, headers);

    elts = http_headers->elts;
    for (i = 0; i < http_headers->nelts; i++) {
      slist = curl_slist_append(slist, elts[i]);
    }

    curl_code = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    if (curl_code != CURLE_OK) {
      pr_trace_msg(trace_channel, 1,
        "error setting CURLOPT_HTTPHEADER: %s",
        curl_easy_strerror(curl_code));
    }
  }

  /* Clear error buffer, response message before performing request,
   * per docs.
   */
  curl_errorbuf[0] = '\0';
  clear_http_response();
  http_resp_pool = make_sub_pool(p);

  curl_code = curl_easy_perform(curl);

  if (slist != NULL) {
    curl_slist_free_all(slist);
  }

  if (curl_code != CURLE_OK) {
    size_t error_len;
    int xerrno = EPERM;

    error_len = strlen(curl_errorbuf);
    if (error_len > 0) {
      pr_trace_msg(trace_channel, 1,
        "'%s' request error: %s", url, curl_errorbuf);

      /* Note: What other error strings should we search for here? */
      if (strstr(curl_errorbuf, "Could not resolve host") != NULL) {
        xerrno = ESRCH;

      } else if (strstr(curl_errorbuf, "Connection timed out") != NULL) {
        /* Hit our AWSTimeoutConnect? */
        xerrno = ETIMEDOUT;

      } else {
        /* Generic error */
        xerrno = EPERM;
      }

    } else {
      pr_trace_msg(trace_channel, 1,
        "'%s' request error: %s", url, curl_easy_strerror(curl_code));
      xerrno = EPERM;
    }

    clear_http_response();

    errno = xerrno;
    return -1;
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, resp_code);
  if (curl_code == CURLE_UNKNOWN_OPTION) {
    /* Use the older option name. */
    curl_code = curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, resp_code);
  }

  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 2,
      "unable to get '%s' response code: %s", url,
      curl_easy_strerror(curl_code));

    clear_http_response();

    errno = EPERM;
    return -1;
  }

  if (http_resp_msg != NULL) {
    pr_trace_msg(trace_channel, 15,
      "received response '%ld %s' for '%s' request", *resp_code,
      http_resp_msg, url);

  } else {
    pr_trace_msg(trace_channel, 15,
      "received response code %ld for '%s' request", *resp_code, url);
  }

  clear_http_response();

  curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
    &content_len);
  if (curl_code == CURLE_OK) {
    if (content_len > 0) {
      pr_trace_msg(trace_channel, 15,
        "received Content-Length %0.0lf for '%s' request", content_len, url);
    }

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_CONTENT_LENGTH_DOWNLOAD: %s",
      curl_easy_strerror(curl_code));
  }

  if (content_type != NULL) {
    curl_code = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, content_type);
    if (curl_code == CURLE_OK) {
      if (*content_type != NULL) {
        pr_trace_msg(trace_channel, 15,
          "received Content-Type '%s' for '%s' request", *content_type, url);
      }

    } else {
      pr_trace_msg(trace_channel, 3,
        "unable to get CURLINFO_CONTENT_TYPE: %s",
        curl_easy_strerror(curl_code));
    }
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_secs);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "'%s' request took %0.3lf secs", url, total_secs);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_TOTAL_TIME: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &rcvd_bytes);
  if (curl_code == CURLE_OK) {
    pr_trace_msg(trace_channel, 15,
      "received %0.0lf bytes for '%s' request", rcvd_bytes, url);

  } else {
    pr_trace_msg(trace_channel, 3,
      "unable to get CURLINFO_SIZE_DOWNLOAD: %s",
      curl_easy_strerror(curl_code));
  }

  return 0;
}

static size_t http_header_cb(char *data, size_t itemsz, size_t item_count,
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
    char *resp_msg;
    size_t resp_msglen;

    /* We're receiving the HTTP response status line. */

    /* Advance the pointer past "HTTP/1.x NNNN "(13). And take back 2,
     * for whose CRLF this line is.
     */
    resp_msg = data + 13;
    resp_msglen = datasz - 13 - 2;

    http_resp_msg = pstrndup(http_resp_pool, resp_msg, resp_msglen);
  }

  return datasz;
}

static int http_trace_cb(CURL *curl, curl_infotype data_type, char *data,
    size_t datasz, void *user_data) {

  /* Tell the compiler we won't be using this argument. */
  (void) curl;

  switch (data_type) {
    case CURLINFO_TEXT:
      pr_trace_msg(trace_channel, 15, "[debug] INFO: %s", data);
      break;

    case CURLINFO_HEADER_IN:
      /* Note: You MAY sometimes see AWS send the following response header:
       *
       *   nnCoection: close
       *
       * This is a deliberate hack, albeit ugly.  See:
       *   https://forums.aws.amazon.com/message.jspa?messageID=81954
       */

      if (datasz > 2) {
        pr_trace_msg(trace_channel, 15,
          "[debug] HEADER IN: %.*s (%ld bytes)", (int) datasz-2, data, datasz);
      }
      break;

    case CURLINFO_HEADER_OUT:
      if (datasz > 2) {
        pr_trace_msg(trace_channel, 15,
          "[debug] HEADER OUT: %.*s (%ld bytes)", (int) datasz-2, data, datasz);
      }
      break;

    case CURLINFO_DATA_IN:
      pr_trace_msg(trace_channel, 19,
        "[debug] DATA IN: (%ld bytes)", datasz);
      break;

    case CURLINFO_DATA_OUT:
      pr_trace_msg(trace_channel, 19,
        "[debug] DATA OUT: (%ld bytes)", datasz);
      break;

    case CURLINFO_SSL_DATA_IN:
      pr_trace_msg(trace_channel, 19,
        "[debug] SSL DATA IN: (%ld bytes)", datasz);
      break;

    case CURLINFO_SSL_DATA_OUT:
      pr_trace_msg(trace_channel, 19,
        "[debug] SSL DATA OUT: (%ld bytes)", datasz);
      break;

    default:
      pr_trace_msg(trace_channel, 3,
        "[debug] UNKNOWN DEBUG DATA: %d", (int) data_type);
      break;
  }

  return 0;
}

void *aws_http_alloc(pool *p, unsigned long max_connect_secs,
    unsigned long max_request_secs, const char *cacerts) {
  CURL *curl;
  CURLcode curl_code;

  curl = curl_easy_init();
  if (curl == NULL) {
    pr_trace_msg(trace_channel, 3, "error initializing curl easy handle");
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

  curl_code = curl_easy_setopt(curl, CURLOPT_SHARE, curl_share);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_SHARE: %s", curl_easy_strerror(curl_code));
  }

  /* HTTP-isms. */
  curl_code = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
    CURL_HTTP_VERSION_1_1);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_HTTP_VERSION: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_USERAGENT, MOD_AWS_VERSION);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_USERAGENT: %s",
      curl_easy_strerror(curl_code));
  }

  /* SSL-isms. */

  if (cacerts != NULL) {
    curl_code = curl_easy_setopt(curl, CURLOPT_CAINFO, cacerts);
    if (curl_code != CURLE_OK) {
      pr_trace_msg(trace_channel, 1,
        "error setting CURLOPT_CAINFO: %s", curl_easy_strerror(curl_code));
    }

    curl_code = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    if (curl_code != CURLE_OK) {
      pr_trace_msg(trace_channel, 1,
        "error setting CURLOPT_SSL_VERIFYPEER: %s",
        curl_easy_strerror(curl_code));
    }

    curl_code = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (curl_code != CURLE_OK) {
      pr_trace_msg(trace_channel, 1,
        "error setting CURLOPT_SSL_VERIFYHOST: %s",
        curl_easy_strerror(curl_code));
    }

    /* XXX Ideally we'd also set CURLOPT_SSL_VERIFYSTATUS, but we don't know
     * if AWS is supporting OCSP stapling.
     *
     * Right now (2016-02-28), using:
     *
     *   `openssl s_client -connect ec2.amazonaws.com:443 -status`
     *
     * shows that AWS does NOT provide a stapled OCSP response.
     */
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, http_header_cb);
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

  curl_code = curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, http_trace_cb);
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

  /* Timeouts */
  curl_code = curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
    (long) max_connect_secs);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_CONNECTTIMEOUT: %s",
      curl_easy_strerror(curl_code));
  }

  curl_code = curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) max_request_secs);
  if (curl_code != CURLE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURLOPT_TIMEOUT: %s",
      curl_easy_strerror(curl_code));
  }

  return curl;
}

int aws_http_destroy(pool *p, void *http) {
  CURL *curl;

  (void) p;
  curl = http;

  if (curl != NULL) {
    CURLcode curl_code;

    curl_code = curl_easy_setopt(curl, CURLOPT_SHARE, NULL);
    if (curl_code != CURLE_OK) {
      pr_trace_msg(trace_channel, 1,
        "error removing CURLOPT_SHARE: %s", curl_easy_strerror(curl_code));
    }

    curl_easy_cleanup(curl);
  }

  return 0;
}

int aws_http_init(pool *p, unsigned long *feature_flags,
    const char **http_details) {
  CURLcode curl_code;
  CURLSHcode share_code;
  long curl_flags = CURL_GLOBAL_ALL;

  (void) p;

#ifdef CURL_GLOBAL_ACK_EINTR
  curl_flags |= CURL_GLOBAL_ACK_EINTR;
#endif /* CURL_GLOBAL_ACK_EINTR */
  curl_code = curl_global_init(curl_flags);
  if (curl_code != CURLE_OK) {
    if (http_details != NULL) {
      *http_details = curl_easy_strerror(curl_code);
    }

    errno = EPERM;
    return -1;
  }

  curl_share = curl_share_init();
  if (curl_share == NULL) {
    errno = ENOMEM;
    return -1;
  }

  share_code = curl_share_setopt(curl_share, CURLSHOPT_SHARE,
    CURL_LOCK_DATA_COOKIE);
  if (curl_code != CURLSHE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURL_LOCK_DATA_COOKIE: %s",
      curl_share_strerror(share_code));
  }

  share_code = curl_share_setopt(curl_share, CURLSHOPT_SHARE,
    CURL_LOCK_DATA_DNS);
  if (curl_code != CURLSHE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURL_LOCK_DATA_DNS: %s", curl_share_strerror(share_code));
  }

  share_code = curl_share_setopt(curl_share, CURLSHOPT_SHARE,
    CURL_LOCK_DATA_SSL_SESSION);
  if (curl_code != CURLSHE_OK) {
    pr_trace_msg(trace_channel, 1,
      "error setting CURL_LOCK_DATA_SSL_SESSION: %s",
      curl_share_strerror(share_code));
  }

  if (feature_flags != NULL) {
    curl_version_info_data *curl_info;

    curl_info = curl_version_info(CURLVERSION_NOW);
    if (curl_info != NULL) {
      pr_log_debug(DEBUG5, MOD_AWS_VERSION
        ": libcurl version: %s", curl_info->version);

      if (!(curl_info->features & CURL_VERSION_SSL)) {
        pr_log_pri(PR_LOG_INFO, MOD_AWS_VERSION
          ": libcurl compiled without SSL support, disabling mod_aws");
        *feature_flags |= AWS_FL_CURL_NO_SSL;

      } else {
        pr_log_debug(DEBUG5, MOD_AWS_VERSION
          ": libcurl compiled using OpenSSL version: %s",
          curl_info->ssl_version);
      }
    }
  }

  return 0;
}

int aws_http_free(void) {
  if (curl_share != NULL) {
    curl_share_cleanup(curl_share);
    curl_share = NULL;
  }

  curl_global_cleanup();
  return 0;
}
