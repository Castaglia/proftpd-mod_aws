/*
 * ProFTPD - mod_aws Health API
 * Copyright (c) 2016-2023 TJ Saunders
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
#include "health.h"
#include "http.h"

/* Note: Per the AWS Route53 docs:
 *
 *  "... must be able to establish a TCP connection with the endpoint within four seconds. In addition, the endpoint must respond with an HTTP status code of 200 or greater and less than 400 within two seconds after connecting."
 *
 * This means that the `freq' argument ideally should NOT be exposed, and
 * perhaps should be hardcoded to 1 second.
 *
 * See:
 *   http://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-failover-determining-health-of-endpoints.html
 */
#define AWS_HEALTH_DEFAULT_INTERVAL		1

/* The maximum length, per line, of an HTTP request that we support. */
#define AWS_HEALTH_HTTP_REQ_BUFSZ		1024

/* The buffer size for formatting HTTP dates. */
#define AWS_HEALTH_HTTP_DATE_BUFSZ		512

/* Right now, we only allow for a SINGLE health listener.  Note that we use
 * this static variable for handling the callback where we check for any
 * connections to accept.
 *
 * In the future, that may need to change.  And due to the Timer API's callback
 * data, we need to keep the handles around in an accessible way.  In that
 * future case, this could be a table, whose keys are the timernos and the
 * values are the associated handle.
 */
static struct aws_health *health_listener = NULL;

/* TODO: Get the list of allowed IP ranges, used by AWS Route53, and only allow
 * requests from those ranges.  See:
 *
 *  http://docs.aws.amazon.com/Route53/latest/APIReference/API_GetCheckerIpRanges.html
 *
 * In addition, double-check that the instance security groups allow ingress
 * access from ALL of these ranges!
 */

static const char *trace_channel = "aws.health";

static int health_allowed_conn(pool *p, conn_t *conn, array_header *acls) {
  register unsigned int i;
  pr_netacl_t **elts;

  if (acls == NULL) {
    return 0;
  }

  elts = acls->elts;
  for (i = 0; i < acls->nelts; i++) {
    pr_netacl_t *acl;

    acl = elts[i];
    if (pr_netacl_match(acl, conn->remote_addr) == 1) {
      pr_trace_msg(trace_channel, 18,
        "connection from %s allowed by ACL %s",
        pr_netaddr_get_ipstr(conn->remote_addr), pr_netacl_get_str(p, acl));
      return 0;
    }
  }

  errno = EACCES;
  return -1;
}

static const char *health_read_request(pool *p, conn_t *conn) {
  char *buf, *req_line;
  size_t bufsz;
  int len, xerrno = 0;

  bufsz = AWS_HEALTH_HTTP_REQ_BUFSZ;
  buf = palloc(p, bufsz);

  /* By explicitly setting the poll interval to zero here, we do a "true"
   * polling of the input stream: either there are bytes to be consumed
   * (i.e. a legitimate HTTP request), or there are not (i.e. telnet/netcat).
   * If there are no bytes, we Do The Right Thing and move on (Issue #45).
   */
  pr_netio_set_poll_interval(conn->instrm, 0);

  /* Read in the first line, which should be our request line.
   *
   * Note that pr_netio_telnet_gets2() converts CRLF terminators to just
   * LF terminators.
   */
  len = pr_netio_telnet_gets2(buf, bufsz, conn->instrm, conn->outstrm);
  if (len < 0) {
    if (errno == E2BIG) {
      xerrno = errno;

      /* Client sent a request line that was too long. */
      pr_trace_msg(trace_channel, 6,
        "client sent too-long request line, closing connection");

    } else {
      if (conn->instrm->strm_errno == 0) {
        pr_trace_msg(trace_channel, 6,
          "client sent EOF, closing connection");
        xerrno = EINVAL;

      } else {
        xerrno = errno;
      }
    }

    errno = xerrno;
    return NULL;
  }

  pr_trace_msg(trace_channel, 15, "read HTTP request line: '%.*s'", len-1, buf);
  req_line = pstrndup(p, buf, len-1);

  /* Now read in all the remaining data (the headers), for logging. */
  len = pr_netio_telnet_gets2(buf, bufsz, conn->instrm, conn->outstrm);
  while (len > 0) {
    pr_signals_handle();

    if (len == 1 &&
        strcmp(buf, "\n") == 0) {
      /* End of headers.  We don't care about any content-bearing requests. */
      break;
    }

    pr_trace_msg(trace_channel, 19,
      "received request header: '%.*s'", len-1, buf);

    len = pr_netio_telnet_gets2(buf, bufsz, conn->instrm, conn->outstrm);
  }

  if (pr_netio_shutdown(conn->instrm, SHUT_RD) < 0) {
    pr_trace_msg(trace_channel, 4,
      "error setting read shutdown: %s", strerror(errno));
  }

  return req_line;
}

static const char *health_fmt_http_date(pool *p, time_t resp_time) {
  char *http_date;
  size_t http_datesz;
  struct tm *gmt_tm;

  gmt_tm = pr_gmtime(p, &resp_time);
  if (gmt_tm == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error obtaining gmtime: %s", strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  http_datesz = AWS_HEALTH_HTTP_DATE_BUFSZ;
  http_date = pcalloc(p, http_datesz);
  (void) strftime(http_date, http_datesz, "%a, %d %b %Y %H:%M:%S GMT", gmt_tm);

  return http_date;
}

static int health_write_response(pool *p, conn_t *conn,
    const char *http_version, long resp_code) {
  int res, xerrno = 0;
  time_t resp_time;
  char *resp = NULL;
  size_t resplen;
  const char *http_date;

  switch (resp_code) {
    case AWS_HTTP_RESPONSE_CODE_OK:
      resp = pstrcat(p, "HTTP/", http_version, " 200 OK\r\n", NULL);
      break;

    case AWS_HTTP_RESPONSE_CODE_BAD_REQUEST:
      resp = pstrcat(p, "HTTP/", http_version, " 400 Bad Request\r\n", NULL);
      break;

    case AWS_HTTP_RESPONSE_CODE_NOT_FOUND:
      resp = pstrcat(p, "HTTP/", http_version, " 404 Not Found\r\n", NULL);
      break;

    case AWS_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR:
      resp = pstrcat(p, "HTTP/", http_version,
        " 500 Internal Server Error\r\n", NULL);
      break;

    default:
     pr_trace_msg(trace_channel, 3,
       "unknown/unimplemented response code %ld", resp_code);
     errno = EINVAL;
     return -1;
  }

  time(&resp_time);

  resp = pstrcat(p, resp,
    AWS_HTTP_HEADER_CONNECTION, ": close\r\n",
    AWS_HTTP_HEADER_CONTENT_LEN, ": 0\r\n",
    AWS_HTTP_HEADER_CACHE_CONTROL, ": private, no-cache, no-store\r\n",
    NULL);

  http_date = health_fmt_http_date(p, resp_time);
  if (http_date != NULL) {
    resp = pstrcat(p, resp,
      AWS_HTTP_HEADER_DATE, ": ", http_date, "\r\n",
      AWS_HTTP_HEADER_EXPIRES, ": ", http_date, "\r\n",
      AWS_HTTP_HEADER_LAST_MODIFIED, ": ", http_date, "\r\n",
      NULL);
  }

  /* Don't forget the end-of-headers sentinel */
  resp = pstrcat(p, resp, "\r\n", NULL);

  resplen = strlen(resp);
  res = pr_netio_write(conn->outstrm, resp, resplen);
  xerrno = errno;

  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error writing response (%lu bytes): %s", (unsigned long) resplen,
      strerror(xerrno));
  }

  if (pr_netio_shutdown(conn->outstrm, SHUT_WR) < 0) {
    pr_trace_msg(trace_channel, 4,
      "error setting write shutdown: %s", strerror(errno));
  }

  errno = xerrno;
  return res;
}

static long health_check_request(pool *p, struct aws_health *health,
    const char *req_line, char **http_version) {
  long resp_code = AWS_HTTP_RESPONSE_CODE_INTERNAL_SERVER_ERROR;
  const char *ptr;
  size_t req_linelen;

  ptr = req_line;
  if (strncmp(ptr, "GET ", 4) != 0) {
    resp_code = AWS_HTTP_RESPONSE_CODE_BAD_REQUEST;
    pr_trace_msg(trace_channel, 4,
      "unsupported HTTP method, returning %ld for '%s'", resp_code, req_line);

  } else {

    /* Advance past the method. */
    ptr += 4;

    if (strncmp(ptr, health->uri, health->urisz) == 0) {
      resp_code = AWS_HTTP_RESPONSE_CODE_OK;

    } else {
      resp_code = AWS_HTTP_RESPONSE_CODE_NOT_FOUND;
      pr_trace_msg(trace_channel, 4,
        "unknown URI requested, returning %ld for '%s'", resp_code, req_line);
    }
  }

  req_linelen = strlen(req_line);
  if (pr_strnrstr(req_line, req_linelen, "1.1", 3, 0) == TRUE) {
    *http_version = "1.1";

  } else if (pr_strnrstr(req_line, req_linelen, "1.0", 3, 0) == TRUE) {
    *http_version = "1.0";

  } else {
    pr_trace_msg(trace_channel, 8,
      "unknown/unsupported HTTP version requested: %s", req_line);
  }

  return resp_code;
}

static void health_handle_ping(pool *p, struct aws_health *health,
    conn_t *conn) {
  int res;
  char *http_version;
  const char *req_line;
  long resp_code;

  /* Check the remote IP address against our ACL whitelist. */
  pr_trace_msg(trace_channel, 21, "%s",
    "checking healthcheck connection against ACLs");
  res = health_allowed_conn(p, conn, health->acls);
  if (res < 0) {
    pr_trace_msg(trace_channel, 5,
      "connection from %s not allowed by ACLs, closing connection",
      pr_netaddr_get_ipstr(conn->remote_addr));
    return;
  }

  pr_trace_msg(trace_channel, 21, "%s", "reading healthcheck HTTP request");
  req_line = health_read_request(p, conn);
  if (req_line == NULL) {
    pr_trace_msg(trace_channel, 5,
      "error reading HTTP request from %s, closing connection",
      pr_netaddr_get_ipstr(conn->remote_addr));
    return;
  }

  /* Assume HTTP 1.1, for now. */
  http_version = "1.1";
  resp_code = health_check_request(p, health, req_line, &http_version);

  pr_trace_msg(trace_channel, 21, "%s", "writing healthcheck HTTP response");
  res = health_write_response(p, conn, http_version, resp_code);
  if (res < 0) {
    pr_trace_msg(trace_channel, 5,
      "error writing HTTP response to %s: %s",
      pr_netaddr_get_ipstr(conn->remote_addr), strerror(errno));
  }
}

static conn_t *health_accept_conn(pool *p, conn_t *listener) {
  conn_t *conn;
  int fd;

  fd = pr_inet_accept_nowait(p, listener);
  if (fd < 0) {
    if (errno != EAGAIN) {
      pr_trace_msg(trace_channel, 19,
        "unable to accept incoming connection: %s", strerror(errno));
    }

    errno = ENOENT;
    return NULL;
  }

  conn = pr_inet_openrw(p, listener, NULL, PR_NETIO_STRM_OTHR, fd, -1, -1,
    FALSE);
  return conn;
}

static void health_close_conn(conn_t *conn) {
  if (conn->instrm != NULL) {
    pr_netio_stream_t *nstrm;

    nstrm = conn->instrm;
    conn->instrm = NULL;
    pr_netio_close(nstrm);
  }

  if (conn->outstrm != NULL) {
    pr_netio_stream_t *nstrm;

    nstrm = conn->outstrm;
    conn->outstrm = NULL;
    pr_netio_close(nstrm);
  }

  if (conn->listen_fd != -1) {
    (void) close(conn->listen_fd);
    conn->listen_fd = -1;
  }

  if (conn->rfd != -1) {
    (void) close(conn->rfd);
    conn->rfd = -1;
  }

  if (conn->wfd != -1) {
    (void) close(conn->wfd);
    conn->wfd = -1;
  }
}

static int health_ping_cb(CALLBACK_FRAME) {
  conn_t *conn;
  struct aws_health *health;
  pool *tmp_pool;
  uint64_t start_ms = 0, end_ms = 0;

  health = health_listener;

  /* Note that we deliberately do NOT use any pool that might be
   * destroyed/recreated during a restart.  Why?  We could be reading in
   * the HTTP request line when a SIGHUP occurs, which then would trigger
   * mod_aws' restart event listener.  And that listener might destroy,
   * re-create pools, whose dependents are resources that we are currently
   * using.  We would find ourselves using stale (or null) pointers, and
   * thus segfaulting (Issue #41).
   */
  tmp_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(tmp_pool, "AWS Health Request Pool");

  pr_trace_msg(trace_channel, 21, "%s", "accepting healthcheck connection");
  conn = health_accept_conn(tmp_pool, health->conn);
  if (conn == NULL) {
    if (errno == ENOENT) {
      pr_trace_msg(trace_channel, 19, "no pending requests to handle");

    } else {
      pr_trace_msg(trace_channel, 3, "error accepting request: %s",
        strerror(errno));
    }

    destroy_pool(tmp_pool);
    return 1;
  }

  pr_gettimeofday_millis(&start_ms);
  health_handle_ping(tmp_pool, health, conn);
  pr_gettimeofday_millis(&end_ms);

  pr_trace_msg(trace_channel, 12, "response time: %lu ms",
    (unsigned long) (end_ms - start_ms));

  /* Note that while we might want to call pr_inet_close() here, doing so
   * causes problems.  So we manually close the connection ourselves.
   */
  health_close_conn(conn);

  destroy_pool(tmp_pool);

  /* Always restart the timer. */
  return 1;
}

static conn_t *health_make_listener(pool *p, const pr_netaddr_t *addr,
    int port) {
  int res;
  conn_t *conn;

  conn = pr_inet_create_conn(p, -1, addr, port, FALSE);
  if (conn == NULL) {
    int xerrno = errno;

    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "error creating listener for %s#%d: %s", pr_netaddr_get_ipstr(addr), port,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  /* Make sure our listening fd is not one of the Big Three.  Doing so now
   * will make problems later (see Issue #34).
   */
  if (pr_fs_get_usable_fd2(&(conn->listen_fd)) < 0) {
    return NULL;
  }

  res = pr_inet_listen(p, conn, 5, 0);
  if (res < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "error listening on %s#%d: %s", pr_netaddr_get_ipstr(addr), port,
      strerror(xerrno));

    errno = xerrno;
    return NULL;
  }

  res = pr_inet_set_nonblock(p, conn);
  if (res < 0) {
    pr_trace_msg(trace_channel, 3,
      "error making %s#%d socket non-blocking: %s", pr_netaddr_get_ipstr(addr),
      port, strerror(errno));
  }

  return conn;
}

struct aws_health *aws_health_listener_create(pool *p,
    const char *addr, int port, const char *uri, int freq, array_header *acls) {
  pool *health_pool;
  struct aws_health *health;

  health_pool = make_sub_pool(p);
  pr_pool_tag(health_pool, "AWS Health Listener Pool");

  health = pcalloc(health_pool, sizeof(struct aws_health));
  health->pool = health_pool;

  health->addr = pr_netaddr_get_addr(health->pool, addr, NULL);
  if (health->addr == NULL) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 3,
      "error obtaining address for '%s': %s", addr, strerror(xerrno));

    destroy_pool(health->pool);
    errno = xerrno;
    return NULL;
  }

  health->port = port;
  health->uri = pstrdup(health->pool, uri);
  health->urisz = strlen(uri);
  health->acls = acls;

  health->conn = health_make_listener(health->pool, health->addr, health->port);
  if (health->conn == NULL) {
    int xerrno = errno;

    destroy_pool(health->pool);
    errno = xerrno;
    return NULL;
  }

  if (freq < 0) {
    freq = AWS_HEALTH_DEFAULT_INTERVAL;
  }

  health->timerno = pr_timer_add(freq, -1, &aws_module, health_ping_cb,
    "AWS Health Request Handling");
  if (health->timerno < 0) {
    int xerrno = errno;

    pr_trace_msg(trace_channel, 1,
      "error adding health request handling timer (%d secs): %s", freq,
      strerror(xerrno));

    /* Since this timer is crucial to the AWSHealthCheck functionality,
     * failure to register a timer means our listener will not work as needed.
     */
    pr_inet_close(health->pool, health->conn);
    health->conn = NULL;
    destroy_pool(health->pool);

    errno = xerrno;
    return NULL;
  }

  health_listener = health;
  return health;
}

int aws_health_listener_destroy(pool *p, struct aws_health *health) {
  int res;

  res = pr_timer_remove(health->timerno, &aws_module);
  if (res < 0 &&
      errno != ENOENT) {
    pr_trace_msg(trace_channel, 3,
      "error removing timer ID %d: %s", health->timerno, strerror(errno));
  }

  if (health->conn != NULL) {
    pr_inet_close(health->pool, health->conn);
    health->conn = NULL;
  }
  destroy_pool(health->pool);
  health_listener = NULL;

  return 0;
}
