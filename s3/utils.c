/*
 * ProFTPD - mod_aws S3 Utilities API
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
#include "utils.h"

static const char *trace_channel = "aws.s3.utils";

time_t aws_s3_utils_lastmod2unix(pool *p, const char *last_modified) {
  struct tm *tm;
  time_t date;
  char *ptr;

  if (p == NULL ||
      last_modified == NULL) {
    errno = EINVAL;
    return 0;
  }

  tm = pcalloc(p, sizeof(struct tm));

  ptr = strptime(last_modified, "%Y-%m-%dT%H:%M:%S", tm);
  if (ptr == NULL) {
    int xerrno = errno;

    /* Should we try to handle "%a, %d %b %Y %H:%M:%S %Z" here as a fallback?
     * It would make for a more useful function.
     */
    pr_trace_msg(trace_channel, 3,
      "unable to parse LastModified date '%s': %s", last_modified,
      strerror(xerrno));

    errno = xerrno;
    return 0;
  }

  /* XXX Beware that mktime(3) has the same TZ-sensitive as other time-related
   * library functions.  If we ASSUME that this function will only EVER be
   * called after authentication, e.g. post-chroot, then it SHOULD be safe.
   */
  date = mktime(tm);

  pr_trace_msg(trace_channel, 17,
    "parsed LastModified date '%s' as Unix epoch %lu", last_modified,
    (unsigned long) date);
  return date;
}

const char *aws_s3_utils_unix2lastmod(pool *p, time_t date) {
  const char *last_modified;
  struct tm *tm;
  char buf[256];

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  tm = pr_gmtime(NULL, &date);

  memset(buf, '\0', sizeof(buf));
  strftime(buf, sizeof(buf)-1, "%Y-%m-%dT%H:%M:%S", tm);
  last_modified = pstrdup(p, buf);

  pr_trace_msg(trace_channel, 17,
    "parsed Unix epoch %lu as LastModified date '%s'", (unsigned long) date,
    last_modified);
  return last_modified;
}
