/*
 * ProFTPD - mod_aws AWS credentials
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
#include "creds.h"
#include "utils.h"

static const char *trace_channel = "aws.creds";

int aws_creds_from_env(pool *p, char **access_key_id,
    char **secret_access_key) {
  const char *k, *id, *secret;

  if (p == NULL ||
      access_key_id == NULL ||
      secret_access_key == NULL) {
    errno = EINVAL;
    return -1;
  }

  k = "AWS_ACCESS_KEY_ID";
  id = pr_env_get(p, k);
  if (id == NULL) {
    pr_trace_msg(trace_channel, 14, "no %s environ variable found", k);
    errno = ENOENT;
    return -1;
  }

  k = "AWS_SECRET_ACCESS_KEY";
  secret = pr_env_get(p, k);
  if (secret == NULL) {
    pr_trace_msg(trace_channel, 14, "no %s environ variable found", k);
    errno = ENOENT;
    return -1;
  }

  *access_key_id = pstrdup(p, id);
  *secret_access_key = pstrdup(p, secret);

  return 0;
}

static char *creds_next_line(pr_fh_t *fh, char *line, size_t linesz,
    unsigned int *lineno, size_t *linelen) {

  while (pr_fsio_getline(line, linesz, fh, lineno) != NULL) {
    size_t len;
    char *ptr;

    pr_signals_handle();

    len = strlen(line);

    /* Trim off the trailing newline, if present. */
    if (len > 0 &&
        line[len-1] == '\n') {
      line[len-1] = '\0';
      len--;
    }

    if (len > 0 &&
        line[len-1] == '\r') {
      line[len-1] = '\0';
      len--;
    }

    /* Advance past any leading whitespace. */
    for (ptr = line; *ptr && PR_ISSPACE(*ptr); ptr++);

    /* Check for commented or blank lines. */
    if (*ptr == '#' || !*ptr) {
      continue;
    }

    /* XXX Trim trailing comments. */

    *linelen = len;
    return ptr;
  }

  return NULL;
}

static int creds_parse_prop(pool *p, char *prop, size_t propsz,
    char **prop_name, size_t *prop_namesz,
    char **prop_val, size_t *prop_valsz) {
  char *ptr;
  size_t sz;

  ptr = memchr(prop, '=', propsz);
  if (ptr == NULL) {
    pr_trace_msg(trace_channel, 8, "badly formatted property '%.*s'",
      (int) propsz, prop);
    errno = EINVAL;
    return -1;
  }

  sz = ptr - prop;
  *prop_name = aws_utils_strn_trim(p, prop, sz);
  *prop_namesz = strlen(*prop_name);

  sz = propsz - sz - 1;
  *prop_val = aws_utils_strn_trim(p, ptr + 1, sz);
  *prop_valsz = strlen(*prop_val);

  return 0;
}

static int creds_from_props(pool *p, pr_fh_t *fh, char **access_key_id,
    char **secret_access_key) {
  size_t bufsz, linelen;
  char *buf, *line;
  unsigned int lineno = 0;

  bufsz = PR_TUNABLE_PARSER_BUFFER_SIZE;
  buf = pcalloc(p, bufsz+1);

  *access_key_id = *secret_access_key = NULL;

  line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
  while (line != NULL) {
    char *name, *val;
    size_t namesz, valsz;

    pr_signals_handle();

    if (creds_parse_prop(p, line, linelen, &name, &namesz, &val, &valsz) < 0) {
      /* Ignore malformed lines. */
      line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
      continue;
    }

    if (namesz == 9) {
      if (strncmp(name, "accessKey", 10) == 0) {
        *access_key_id = val;

      } else if (strncmp(name, "secretKey", 10) == 0) {
        *secret_access_key = val;
      }
    }

    if (*access_key_id != NULL &&
        *secret_access_key != NULL) {
      return 0;
    }

    line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
  }

  errno = ENOENT;
  return -1;
}

static int creds_from_profile_props(pool *p, pr_fh_t *fh, const char *profile,
    char **access_key_id, char **secret_access_key) {

  /* Read each line. */
  /* Ignore empty lines, comments. */
  /* Trim trailing comments. */

  /* Parse line into section name. */
  /* If section name matches profile name, read next lines as key/value. */
  /* If seciton name not matches profile, read next lines as sections. */

  /* Parse line into key, value strings. */
  /* If key is "accessKey", populate access_key_id. */
  /* If key is "secretKey", populate secret_access_key. */
  /* If both values are provisioned, we're done.  Otherwise, ENOENT. */

  errno = ENOSYS;
  return -1;
}

int aws_creds_from_file(pool *p, const char *path, const char *profile,
    char **access_key_id, char **secret_access_key) {
  int res, xerrno;
  char *id, *key;
  pr_fh_t *fh;
  struct stat st;
  pool *sub_pool;

  if (p == NULL ||
      path == NULL ||
      access_key_id == NULL ||
      secret_access_key == NULL) {
    errno = EINVAL;
    return -1;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "AWS file credentials pool");

  fh = pr_fsio_open(path, O_RDONLY);
  if (fh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 9,  "unable to read credentials from '%s': %s",
      path, strerror(xerrno));

    destroy_pool(sub_pool);
    errno = xerrno;
    return -1;
  }

  if (pr_fsio_fstat(fh, &st) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 9,  "fstat(2) error on '%s': %s",
      path, strerror(xerrno));

    (void) pr_fsio_close(fh);
    destroy_pool(sub_pool);
    errno = xerrno;
    return -1;
  }

  fh->fh_iosz = st.st_blksize;

  /* Advise the platform that we will be only reading this file
   * sequentially.
   */
  pr_fs_fadvise(PR_FH_FD(fh), 0, 0, PR_FS_FADVISE_SEQUENTIAL);

  id = key = NULL;

  if (profile != NULL) {
    res = creds_from_profile_props(sub_pool, fh, profile, &id, &key);

  } else {
    res = creds_from_props(sub_pool, fh, &id, &key);
  }

  xerrno = errno;

  if (res == 0) {
    *access_key_id = pstrdup(p, id);
    *secret_access_key = pstrdup(p, key);
  }

  (void) pr_fsio_close(fh);
  destroy_pool(sub_pool);

  errno = xerrno;
  return res;
}

int aws_creds_from_sql(pool *p, const char *query, char **access_key_id,
    char **secret_access_key) {
  if (p == NULL ||
      query == NULL ||
      access_key_id == NULL ||
      secret_access_key == NULL) {
    return -1;
  }

  errno = ENOSYS;
  return -1;
}