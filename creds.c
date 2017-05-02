/*
 * ProFTPD - mod_aws AWS credentials
 * Copyright (c) 2016-2017 TJ Saunders
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
#include "http.h"
#include "json.h"
#include "utils.h"

static const char *trace_channel = "aws.creds";

int aws_creds_from_env(pool *p, struct aws_credentials **creds) {
  const char *k, *id, *secret, *token;

  if (p == NULL ||
      creds == NULL) {
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

  *creds = pcalloc(p, sizeof(struct aws_credentials));
  (*creds)->access_key_id = pstrdup(p, id);
  (*creds)->secret_access_key = pstrdup(p, secret);

  k = "AWS_SESSION_TOKEN";
  token = pr_env_get(p, k);
  if (token != NULL) {
    (*creds)->session_token = pstrdup(p, token);
  }

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

static int creds_parse_prop(pool *p, char *line, size_t linesz,
    char **prop_name, size_t *prop_namesz,
    char **prop_val, size_t *prop_valsz) {
  char *ptr;
  size_t sz;

  ptr = memchr(line, '=', linesz);
  if (ptr == NULL) {
    pr_trace_msg(trace_channel, 11, "badly formatted property '%.*s'",
      (int) linesz, line);
    errno = EINVAL;
    return -1;
  }

  sz = ptr - line;
  *prop_name = aws_utils_strn_trim(p, line, sz);
  *prop_namesz = strlen(*prop_name);

  sz = linesz - sz - 1;
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

    pr_memscrub(line, linelen);

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

static int creds_parse_section(pool *p, char *line, size_t linesz,
    char **section_name, size_t *section_namesz) {

  if (*line != '[' ||
      line[linesz-1] != ']') {
    pr_trace_msg(trace_channel, 8, "badly formatted section name '%.*s'",
      (int) linesz, line);
    errno = EINVAL;
    return -1;
  }

  *section_name = aws_utils_strn_trim(p, line+1, linesz-2);
  *section_namesz = strlen(*section_name);

  return 0;
}

static int creds_from_profile_props(pool *p, pr_fh_t *fh, const char *profile,
    char **access_key_id, char **secret_access_key, char **session_token) {
  size_t bufsz, linelen, profilelen;
  char *buf, *line, *token;
  unsigned int lineno = 0;
  int have_section = FALSE;

  bufsz = PR_TUNABLE_PARSER_BUFFER_SIZE;
  buf = pcalloc(p, bufsz+1);

  *access_key_id = *secret_access_key = token = NULL;
  profilelen = strlen(profile);

  line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
  while (line != NULL) {
    char *section, *name, *val;
    size_t sectionsz, namesz, valsz;

    pr_signals_handle();

    if (have_section == FALSE) {
      if (creds_parse_section(p, line, linelen, &section, &sectionsz) == 0) {
        if (sectionsz == profilelen &&
            strncmp(section, profile, profilelen) == 0) {
          have_section = TRUE;

        } else {
          have_section = FALSE;
        }
      }

      line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
      continue;
    }

    if (creds_parse_prop(p, line, linelen, &name, &namesz, &val, &valsz) < 0) {
      if (creds_parse_section(p, line, linelen, &section, &sectionsz) == 0) {
        /* We're now in a new section; we're done. */
        break;
      }

      /* Ignore malformed lines. */
      line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
      continue;
    }

    pr_memscrub(line, linelen);

    if (namesz == 17) {
      if (strncmp(name, "aws_access_key_id", 18) == 0) {
        *access_key_id = val;

      } else if (strncmp(name, "aws_session_token", 18) == 0) {
        token = val;
      }

    } else if (namesz == 21 &&
               strncmp(name, "aws_secret_access_key", 22) == 0) {
      *secret_access_key = val;
    }

    line = creds_next_line(fh, buf, bufsz, &lineno, &linelen);
  }

  if (*access_key_id != NULL &&
      *secret_access_key != NULL) {

    if (session_token != NULL) {
      *session_token = token;
    }

    return 0;
  }

  errno = ENOENT;
  return -1;
}

int aws_creds_from_file(pool *p, const char *creds_path, const char *profile,
    struct aws_credentials **creds) {
  int res, xerrno;
  char *id, *key, *token;
  pr_fh_t *fh;
  struct stat st;
  pool *sub_pool;

  if (p == NULL ||
      creds_path == NULL ||
      creds == NULL) {
    errno = EINVAL;
    return -1;
  }

  sub_pool = make_sub_pool(p);
  pr_pool_tag(sub_pool, "AWS file credentials pool");

  fh = pr_fsio_open(creds_path, O_RDONLY);
  if (fh == NULL) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 9,  "unable to read credentials from '%s': %s",
      creds_path, strerror(xerrno));

    destroy_pool(sub_pool);
    errno = xerrno;
    return -1;
  }

  if (pr_fsio_fstat(fh, &st) < 0) {
    xerrno = errno;

    pr_trace_msg(trace_channel, 9,  "fstat(2) error on '%s': %s",
      creds_path, strerror(xerrno));

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

  id = key = token = NULL;

  if (profile != NULL) {
    res = creds_from_profile_props(sub_pool, fh, profile, &id, &key, &token);

  } else {
    res = creds_from_props(sub_pool, fh, &id, &key);
  }

  xerrno = errno;

  if (res == 0) {
    *creds = pcalloc(p, sizeof(struct aws_credentials));
    (*creds)->access_key_id = pstrdup(p, id);
    (*creds)->secret_access_key = pstrdup(p, key);
    (*creds)->session_token = pstrdup(p, token);
  }

  (void) pr_fsio_close(fh);
  destroy_pool(sub_pool);

  errno = xerrno;
  return res;
}

struct iam_info {
  pool *pool;

  const char *iam_role;

  /* http://169.254.169.254/latest/meta-data/iam/security-credentials/{role} */
  char *creds_doc;
  size_t creds_docsz;

  /* See security credentials doc "AccessKeyId" key. */
  const char *access_key_id;

  /* See security credentials doc "SecretAccessKey" key. */
  const char *secret_access_key;

  /* See security credentials doc "Token" key. */
  const char *session_token;
};

static int get_metadata(pool *p, void *http, const char *url,
    size_t (*resp_body)(char *, size_t, size_t, void *),
    void *user_data) {
  int res;
  long resp_code;

  res = aws_http_get(p, http, url, NULL, resp_body, user_data, &resp_code,
    NULL);
  if (res < 0) {
    return -1;
  }

  /* Note: should we handle other response codes? */
  switch (resp_code) {
    case AWS_HTTP_RESPONSE_CODE_OK:
      break;

    case AWS_HTTP_RESPONSE_CODE_BAD_REQUEST:
      pr_trace_msg(trace_channel, 2,
        "received %ld response code for '%s' request", resp_code, url);
      errno = EINVAL;
      return -1;

    case AWS_HTTP_RESPONSE_CODE_NOT_FOUND:
      pr_trace_msg(trace_channel, 2,
        "received %ld response code for '%s' request", resp_code, url);
      errno = ENOENT;
      return -1;

    default:
      pr_trace_msg(trace_channel, 2,
        "received %ld response code for '%s' request", resp_code, url);
      errno = EPERM;
      return -1;
  }

  return 0;
}

/* Security credentials doc */
static size_t iam_creds_cb(char *data, size_t item_sz, size_t item_count,
    void *user_data) {
  struct iam_info *info;
  size_t datasz;
  char *ptr;

  info = user_data;
  datasz = item_sz * item_count;

  if (datasz == 0) {
    return 0;
  }

  if (info->creds_docsz == 0) {
    info->creds_docsz = datasz;
    ptr = info->creds_doc = palloc(info->pool, info->creds_docsz);

  } else {
    ptr = info->creds_doc;
    info->creds_doc = palloc(info->pool, info->creds_docsz + datasz);
    memcpy(info->creds_doc, ptr, info->creds_docsz);

    ptr = info->creds_doc + info->creds_docsz;
    info->creds_docsz += datasz;
  }

  memcpy(ptr, data, datasz);
  return datasz;
}

static int get_iam_info(pool *p, void *http, struct iam_info *info) {
  int res;
  const char *url;

  url = pstrcat(p, AWS_INSTANCE_METADATA_URL, "/iam/security-credentials/",
    info->iam_role, NULL);

  res = get_metadata(p, http, url, iam_creds_cb, info);
  if (res == 0) {
    const char *text;
    pr_json_object_t *json;

    text = pstrndup(info->pool, info->creds_doc, info->creds_docsz);
    json = pr_json_object_from_text(info->pool, text);
    if (json != NULL) {
      const char *key;
      char *val = NULL;

      key = "AccessKeyId";
      if (pr_json_object_get_string(info->pool, json, key, &val) == 0) {
        info->access_key_id = pstrdup(info->pool, val);

      } else {
        pr_trace_msg(trace_channel, 3, "no '%s' string found in '%s'", key,
          text);
      }

      key = "SecretAccessKey";
      val = NULL;
      if (pr_json_object_get_string(info->pool, json, key, &val) == 0) {
        info->secret_access_key = pstrdup(info->pool, val);

      } else {
        pr_trace_msg(trace_channel, 3, "no '%s' string found in '%s'", key,
          text);
      }

      key = "Token";
      val = NULL;
      if (pr_json_object_get_string(info->pool, json, key, &val) == 0) {
        info->session_token = pstrdup(info->pool, val);

      } else {
        pr_trace_msg(trace_channel, 3, "no '%s' string found in '%s'", key,
          text);
      }

      pr_json_object_free(json);

    } else {
      pr_trace_msg(trace_channel, 3,
        "'%s' JSON failed validation, ignoring", url);

      info->creds_docsz = 0;
      info->creds_doc = NULL;

      errno = ENOENT;
      return -1;
    }

  } else if (res < 0 &&
             errno == ENOENT) {
    /* Clear the response data for 404 responses. */
    info->creds_docsz = 0;
    info->creds_doc = NULL;
  }

  return res;
}

int aws_creds_from_iam(pool *p, const char *iam_role,
    struct aws_credentials **creds) {
  int res, xerrno = 0;
  pool *iam_pool;
  void *http;
  struct iam_info *info;

  if (p == NULL ||
      iam_role == NULL ||
      creds == NULL) {
    errno = EINVAL;
    return -1;
  }

  http = aws_http_alloc(p, 1UL, 1UL, NULL);
  if (http == NULL) {
    return -1;
  }

  iam_pool = make_sub_pool(p);
  pr_pool_tag(iam_pool, "AWS IAM credentials pool");

  info = palloc(iam_pool, sizeof(struct iam_info));
  info->pool = iam_pool;
  info->iam_role = iam_role;

  res = get_iam_info(p, http, info);
  xerrno = errno;

  aws_http_destroy(p, http);

  if (res == 0) {
    *creds = pcalloc(p, sizeof(struct aws_credentials));
    (*creds)->access_key_id = pstrdup(p, info->access_key_id);
    (*creds)->secret_access_key = pstrdup(p, info->secret_access_key);
    (*creds)->session_token = pstrdup(p, info->session_token);
  }

  destroy_pool(iam_pool);

  errno = xerrno;
  return res;
}

int aws_creds_from_chain(pool *p, const array_header *providers,
    const struct aws_credential_info *info, struct aws_credentials **creds) {
  register unsigned int i;
  int res;
  pool *sub_pool;

  if (p == NULL ||
      info == NULL ||
      creds == NULL) {
    errno = EINVAL;
    return -1;
  }

  if (providers == NULL) {
    /* Default to just the "IAM" provider */
    res = aws_creds_from_iam(p, info->iam_role, creds);
    return res;
  }

  sub_pool = make_sub_pool(p);
  for (i = 0; i < providers->nelts; i++) {
    const char *provider;

    provider = ((char **) providers->elts)[i];

    if (strcmp(provider, AWS_CREDS_PROVIDER_NAME_IAM) == 0) {
      res = aws_creds_from_iam(p, info->iam_role, creds);

    } else if (strcmp(provider, AWS_CREDS_PROVIDER_NAME_PROFILE) == 0) {
      const char *default_path;
      char *profile_path;

      default_path = "~/.aws/credentials";
      profile_path = pr_env_get(sub_pool, "AWS_CREDENTIAL_PROFILES_FILE");
      if (profile_path == NULL) {
        size_t sz = PR_TUNABLE_PATH_MAX;

        profile_path = pcalloc(sub_pool, sz+1);
        res = pr_fs_interpolate(default_path, profile_path, sz);
        if (res < 0) {
          pr_trace_msg(trace_channel, 5, "unable to interpolate '%s': %s",
            default_path, strerror(errno));
          profile_path = NULL;
        }
      }

      if (profile_path != NULL) {
        res = aws_creds_from_file(p, profile_path, info->profile, creds);
      }

    } else if (strcmp(provider, AWS_CREDS_PROVIDER_NAME_PROPERTIES) == 0) {
      res = aws_creds_from_file(p, info->creds_path, NULL, creds);

    } else if (strcmp(provider, AWS_CREDS_PROVIDER_NAME_ENVIRONMENT) == 0) {
      res = aws_creds_from_env(p, creds);

    } else {
      pr_trace_msg(trace_channel, 4,
        "unknown/unsupported credentials provider: %s", provider);
      res = -1;
    }

    if (res == 0) {
      break;
    }
  }

  destroy_pool(sub_pool);
  errno = ENOENT;
  return res;
}

int aws_creds_from_sql(pool *p, const char *query,
    struct aws_credentials **creds) {

  if (p == NULL ||
      query == NULL ||
      creds == NULL) {
    errno = EINVAL;
    return -1;
  }

  errno = ENOSYS;
  return -1;
}
