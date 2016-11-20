/*
 * ProFTPD - mod_aws utilities
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

array_header *aws_utils_table2array(pool *p, pr_table_t *tab) {
  array_header *list;
  int listsz;
  const void *key;

  if (p == NULL ||
      tab == NULL) {
    errno = EINVAL;
    return NULL;
  }

  listsz = pr_table_count(tab);
  list = make_array(p, listsz, sizeof(char *));

  pr_table_rewind(tab);

  key = pr_table_next(tab);
  while (key != NULL) {
    const void *value;

    pr_signals_handle();

    value = pr_table_get(tab, (const char *) key, NULL);
    if (value != NULL) {
      *((char **) push_array(list)) = pstrcat(p, (char *) key, ": ",
        (char *) value, NULL);
    }

    key = pr_table_next(tab);
  }

  return list;
}

pr_table_t *aws_utils_table_dup(pool *p, pr_table_t *src) {
  pr_table_t *dst;
  const void *key;

  if (p == NULL ||
      src == NULL) {
    errno = EINVAL;
    return NULL;
  }

  dst = pr_table_alloc(p, 0);

  pr_table_rewind(src);

  key = pr_table_next(src);
  while (key != NULL) {
    const void *val;
    size_t valsz = 0;

    pr_signals_handle();

    val = pr_table_get(src, (const char *) key, &valsz);
    if (val != NULL) {
      void *dst_val;

      /* NOTE: This will only work for tables whose keys are strings.  The
       * core Table API needs a new function for iterating, such that the
       * size of the key is also provided, for better table duplication to be
       * supportable.
       */

      dst_val = palloc(p, valsz);
      memcpy(dst_val, val, valsz);
      (void) pr_table_add(dst, key, dst_val, valsz);
    }

    key = pr_table_next(src);
  }

  return dst;
}

char *aws_utils_str_n2s(pool *p, int n) {
  char buf[256], *num;
  int len;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  memset(buf, '\0', sizeof(buf));
  len = snprintf(buf, sizeof(buf)-1, "%d", n);
  num = pstrndup(p, buf, len);

  return num;
}

char *aws_utils_str_ul2s(pool *p, unsigned long n) {
  char buf[256], *num;
  int len;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  memset(buf, '\0', sizeof(buf));
  len = snprintf(buf, sizeof(buf)-1, "%lu", n);
  num = pstrndup(p, buf, len);

  return num;
}

char *aws_utils_str_off2s(pool *p, off_t n) {
  char buf[256], *num;
  int len;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  memset(buf, '\0', sizeof(buf));
  len = snprintf(buf, sizeof(buf)-1, "%" PR_LU, (pr_off_t) n);
  num = pstrndup(p, buf, len);

  return num;
}

char *aws_utils_str_mode2s(pool *p, mode_t m) {
  char buf[256], *mode;
  int len;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  memset(buf, '\0', sizeof(buf));
  len = snprintf(buf, sizeof(buf)-1, "%08o", m);
  mode = pstrndup(p, buf, len);

  return mode;
}

int aws_utils_str_s2off(pool *p, const char *s, off_t *n) {
  char *ptr = NULL;

  if (p == NULL ||
      s == NULL ||
      n == NULL) {
    errno = EINVAL;
    return -1;
  }

#ifdef HAVE_STROTOULL
  *n = strtoull(s, &ptr, 10);
#else
  *n = strtoul(s, &ptr, 10);
#endif /* HAVE_STRTOULL */

  if (ptr && *ptr) {
    errno = EINVAL;
    return -1;
  }

  return 0;
}

int aws_utils_str_s2mode(pool *p, const char *s, mode_t *m) {
  int count;
  unsigned int num;

  if (p == NULL ||
      s == NULL ||
      m == NULL) {
    errno = EINVAL;
    return -1;
  }

  count = sscanf(s, "%08o", &num);
  if (count != 1) {
    errno = EINVAL;
    return -1;
  }

  *m = num;
  return 0;
}

int aws_utils_str_s2ul(pool *p, const char *s, unsigned long *l) {
  int count;
  unsigned long num;

  if (p == NULL ||
      s == NULL ||
      l == NULL) {
    errno = EINVAL;
    return -1;
  }

  count = sscanf(s, "%lu", &num);
  if (count != 1) {
    errno = EINVAL;
    return -1;
  }

  *l = num;
  return 0;
}

char *aws_utils_strn_trim(pool *p, const char *str, size_t len) {
  const char *start, *end;
  char *trimmed = NULL;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (len == 0) {
    return pstrdup(p, "");
  }

  /* "Trim" the leading whitespace by skipping over it, to find the "start"
   * of our string to copy.
   */
  start = str;
  while (PR_ISSPACE(*start)) {
    pr_signals_handle();
    start++;
  }

  /* Similarly, "trim" the trailing whitepsace by skipping it in our copy
   * by finding the non-whitespace "end" of the string.
   */
  end = &str[len-1];
  while (PR_ISSPACE(*end)) {
    pr_signals_handle();
    end--;
  }

  trimmed = pstrndup(p, start, end - start + 1);
  return trimmed;
}

char *aws_utils_str_trim(pool *p, const char *str) {
  size_t len;

  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  len = strlen(str);
  return aws_utils_strn_trim(p, str, len);
}
