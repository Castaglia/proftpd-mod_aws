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

char *aws_utils_str_trimn(pool *p, const char *str, size_t len) {
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
  return aws_utils_str_trimn(p, str, len);
}
