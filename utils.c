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
  void *key;

  listsz = pr_table_count(tab);
  list = make_array(p, listsz, sizeof(char *));

  pr_table_rewind(tab);

  key = pr_table_next(tab);
  while (key != NULL) {
    void *value;

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

char *aws_utils_str_trim(pool *p, const char *str) {
  if (p == NULL ||
      str == NULL) {
    errno = EINVAL;
    return NULL;
  }

  errno = ENOSYS;
  return NULL;
}