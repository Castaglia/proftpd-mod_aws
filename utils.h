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

#ifndef MOD_AWS_UTILS_H
#define MOD_AWS_UTILS_H

#include "mod_aws.h"

/* Converts a table whose keys/values are both strings into a single array
 * of strings.
 */
array_header *aws_utils_table2array(pool *p, pr_table_t *tab);

/* Duplicate (deep copy) a table, using the given pool. */
pr_table_t *aws_utils_table_dup(pool *p, pr_table_t *tab);

/* Converts the given numbers to strings, allocated out of the given pool. */
char *aws_utils_str_n2s(pool *p, int n);
char *aws_utils_str_ul2s(pool *p, unsigned long n);
char *aws_utils_str_off2s(pool *p, off_t n);
char *aws_utils_str_mode2s(pool *p, mode_t m);

/* Converts the given strings to numbers. */
int aws_utils_str_s2mode(pool *P, const char *s, mode_t *m);
int aws_utils_str_s2off(pool *p, const char *s, off_t *n);
int aws_utils_str_s2ul(pool *p, const char *s, unsigned long *l);

/* Trim any leading/trailing whitespace from the given string.
 *
 * A copy of the given string is made from the pool, and that copy is
 * then modified as needed; a pointer to the modified string is returned.
 */
char *aws_utils_str_trim(pool *p, const char *str);

/* Similar to aws_utils_str_trim(), except that the string length is
 * explicitly provided.
 */
char *aws_utils_strn_trim(pool *p, const char *str, size_t len);

#endif /* MOD_AWS_UTILS_H */
