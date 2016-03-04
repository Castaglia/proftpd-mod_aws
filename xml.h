/*
 * ProFTPD - mod_aws XML
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

#ifndef MOD_AWS_XML_H
#define MOD_AWS_XML_H

int aws_xml_elt_get_child_count(pool *p, void *elt, unsigned long *count);
void *aws_xml_elt_get_child(pool *p, void *elt, const char *name,
  size_t name_len);
const char *aws_xml_elt_get_name(pool *p, void *elt, size_t *name_len);
void *aws_xml_elt_get_next(pool *p, void *elt);
const char *aws_xml_elt_get_text(pool *p, void *elt);

void *aws_xml_doc_parse(pool *p, const char *data, size_t datasz);
void aws_xml_doc_free(pool *p, void *xml);
void *aws_xml_doc_get_root_elt(pool *p, void *xml);

/* API lifetime functions, for mod_aws use only. */
int aws_xml_init(pool *p);
int aws_xml_free(void);

#endif /* MOD_AWS_XML_H */
