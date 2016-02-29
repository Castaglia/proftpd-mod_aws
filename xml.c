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
#include "xml.h"

#ifdef HAVE_LIBXML_PARSER_H
# include <libxml/parser.h>
# include <libxml/tree.h>
#endif

static const char *trace_channel = "aws.xml";

void *aws_xml_alloc(pool *p, const char *data, size_t datasz) {
  xmlDocPtr doc;
  int doc_opts = XML_PARSE_NONET;

  doc = xmlReadMemory(data, (int) datasz, "error.xml", NULL, doc_opts);
  if (doc == NULL) {
/* XXX libxml2 error reporting? */
    errno = EINVAL;
    return NULL;
  }

  return doc;
}

int aws_xml_destroy(pool *p, void *xml) {
  xmlDocPtr doc;

  if (xml == NULL) {
    errno = EINVAL;
    return -1;
  }

  doc = xml;
  xmlFreeDoc(doc);

  return 0;
}

/* Generic error reporting callback. */
static void xml_error_cb(void *ctx, const char *fmt, ...) {
  va_list msg;

  va_start(msg, fmt);
  (void) pr_trace_vmsg(trace_channel, 1, fmt, msg);
  va_end(msg);
}

int aws_xml_init(pool *p) {
  (void) p;

  xmlInitParser();
  xmlSetGenericErrorFunc(NULL, xml_error_cb);

  return 0;
}

int aws_xml_free(void) {
  xmlCleanupParser();

  return 0;
}
