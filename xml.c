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
#include "error.h"

#ifdef HAVE_LIBXML_PARSER_H
# include <libxml/parser.h>
# include <libxml/tree.h>
#endif

static int xml_parse_opts = XML_PARSE_COMPACT|XML_PARSE_NOBLANKS|XML_PARSE_NONET|XML_PARSE_PEDANTIC;

static const char *trace_channel = "aws.xml";

static int is_text(xmlNodePtr elt) {
  if (elt == NULL) {
    return FALSE;
  }

  if (elt->type != XML_TEXT_NODE) {
    pr_trace_msg(trace_channel, 2,
      "unexpected non-text <%s> node (type %d)", elt->name, (int) elt->type);
    return FALSE;
  }

  return TRUE;
}

/* XML elements */

int aws_xml_elt_get_child_count(pool *p, void *ptr, unsigned long *count) {
  xmlNodePtr elt;

  (void) p;

  if (ptr == NULL ||
      count == NULL) {
    errno = EINVAL;
    return -1;
  }

  elt = ptr;
  *count = xmlChildElementCount(elt);
  return 0;
}

void *aws_xml_elt_get_child(pool *p, void *ptr, const char *name,
    size_t name_len) {
  register unsigned long i;
  xmlNodePtr elt, kid;
  unsigned long count;

  (void) p;

  if (ptr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  if (aws_xml_elt_get_child_count(p, ptr, &count) < 0) {
    return NULL;
  }

  if (count == 0) {
    errno = ENOENT;
    return NULL;
  }

  if (name != NULL &&
      name_len == 0) {
    name_len = strlen(name);
  }

  /* Walk the children, looking for a node whose name matches the given
   * name.
   */

  elt = ptr;

  for (i = 0, kid = elt->children; i < count && kid != NULL; i++) {
    pr_signals_handle();

    if (name == NULL) {
      /* Simply return the next sibling. */
      return kid->next;
    }

    if (strncmp((const char *) kid->name, name, name_len) == 0) {
      return kid;
    }

    kid = kid->next;
  }

  errno = ENOENT;
  return NULL;
}

void *aws_xml_elt_get_next(pool *p, void *ptr) {
  xmlNodePtr elt;

  (void) p;

  if (ptr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  elt = ptr;
  return elt->next;
}

const char *aws_xml_elt_get_name(pool *p, void *ptr, size_t *name_len) {
  xmlNodePtr elt;
  const char *name;

  if (p == NULL ||
      ptr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  elt = ptr;
  name = (const char *) elt->name;

  if (name_len != NULL) {
    *name_len = strlen(name);
  }

  return name;
}

const char *aws_xml_elt_get_text(pool *p, void *ptr) {
  xmlNodePtr elt, kid;
  xmlChar *content;
  char *text;

  if (p == NULL ||
      ptr == NULL) {
    errno = EINVAL;
    return NULL;
  }

  /* For some reason, libxml2 stores the text of an element as a child
   * node of that element, with TEXT type.
   */
  elt = ptr;
  kid = elt->children;
  if (is_text(kid) == FALSE) {
    errno = EINVAL;
    return NULL;
  }

  content = XML_GET_CONTENT(kid);
  if (content == NULL) {
    return NULL;
  }

  text = pstrdup(p, (const char *) content);
  return text;
}

/* XML documents */

void *aws_xml_doc_parse(pool *p, const char *data, size_t datasz) {
  xmlDocPtr doc;

  if (data == NULL ||
      datasz == 0) {
    errno = EINVAL;
    return NULL;
  }

  doc = xmlReadMemory(data, (int) datasz, "error.xml", NULL, xml_parse_opts);
  return doc;
}

void aws_xml_doc_free(pool *p, void *xml) {
  xmlDocPtr doc;

  (void) p;

  if (xml == NULL) {
    return;
  }

  doc = xml;
  xmlFreeDoc(doc);
}

void *aws_xml_doc_get_root_elt(pool *p, void *xml) {
  xmlDocPtr doc;
  xmlNodePtr elt;

  (void) p;

  if (xml == NULL) {
    errno = EINVAL;
    return NULL;
  }

  doc = xml;
  elt = xmlDocGetRootElement(doc);
  return elt;
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

  /* Let libxml2 does its version self-check. */
  LIBXML_TEST_VERSION

  xmlInitParser();
  xmlSetGenericErrorFunc(NULL, xml_error_cb);

  return 0;
}

int aws_xml_free(void) {
  xmlCleanupParser();

  return 0;
}
