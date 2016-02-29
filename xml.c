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

static int has_name(xmlNodePtr elt, const char *name, size_t name_len) {
  if (elt == NULL) {
    return FALSE;
  }

  if (strncmp((const char *) elt->name, name, name_len) != 0) {
    pr_trace_msg(trace_channel, 2,
      "unexpected <%s> element for error (expected <%s>)", elt->name, name);
    return FALSE;
  }

  return TRUE;
}

static int is_element(xmlNodePtr elt) {
  if (elt == NULL) {
    return FALSE;
  }

  if (elt->type != XML_ELEMENT_NODE) {
    pr_trace_msg(trace_channel, 2,
      "unexpected non-element <%s> node (type %d)", elt->name, (int) elt->type);
    return FALSE;
  }

  return TRUE;
}

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

static const char *get_text(pool *p, xmlNodePtr elt) {
  xmlChar *content;
  char *text;

  if (is_text(elt) == FALSE) {
    errno = EINVAL;
    return NULL;
  }

  content = XML_GET_CONTENT(elt);
  if (content == NULL) {
    return NULL;
  }

  text = pstrdup(p, (const char *) content);
  return text;
}

struct aws_error *aws_xml_parse_error(pool *p, const char *data,
    size_t datasz) {
  xmlDocPtr doc;
  xmlNodePtr response, errors, error, elt, req_id;
  pool *err_pool;
  struct aws_error *err;
  unsigned long count;

  doc = xmlReadMemory(data, (int) datasz, "error.xml", NULL, xml_parse_opts);
  if (doc == NULL) {
    errno = EINVAL;
    return NULL;
  }

  response = xmlDocGetRootElement(doc);
  if (response == NULL) {
    /* Malformed XML. */
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  if (is_element(response) == FALSE) {
    xmlFreeDoc(doc);
    errno = EINVAL;
    return NULL;
  }

  if (has_name(response, "Response", 9) == FALSE) {
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  /* We expect only 2 child elements: <Errors> and <RequestID> */
  count = xmlChildElementCount(response);
  if (count != 2) {
    pr_trace_msg(trace_channel, 2,
      "unexpected count of child elements (%lu != 2)", count);

    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  errors = xmlFirstElementChild(response);
  if (is_element(errors) == FALSE) {
    xmlFreeDoc(doc);
    errno = EINVAL;
    return NULL;
  }

  if (has_name(errors, "Errors", 7) == FALSE) {
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  count = xmlChildElementCount(errors);
  if (count != 1) {
    pr_trace_msg(trace_channel, 5,
      "expected 1 error element, found %lu", count);
  }

  error = errors->children;
  if (is_element(error) == FALSE) {
    xmlFreeDoc(doc);
    errno = EINVAL;
    return NULL;
  }

  if (has_name(error, "Error", 6) == FALSE) {
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  elt = error->children;
  if (is_element(elt) == FALSE) {
    xmlFreeDoc(doc);
    errno = EINVAL;
    return NULL;
  }

  if (has_name(elt, "Code", 5) == FALSE) {
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  err_pool = make_sub_pool(p);
  pr_pool_tag(err_pool, "AWS Error Pool");
  err = palloc(err_pool, sizeof(struct aws_error));
  err->pool = err_pool;

  err->err_code = aws_error_get_code(err->pool,
    get_text(err->pool, elt->children));

  elt = elt->next;
  if (is_element(elt) == FALSE) {
    destroy_pool(err->pool);
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  if (has_name(elt, "Message", 8) == FALSE) {
    destroy_pool(err->pool);
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  err->err_msg = get_text(err->pool, elt->children);

  req_id = xmlLastElementChild(response);
  if (is_element(req_id) == FALSE) {
    destroy_pool(err->pool);
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  if (has_name(req_id, "RequestID", 10) == FALSE) {
    destroy_pool(err->pool);
    xmlFreeDoc(doc);

    errno = EINVAL;
    return NULL;
  }

  err->req_id = get_text(err->pool, req_id->children);

  xmlFreeDoc(doc);
  return err;
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
