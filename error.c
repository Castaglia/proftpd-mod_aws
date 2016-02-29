/*
 * ProFTPD - mod_aws AWS Errors
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
#include "error.h"
#include "xml.h"

static const char *trace_channel = "aws.error";

/*
Example doc to parse:

<?xml version="1.0" encoding="UTF-8"?>
<Response><Errors><Error><Code>MissingParameter</Code><Message>The request must contain the parameter AWSAccessKeyId</Message></Error></Errors><RequestID>e03bfe35-249e-42ee-8671-f9a1c6201ceb</RequestID></Response>

 */

/* XXX Will need a string table, matching <code> string to our error code */

struct aws_error *aws_error_parse(pool *p, const char *data, size_t datasz) {
  void *xml;

  xml = aws_xml_alloc(p, data, datasz);
  if (xml == NULL) {
    errno = EINVAL;
    return NULL;
  }

  aws_xml_destroy(p, xml);

  errno = ENOSYS;
  return NULL;
}
