/*
 * ProFTPD - mod_aws CloudWatch Dimension API
 * Copyright (c) 2017 TJ Saunders
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
#include "cloudwatch/dimension.h"

static const char *trace_channel = "aws.cloudwatch.dimension";

/* An array of dimensions is assumed to be alternating key/value strings. */
static void add_dimension(pool *p, array_header *dimensions, const char *name,
    char *value) {
  *((char **) push_array(dimensions)) = pstrdup(p, name);
  *((char **) push_array(dimensions)) = value;
}

array_header *aws_cloudwatch_dimension_get(pool *p,
    unsigned long dimension_set, const struct aws_info *info) {
  array_header *dimensions = NULL;

  if (p == NULL) {
    errno = EINVAL;
    return NULL;
  }

  dimensions = make_array(p, 0, sizeof(char *));

  if (dimension_set & AWS_CLOUDWATCH_DIMENSION_PROTOCOL) {
    char *name;
    const char *value;

    name = "Protocol";
    value = pr_session_get_protocol(0);
    add_dimension(p, dimensions, name, pstrdup(p, value));
  }

  if (dimension_set & AWS_CLOUDWATCH_DIMENSION_INSTANCE_ID) {
    char *name;

    name = "InstanceId";

    if (info != NULL) {
      char *value;

      value = pstrndup(p, info->instance_id, info->instance_idsz);
      add_dimension(p, dimensions, name, value);

    } else {
      pr_trace_msg(trace_channel, 14,
        "unable to provide %s dimension: missing instance info", name);
    }
  }

  if (dimension_set & AWS_CLOUDWATCH_DIMENSION_AVAIL_ZONE) {
    char *name;

    name = "AvailabilityZone";

    if (info != NULL) {
      char *value;

      value = pstrndup(p, info->avail_zone, info->avail_zonesz);
      add_dimension(p, dimensions, name, value);

    } else {
      pr_trace_msg(trace_channel, 14,
        "unable to provide %s dimension: missing instance info", name);
    }
  }

  return dimensions;
}
