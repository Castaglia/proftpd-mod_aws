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

#ifndef MOD_AWS_CLOUDWATCH_DIMENSION_H
#define MOD_AWS_CLOUDWATCH_DIMENSION_H

#include "mod_aws.h"
#include "instance.h"

#define AWS_CLOUDWATCH_MAX_DIMENSIONS		10

#define AWS_CLOUDWATCH_DIMENSION_PROTOCOL	0x0001
#define AWS_CLOUDWATCH_DIMENSION_INSTANCE_ID	0x0002
#define AWS_CLOUDWATCH_DIMENSION_AVAIL_ZONE	0x0004

array_header *aws_cloudwatch_dimension_get(pool *p, unsigned long dimensions,
  const struct aws_info *info);

#endif /* MOD_AWS_CLOUDWATCH_DIMENSION_H */
