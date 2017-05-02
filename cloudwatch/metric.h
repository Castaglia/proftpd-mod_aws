/*
 * ProFTPD - mod_aws CloudWatch Error API
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

#ifndef MOD_AWS_CLOUDWATCH_ERROR_H
#define MOD_AWS_CLOUDWATCH_ERROR_H

#include "mod_aws.h"
#include "cloudwatch/conn.h"

int aws_cloudwatch_metric_counter(pool *p, struct cloudwatch_conn *cw,
  const char *name, double incr, array_header *dimensions, int flags);

int aws_cloudwatch_metric_timer(pool *p, struct cloudwatch_conn *cw,
  const char *name, double ms, array_header *dimensions, int flags);

#endif /* MOD_AWS_CLOUDWATCH_METRIC_H */
