/*
 * ProFTPD - mod_aws
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
 *
 * -----DO NOT EDIT BELOW THIS LINE-----
 * $Archive: mod_aws.a $
 * $Libraries: -lcurl -lxml2 -lcrypto$
 */

#include "mod_aws.h"
#include "http.h"
#include "instance.h"

/* How long (in secs) to wait to connect to real server? */
#define AWS_CONNECT_DEFAULT_TIMEOUT	5

/* How long (in secs) to wait for the response? */
#define AWS_REQUEST_DEFAULT_TIMEOUT	3

extern xaset_t *server_list;

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;

module aws_module;

int aws_logfd = -1;
pool *aws_pool = NULL;
unsigned long aws_opts = 0UL;

static int aws_engine = FALSE;
static unsigned long aws_flags = 0UL;

static const char *aws_logfile = NULL;
static const char *aws_cacerts = NULL;

/* XXX Make these named constants. Reset them during restart_ev. */
static unsigned long aws_connect_timeout_secs = 15;
static unsigned long aws_request_timeout_secs = 30;

static const char *trace_channel = "aws";

static void log_instance_info(pool *p, struct aws_info *info) {

  /* NOTE that many of the fields are NOT NUL-terminated. */

  /* AWS domain */
  if (info->domain != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.domain = '%.*s'", (int) info->domainsz, info->domain);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.domain = unavailable");
  }

  /* Account ID */
  if (info->account_id != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION, "aws.account-id = '%s'",
      info->account_id);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.account-id = unavailable");
  }

  /* Region */
  if (info->region != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION, "aws.region = '%s'",
      info->region);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.region = unavailable");
  }

  /* Availability zone */
  if (info->avail_zone != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.avail-zone = '%.*s'", (int) info->avail_zonesz, info->avail_zone);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.avail-zone = unavailable");
  }

  /* Instance type */
  if (info->instance_type != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.instance-type = '%.*s'", (int) info->instance_typesz,
      info->instance_type);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.instance-type = unavailable");
  }

  /* Instance ID */
  if (info->instance_id != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.instance-id = '%.*s'", (int) info->instance_idsz, info->instance_id);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.instance-id = unavailable");
  }

  /* AMI ID */
  if (info->ami_id != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION, "aws.ami-id = '%.*s'",
      (int) info->ami_idsz, info->ami_id);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.ami-id = unavailable");
  }

  /* IAM role */
  if (info->iam_role != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION, "aws.iam-role = '%.*s'",
      (int) info->iam_rolesz, info->iam_role);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.iam-role = unavailable");
  }

  /* MAC */
  if (info->hw_mac != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION, "aws.mac = '%.*s'",
      (int) info->hw_macsz, info->hw_mac);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.mac = unavailable");
  }

  /* VPC ID */
  if (info->vpc_id != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION, "aws.vpc-id = '%.*s'",
      (int) info->vpc_idsz, info->vpc_id);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.vpc-id = unavailable");
  }

  /* Subnet ID */
  if (info->subnet_id != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.subnet-id = '%.*s'", (int) info->subnet_idsz, info->subnet_id);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.subnet-id = unavailable");
  }

  /* Local IPv4 */
  if (info->local_ipv4 != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.local-ipv4 = '%.*s'", (int) info->local_ipv4sz, info->local_ipv4);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.local-ipv4 = unavailable");
  }

  /* Local hostname */
  if (info->local_hostname != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.local-hostname = '%.*s'", (int) info->local_hostnamesz,
      info->local_hostname);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.local-hostname = unavailable");
  }

  /* Public IPv4 */
  if (info->public_ipv4 != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.public-ipv4 = '%.*s'", (int) info->public_ipv4sz, info->public_ipv4);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.public-ipv4 = unavailable");
  }

  /* Public hostname */
  if (info->public_hostname != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.public-hostname = '%.*s'", (int) info->public_hostnamesz,
      info->public_hostname);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.public-hostname = unavailable");
  }

  /* Security groups */
  if (info->security_groups != NULL) {
    register unsigned int i;
    char **elts, *groups = "";

    elts = info->security_groups->elts;
    for (i = 0; i < info->security_groups->nelts; i++) {
      groups = pstrcat(p, groups, *groups ? ", " : "", elts[i], NULL);
    }

    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.security-groups = '%s'", groups);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.security-groups = unavailable");
  }
}

/* Configuration handlers
 */

/* usage: AWSCACertificateFile path */
MODRET set_awscacertfile(cmd_rec *cmd) {
  int res;
  char *path;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1];

  PRIVS_ROOT
  res = file_exists2(cmd->tmp_pool, path);
  PRIVS_RELINQUISH

  if (!res) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", path, "' does not exist",
      NULL));
  }

  if (*path != '/') {
    CONF_ERROR(cmd, "parameter must be an absolute path");
  }

  aws_cacerts = pstrdup(aws_pool, path);
  return PR_HANDLED(cmd);
}

/* usage: AWSEngine on|off */
MODRET set_awsengine(cmd_rec *cmd) {
  int engine = 1;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  if (engine == TRUE) {
    if (aws_flags & AWS_FL_CURL_NO_SSL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unable to enable mod_aws: HTTP API lacks necessary SSL support",
        NULL));
    }
  }

  aws_engine = engine;
  return PR_HANDLED(cmd);
}

/* usage: AWSLog path */
MODRET set_awslog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  aws_logfile = pstrdup(aws_pool, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: AWSOptions opt1 ... optN */
MODRET set_awsoptions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long opts = 0UL;

  if (cmd->argc-1 == 0) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  c = add_config_param(cmd->argv[0], 1, NULL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcmp(cmd->argv[i], "FooBar") == 0) {

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AWSOption '",
        (char *) cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: AWSTimeoutConnect secs */
MODRET set_awstimeoutconnect(cmd_rec *cmd) {
  int timeout = -1;
  char *timespec;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  timespec = cmd->argv[1];
  if (pr_str_get_duration(timespec, &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      timespec, "': ", strerror(errno), NULL));
  }

  aws_connect_timeout_secs = timeout;
  return PR_HANDLED(cmd);
}

/* usage: AWSTimeoutRequest secs */
MODRET set_awstimeoutrequest(cmd_rec *cmd) {
  int timeout = -1;
  char *timespec;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  timespec = cmd->argv[1];
  if (pr_str_get_duration(timespec, &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      timespec, "': ", strerror(errno), NULL));
  }

  aws_request_timeout_secs = timeout;
  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void aws_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_aws.c", 12) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&aws_module, NULL, NULL);

    aws_http_free();
    destroy_pool(aws_pool);
    aws_pool = NULL;

    if (aws_logfd >= 0) {
      (void) close(aws_logfd);
      aws_logfd = -1;
    }
  }
}
#endif

static void aws_restart_ev(const void *event_data, void *user_data) {
  int res;
  const char *http_details = NULL;

  aws_http_free();

  res = aws_http_init(aws_pool, NULL, &http_details);
  if (res < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
      ": error initializing HTTP API: %s", http_details);

    pr_session_disconnect(&aws_module, PR_SESS_DISCONNECT_SESSION_INIT_FAILED,
      http_details);
  }

  destroy_pool(aws_pool);
  aws_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(aws_pool, MOD_AWS_VERSION);

  /* XXX Close/reopen AWSLog? */
}

static void aws_shutdown_ev(const void *event_data, void *user_data) {
  /* XXX Unregister from ELB, or Route53 */

  aws_http_free();

  destroy_pool(aws_pool);
  aws_pool = NULL;

  if (aws_logfd >= 0) {
    (void) close(aws_logfd);
    aws_logfd = -1;
  }
}

static void aws_startup_ev(const void *event_data, void *user_data) {
  struct aws_info *aws_info;

  if (aws_engine == FALSE) {
    return;
  }

  if (aws_logfile != NULL) {
    int res, xerrno;

    pr_signals_block();
    PRIVS_ROOT
    res = pr_log_openfile(aws_logfile, &aws_logfd, PR_LOG_SYSTEM_MODE);
    xerrno = errno;
    PRIVS_RELINQUISH
    pr_signals_unblock();

    if (res < 0) {
      if (res == -1) {
        pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
          ": notice: unable to open AWSLog '%s': %s", aws_logfile,
          strerror(xerrno));

      } else if (res == PR_LOG_WRITABLE_DIR) {
        pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
          ": notice: unable to open AWSLog '%s': parent directory is "
          "world-writable", aws_logfile);

      } else if (res == PR_LOG_SYMLINK) {
        pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
          ": notice: unable to open AWSLog '%s': cannot log to a symlink",
          aws_logfile);
      }
    }
  }

  aws_info = aws_instance_get_info(aws_pool, aws_connect_timeout_secs,
    aws_request_timeout_secs);
  if (aws_info == NULL) {
    pr_log_debug(DEBUG0, MOD_AWS_VERSION
      ": unable to discover EC2 instance metadata: %s", strerror(errno));
    return;
  }

  log_instance_info(aws_pool, aws_info);

  /* XXX Scan server list, and check SG settings (if allowed by IAM).
   *
   * Make sure to see if MasqueradeAddress is set (if not, suggest/set it),
   * if PassivePorts are set (if not, suggest/set them AND check SGs).
   */

  /* XXX Register with ELB, or Route53 */

}

/* XXX Do we want to support any Controls/ftpctl actions? */

/* Initialization routines
 */

static int aws_init(void) {
  const char *http_details = NULL;

  if (aws_http_init(aws_pool, &aws_flags, &http_details) < 0) {
    pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
      ": error initializing HTTP API: %s", http_details);
    errno = EPERM;
    return -1;
  }

  if (aws_flags & AWS_FL_CURL_NO_SSL) {
    aws_http_free();
    return 0;
  }

  aws_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(aws_pool, MOD_AWS_VERSION);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&aws_module, "core.module-unload", aws_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&aws_module, "core.restart", aws_restart_ev, NULL);
  pr_event_register(&aws_module, "core.shutdown", aws_shutdown_ev, NULL);
  pr_event_register(&aws_module, "core.startup", aws_startup_ev, NULL);

  return 0;
}

/* Module API tables
 */

static conftable aws_conftab[] = {
  { "AWSCACertificateFile",	set_awscacertfile,	NULL },
  { "AWSEngine",		set_awsengine,		NULL },
  { "AWSLog",			set_awslog,		NULL },
  { "AWSOptions",		set_awsoptions,		NULL },
  { "AWSTimeoutConnect",	set_awstimeoutconnect,	NULL },
  { "AWSTimeoutRequest",	set_awstimeoutrequest,	NULL },

  { NULL }
};

module aws_module = {
  /* Always NULL */
  NULL, NULL,

  /* Module API version */
  0x20,

  /* Module name */
  "aws",

  /* Module configuration handler table */
  aws_conftab,

  /* Module command handler table */
  NULL,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  aws_init,

  /* Session initialization */
  NULL,

  /* Module version */
  MOD_AWS_VERSION
};
