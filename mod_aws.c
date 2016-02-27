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
 * $Libraries: -lcurl -lcrypto$
 */

#include "mod_aws.h"
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
#define AWS_FL_CURL_NO_SSL	0x0001;

static const char *aws_logfile = NULL;


static const char *trace_channel = "aws";

/* Configuration handlers
 */

/* usage: AWSCACertificateFile path */
MODRET set_awscacertfile(cmd_rec *cmd) {
#ifdef PR_USE_OPENSSL
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

  add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "Missing required OpenSSL support (see --enable-openssl configure option)");
#endif /* PR_USE_OPENSSL */
}

/* usage: AWSCACertificatePath path */
MODRET set_awscacertpath(cmd_rec *cmd) {
#ifdef PR_USE_OPENSSL
  int res;
  char *path;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  path = cmd->argv[1];

  PRIVS_ROOT
  res = dir_exists2(cmd->tmp_pool, path);
  PRIVS_RELINQUISH

  if (!res) {
    CONF_ERROR(cmd, "parameter must be a directory path");
  }

  if (*path != '/') {
    CONF_ERROR(cmd, "parameter must be an absolute path");
  }

  add_config_param_str(cmd->argv[0], 1, path);
  return PR_HANDLED(cmd);
#else
  CONF_ERROR(cmd, "Missing required OpenSSL support (see --enable-openssl configure option)");
#endif /* PR_USE_OPENSSL */
}

/* usage: AWSEngine on|off */
MODRET set_awsengine(cmd_rec *cmd) {
  int engine = 1;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  if (engine == TRUE) {
    if (aws_flags & AWS_FL_CURL_NO_SSL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "unable to enable mod_aws: libcurl lacks necessary SSL support", NULL));
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
    if (0) {

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
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_str_get_duration(cmd->argv[1], &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      (char *) cmd->argv[1], "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* usage: AWSTimeoutRequest secs */
MODRET set_awstimeoutrequest(cmd_rec *cmd) {
  int timeout = -1;
  config_rec *c = NULL;
  char *timespec;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  timespec = cmd->argv[1];

  if (pr_str_get_duration(timespec, &timeout) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "error parsing timeout value '",
      timespec, "': ", strerror(errno), NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = timeout;

  return PR_HANDLED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void aws_mod_unload_ev(const void *event_data, void *user_data) {
  if (strncmp((const char *) event_data, "mod_aws.c", 12) == 0) {
    /* Unregister ourselves from all events. */
    pr_event_unregister(&aws_module, NULL, NULL);

    destroy_pool(aws_pool);
    aws_pool = NULL;

    if (aws_logfd >= 0) {
      (void) close(aws_logfd);
      aws_logfd = -1;
    }
  }
}
#endif

static void proxy_restart_ev(const void *event_data, void *user_data) {
  CURLcode curl_code;
  long curl_flags = CURL_GLOBAL_ALL;

  /* Re-init libcurl? OpenSSL (for signatures) ? */

  curl_global_cleanup();

#ifdef CURL_GLOBAL_ACK_EINTR
  curl_flags |= CURL_GLOBAL_ACK_EINTR;
#endif /* CURL_GLOBAL_ACK_EINTR *
  curl_code = curl_global_init(curl_flags);
  if (curl_code != CURLE_OK) {
    const char *details;

    details = curl_easy_strerror(curl_code);
    pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
      ": error initializing libcurl: %s", details);

    pr_session_disconnect(&aws_module, PR_SESS_DISCONNECT_SESSION_INIT_FAILED,
      details);
  }
}

static void aws_shutdown_ev(const void *event_data, void *user_data) {
  /* XXX Unregister from ELB, or Route53 */

  curl_global_cleanup();

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

  aws_info = aws_instance_get_info();
  if (aws_info == NULL) {
    pr_log_debug(DEBUG0, MOD_AWS_VERSION
      ": unable to discover EC2 instance metadata: %s", strerror(errno));
    return;
  }

  /* XXX Scan server list, and check SG settings (if allowed by IAM). */

  /* XXX Register with ELB, or Route53 */

}

/* XXX Do we want to support any Controls/ftpctl actions? */

/* Initialization routines
 */

static int aws_init(void) {
  CURLcode curl_code;
  curl_version_info_data *curl_info;
  long curl_flags = CURL_GLOBAL_ALL;

#ifdef CURL_GLOBAL_ACK_EINTR
  curl_flags |= CURL_GLOBAL_ACK_EINTR;
#endif /* CURL_GLOBAL_ACK_EINTR *
  curl_code = curl_global_init(curl_flags);
  if (curl_code != CURLE_OK) {
    pr_log_pri(PR_LOG_NOTICE, MOD_AWS_VERSION
      ": error initializing libcurl: %s", curl_easy_strerror(curl_code));
    errno = EPERM;
    return -1;
  }

  curl_info = curl_version_info(CURLVERSION_NOW);
  if (curl_info != NULL) {
    pr_log_debug(DEBUG5, MOD_AWS_VERSION
      ": libcurl version: %s", curl_info->version);

    if (!(curl_info->features & CURL_VERSION_SSL)) {
      pr_log_pri(PR_LOG_INFO, MOD_AWS_VERSION
        ": libcurl compiled without SSL support, disabling mod_aws");
      aws_flags |= AWS_FL_CURL_NO_SSL;

    } else {
      pr_log_debug(DEBUG5, MOD_AWS_VERSION
        ": libcurl compiled using OpenSSL version: %s", curl_info->ssl_version);
    }
  }

  if (aws_flags & AWS_FL_CURL_NO_SSL) {
    curl_global_cleanup();
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
  { "AWSCACertificateFile",	set_awsscacertfile,	NULL },
  { "AWSCACertificatePath",	set_awscacertpath,	NULL },
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
