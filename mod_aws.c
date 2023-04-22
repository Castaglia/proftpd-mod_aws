/*
 * ProFTPD - mod_aws
 * Copyright (c) 2016-2023 TJ Saunders
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
#include "xml.h"
#include "instance.h"
#include "creds.h"
#include "ec2.h"
#include "route53.h"
#include "health.h"
#include "cloudwatch/conn.h"
#include "cloudwatch/dimension.h"
#include "cloudwatch/metric.h"

/* How long (in secs) to wait to connect to real server? */
#define AWS_CONNECT_DEFAULT_TIMEOUT	3

/* How long (in secs) to wait for the response? */
#define AWS_REQUEST_DEFAULT_TIMEOUT	5

/* Which AWS services will we be using? */
#define AWS_SERVICE_CLOUDWATCH		0x0001

extern xaset_t *server_list;

/* From response.c */
extern pr_response_t *resp_list, *resp_err_list;

module aws_module;

int aws_logfd = -1;
pool *aws_pool = NULL;
unsigned long aws_opts = 0UL;

static int aws_engine = FALSE;
static unsigned long aws_flags = 0UL;
static unsigned long aws_services = 0UL;

static const char *aws_logfile = NULL;
static const char *aws_cacerts = PR_CONFIG_DIR "/aws-cacerts.pem";
static const char *aws_region = NULL;

/* For obtaining AWS credentials. */
static const char *aws_profile = AWS_CREDS_DEFAULT_PROFILE;
static array_header *aws_creds_providers = NULL;
static uint64_t aws_sess_start_ms = 0;

static unsigned long aws_connect_timeout_secs = AWS_CONNECT_DEFAULT_TIMEOUT;
static unsigned long aws_request_timeout_secs = AWS_REQUEST_DEFAULT_TIMEOUT;

/* The IANA registered ephemeral port range. */
#define AWS_PASSIVE_PORT_MIN_DEFAULT		49152
#define AWS_PASSIVE_PORT_MAX_DEFAULT		65534

/* For AWSAdjustments */
static unsigned long aws_adjustments = 0UL;
#define AWS_ADJUST_FL_MASQ_ADDR			0x001
#define AWS_ADJUST_FL_PASV_PORTS		0x002
#define AWS_ADJUST_FL_SECURITY_GROUP		0x004

static const char *aws_adjust_sg_id = NULL;

/* For holding onto the EC2 instance metadata for e.g. session processes' use */
static const struct aws_info *instance_info = NULL;

static int aws_use_health = FALSE;
static const char *aws_health_addr = NULL;
static int aws_health_port = 8080;
static const char *aws_health_uri = "/health";

/* For holding onto the health listener, for shutting down when the daemon
 * is stopped.
 */
struct aws_health *instance_health = NULL;

/* CloudWatch */
static struct cloudwatch_conn *aws_cloudwatch = NULL;
static unsigned long aws_cloudwatch_dimensions = 0UL;
static const char *aws_cloudwatch_namespace = NULL;

static const char *trace_channel = "aws";

static const pr_netaddr_t *get_addr(pool *p, const char *data, size_t datasz) {
  char *name;
  const pr_netaddr_t *addr;

  name = pstrndup(p, data, datasz);
  addr = pr_netaddr_get_addr(p, name, NULL);
  return addr;
}

/* Get the security group ID for adjusting for access. */
static const char *get_adjust_sg_id(pool *p, pr_table_t *security_groups) {
  const void *key;
  const char *sg_id = NULL;

  pr_table_rewind(security_groups);
  key = pr_table_next(security_groups);
  while (key != NULL) {
    const struct ec2_security_group *sg;

    pr_signals_handle();

    sg = pr_table_get(security_groups, key, NULL);
    if (sg != NULL) {
      /* Make sure that the AWSSecurityGroup configured actually appears
       * in this instance's list of security groups.  Otherwise, we
       * use the last security group in the list.
       */
      if (aws_adjust_sg_id != NULL) {
        if (strcmp((const char *) key, aws_adjust_sg_id) == 0) {
          sg_id = aws_adjust_sg_id;
          break;
        }

      } else {
        sg_id = key;
      }
    }
  }

  if (sg_id == NULL) {
    errno = ENOENT;
  }

  return sg_id;
}

static int allow_sg_ports(pool *p, struct ec2_conn *ec2, const char *sg_id,
    int from_port, int to_port) {
  struct ec2_ip_rule *rule;
  pr_netacl_t *range;

  range = pr_netacl_create(p, pstrdup(p, "0.0.0.0/0"));
  if (range == NULL) {
    return -1;
  }

  rule = pcalloc(p, sizeof(struct ec2_ip_rule));
  rule->proto = pstrdup(p, "tcp");
  rule->from_port = from_port;
  rule->to_port = to_port;
  rule->ranges = make_array(p, 1, sizeof(pr_netacl_t *));
  *((pr_netacl_t **) push_array(rule->ranges)) = range;

  return aws_ec2_security_group_allow_rule(p, ec2, sg_id, rule);
}

static void verify_ctrl_port(pool *p, const struct aws_info *info,
    struct ec2_conn *ec2, server_rec *s, pr_table_t *security_groups) {
  const void *key = NULL;
  const char *sg_id = NULL;
  int ctrl_port_allowed = FALSE;

  if (s->ServerPort == 0) {
    /* Skip disabled vhosts. */
    return;
  }

  if (security_groups == NULL) {
    /* No SGs to check. */
    pr_trace_msg(trace_channel, 5,
      "unable to verify whether Port %u for <VirtualHost> '%s' allowed "
      "by security groups: no security groups found", s->ServerPort,
      s->ServerName);
    return;
  }

  pr_table_rewind(security_groups);
  key = pr_table_next(security_groups);
  while (key != NULL) {
    const struct ec2_security_group *sg;

    pr_signals_handle();

    if (ctrl_port_allowed) {
      break;
    }

    sg = pr_table_get(security_groups, key, NULL);
    if (sg != NULL) {
      register unsigned int i;
      struct ec2_ip_rule **rules;

      sg_id = key;

      rules = sg->inbound_rules->elts;
      for (i = 0; i < sg->inbound_rules->nelts; i++) {
        struct ec2_ip_rule *rule;

        rule = rules[i];

        if (rule->from_port > 0 &&
            rule->to_port > 0) {
          unsigned int from_port, to_port;

          from_port = rule->from_port;
          to_port = rule->to_port;

          if (from_port >= s->ServerPort &&
              to_port <= s->ServerPort) {
            /* This SG allows access for our control port.  Good. */
            (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
              "<VirtualHost> '%s' control port %u allowed by security group "
              "ID %s (%s)", s->ServerName, s->ServerPort, sg_id, sg->name);
            ctrl_port_allowed = TRUE;
            break;
          }
        }
      }
    }

    key = pr_table_next(security_groups);
  }

  if (ctrl_port_allowed == FALSE) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "<VirtualHost> '%s' control port %u is NOT ALLOWED by any security group",
      s->ServerName, s->ServerPort);

    if (!(aws_adjustments & AWS_ADJUST_FL_SECURITY_GROUP)) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "consider allowing this port using:\n  aws ec2 authorize-security-group-ingress --group-id %s --protocol tcp --port %u --cidr 0.0.0.0/0",
        sg_id, s->ServerPort);

    } else {
      int res, xerrno;
      pool *rule_pool;

      sg_id = get_adjust_sg_id(p, security_groups);
      rule_pool = make_sub_pool(p);

      res = allow_sg_ports(rule_pool, ec2, sg_id, s->ServerPort, s->ServerPort);
      xerrno = errno;
      destroy_pool(rule_pool);

      if (res < 0) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error adjusting AWS security group ID %s to allow port %u: %s",
          sg_id, s->ServerPort, strerror(xerrno));

      } else {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "adjusted AWS security group ID %s to allow port %u",
          sg_id, s->ServerPort);
      }
    }
  }
}

static void verify_masq_addr(pool *p, const struct aws_info *info,
    server_rec *s) {
  config_rec *c;
  const pr_netaddr_t *public_addr;

  /* Should we use public_hostname here instead? */
  if (info->public_ipv4 == NULL) {
    return;
  }

  public_addr = get_addr(s->pool, info->public_ipv4, info->public_ipv4sz);

  c = find_config(s->conf, CONF_PARAM, "MasqueradeAddress", FALSE);
  if (c != NULL) {
    pr_netaddr_t *masq_addr;
    char *masq_name;

    masq_addr = c->argv[0];
    masq_name = c->argv[1];

    if (pr_netaddr_cmp(masq_addr, public_addr) != 0) {
      if (!(aws_adjustments & AWS_ADJUST_FL_MASQ_ADDR)) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "existing 'MasqueradeAddress %s' for <VirtualHost> '%s' is INCORRECT",
          masq_name, s->ServerName);
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "consider using 'MasqueradeAddress %s' instead for "
          "<VirtualHost> '%s' for passive data transfers",
          pr_netaddr_get_ipstr(public_addr), s->ServerName);

      } else {
        c->argv[0] = (void *) public_addr;
        c->argv[1] = pstrndup(c->pool, info->public_ipv4, info->public_ipv4sz);

        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "automatically set 'MasqueradeAddress %s' for <VirtualHost> '%s'",
          pr_netaddr_get_ipstr(public_addr), s->ServerName);
      }
    }

  } else {
    if (!(aws_adjustments & AWS_ADJUST_FL_MASQ_ADDR)) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "consider adding 'MasqueradeAddress %s' to <VirtualHost> '%s' for "
        "passive data transfers", pr_netaddr_get_ipstr(public_addr),
        s->ServerName);

    } else {
      c = pr_config_add(s, "MasqueradeAddress", 0);
      c->config_type = CONF_PARAM;
      c->argc = 2;
      c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));
      c->argv[0] = (void *) public_addr;
      c->argv[1] = pstrndup(c->pool, info->public_ipv4, info->public_ipv4sz);

      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "automatically added 'MasqueradeAddress %s' to <VirtualHost> '%s'",
        pr_netaddr_get_ipstr(public_addr), s->ServerName);
    }
  }
}

static void verify_pasv_ports(pool *p, const struct aws_info *info,
    struct ec2_conn *ec2, server_rec *s, pr_table_t *security_groups) {
  config_rec *c;
  int pasv_min_port, pasv_max_port;
  const void *key = NULL;
  const char *sg_id = NULL;
  int pasv_ports_allowed = FALSE;

  /* If this vhost is for mod_sftp, then PassivePorts have no effect/meaning */
  c = find_config(s->conf, CONF_PARAM, "SFTPEngine", FALSE);
  if (c != NULL) {
    pr_trace_msg(trace_channel, 5,
      "<VirtualHost> '%s' uses mod_sftp, skipping PassivePorts check",
      s->ServerName);
    return;
  }

  c = find_config(s->conf, CONF_PARAM, "PassivePorts", FALSE);
  if (c == NULL) {
    pasv_min_port = AWS_PASSIVE_PORT_MIN_DEFAULT;
    pasv_max_port = AWS_PASSIVE_PORT_MAX_DEFAULT;

    if (!(aws_adjustments & AWS_ADJUST_FL_PASV_PORTS)) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "consider adding 'PassivePorts %d %d' to <VirtualHost> '%s' for "
        "passive data transfers", pasv_min_port, pasv_max_port, s->ServerName);

    } else {
      c = pr_config_add(s, "PassivePorts", 0);
      c->config_type = CONF_PARAM;
      c->argc = 2;
      c->argv = pcalloc(c->pool, sizeof(void *) * (c->argc + 1));

      c->argv[0] = palloc(c->pool, sizeof(int));
      *((int *) c->argv[0]) = AWS_PASSIVE_PORT_MIN_DEFAULT;
      c->argv[1] = palloc(c->pool, sizeof(int));
      *((int *) c->argv[1]) = AWS_PASSIVE_PORT_MAX_DEFAULT;

      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "automatically added 'PassivePorts %d %d' to <VirtualHost> '%s'",
        AWS_PASSIVE_PORT_MIN_DEFAULT, AWS_PASSIVE_PORT_MAX_DEFAULT,
        s->ServerName);
    }

  } else {
    pasv_min_port = *((int *) c->argv[0]);
    pasv_max_port = *((int *) c->argv[1]);
  }

  if (security_groups == NULL) {
    /* No SGs to check. */
    pr_trace_msg(trace_channel, 5,
      "unable to verify whether PassivePorts %d-%d for <VirtualHost> '%s' "
      "allowed by security groups: no security groups found", pasv_min_port,
      pasv_max_port, s->ServerName);
    return;
  }

  pr_table_rewind(security_groups);
  key = pr_table_next(security_groups);
  while (key != NULL) {
    const struct ec2_security_group *sg;

    pr_signals_handle();

    if (pasv_ports_allowed) {
      break;
    }

    sg = pr_table_get(security_groups, key, NULL);
    if (sg != NULL) {
      register unsigned int i;
      struct ec2_ip_rule **rules;

      sg_id = key;

      rules = sg->inbound_rules->elts;
      for (i = 0; i < sg->inbound_rules->nelts; i++) {
        struct ec2_ip_rule *rule;

        rule = rules[i];
        if (rule->from_port >= pasv_min_port &&
            rule->to_port <= pasv_max_port) {
          /* This SG allows access for our PassivePorts.  Good. */

          (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
            "<VirtualHost> '%s' PassivePorts %d-%d allowed by security group "
            "ID %s (%s)", s->ServerName, pasv_min_port, pasv_max_port, sg_id,
            sg->name);
          pasv_ports_allowed = TRUE;
          break;
        }
      }
    }

    key = pr_table_next(security_groups);
  }

  if (pasv_ports_allowed == FALSE) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "<VirtualHost> '%s' PassivePorts %d-%d are NOT ALLOWED by any security "
      "group", s->ServerName, pasv_min_port, pasv_max_port);

    if (!(aws_adjustments & AWS_ADJUST_FL_PASV_PORTS)) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "consider allowing these ports using:\n  aws ec2 authorize-security-group-ingress --group-id %s --protocol tcp --port %d-%d --cidr 0.0.0.0/0",
        sg_id, pasv_min_port, pasv_max_port);

    } else {
      int res, xerrno;
      pool *rule_pool;

      sg_id = get_adjust_sg_id(p, security_groups);
      rule_pool = make_sub_pool(p);

      res = allow_sg_ports(rule_pool, ec2, sg_id, pasv_min_port, pasv_max_port);
      xerrno = errno;
      destroy_pool(rule_pool);

      if (res < 0) {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "error adjusting AWS security group ID %s to allow ports %d-%d: %s",
          sg_id, pasv_min_port, pasv_max_port, strerror(xerrno));

      } else {
        (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
          "adjusted AWS security group ID %s to allow ports %d-%d",
          sg_id, pasv_min_port, pasv_max_port);
      }
    }
  }
}

static void log_instance_info(pool *p, const struct aws_info *info) {

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

  /* API version */
  if (info->api_version != NULL) {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.api-version = '%s'", info->api_version);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "aws.api-version = unavailable");
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

static void open_logfile(void) {
  int res, xerrno;

  if (aws_logfile == NULL) {
    return;
  }

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

static void set_sess_note(pool *p, const char *key, const char *val,
    size_t valsz) {
  if (val == NULL) {
    val = "";
    valsz = 0;

  } else if (valsz == 0) {
    valsz = strlen(val);
  }

  /* Watch out for the non-NUL-terminated strings. */
  if (valsz > 0) {
    val = pstrndup(p, val, valsz);
  }

  if (pr_table_add(session.notes, pstrdup(p, key), (void *) val, valsz) < 0) {
    pr_trace_msg(trace_channel, 2,
      "error stashing '%s' note: %s", key, strerror(errno));
  }
}

/* Configuration handlers
 */

/* usage: AWSAdjustments on|[MasqueradeAddress] [PassivePorts]
 *          [SecurityGroup]
 */
MODRET set_awsadjustments(cmd_rec *cmd) {
  int adjust_all = -1;
  unsigned long adjustments = 0UL;

  if (cmd->argc < 2 ||
      cmd->argc > 4) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  adjust_all = get_boolean(cmd, 1);
  if (adjust_all == TRUE) {
    adjustments = AWS_ADJUST_FL_MASQ_ADDR|AWS_ADJUST_FL_PASV_PORTS|
      AWS_ADJUST_FL_SECURITY_GROUP;

  } else {
    register unsigned int i;

    for (i = 1; i < cmd->argc; i++) {
      if (strcasecmp(cmd->argv[i], "MasqueradeAddress") == 0) {
        adjustments |= AWS_ADJUST_FL_MASQ_ADDR;

      } else if (strcasecmp(cmd->argv[i], "PassivePorts") == 0) {
        adjustments |= AWS_ADJUST_FL_PASV_PORTS;

      } else if (strcasecmp(cmd->argv[i], "SecurityGroup") == 0) {
        adjustments |= AWS_ADJUST_FL_SECURITY_GROUP;

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AWSAdjustment: ",
          cmd->argv[i], NULL));
      }
    }
  }

  aws_adjustments = adjustments;
  return PR_HANDLED(cmd);
}

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

/* usage: AWSCredentials provider1 ... */
MODRET set_awscredentials(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  array_header *providers;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  providers = make_array(c->pool, 1, sizeof(char *));

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "IAM") == 0) {
      *((char **) push_array(providers)) = pstrdup(c->pool,
        AWS_CREDS_PROVIDER_NAME_IAM);

    } else if (strcasecmp(cmd->argv[i], "Profile") == 0) {
      *((char **) push_array(providers)) = pstrdup(c->pool,
        AWS_CREDS_PROVIDER_NAME_PROFILE);

    } else if (strcasecmp(cmd->argv[i], "Properties") == 0) {
      *((char **) push_array(providers)) = pstrdup(c->pool,
        AWS_CREDS_PROVIDER_NAME_PROPERTIES);

    } else if (strcasecmp(cmd->argv[i], "Environment") == 0) {
      *((char **) push_array(providers)) = pstrdup(c->pool,
        AWS_CREDS_PROVIDER_NAME_ENVIRONMENT);

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        ": unknown AWSCredentials provider '", cmd->argv[i], "'", NULL));
    }
  }

  /* Make sure there are no duplicates. */
  for (i = 0; i < providers->nelts; i++) {
    register unsigned int j;
    const char *ith;

    ith = ((char **) providers->elts)[i];
    for (j = i + 1; j < providers->nelts; j++) {
      const char *jth;

      jth = ((char **) providers->elts)[j];
      if (strcmp(ith, jth) == 0) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "provider '", ith,
          "' appears multiple times", NULL));
      }
    }
  }

  c->argv[0] = providers;
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

/* usage: AWSHealthCheck uri [address] [port] */
MODRET set_awshealthcheck(cmd_rec *cmd) {
  if (cmd->argc < 2 ||
      cmd->argc > 4) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT);

  if (strcasecmp(cmd->argv[1], "off") == 0 ||
      strcasecmp(cmd->argv[1], "none") == 0) {
    aws_use_health = FALSE;
    return PR_HANDLED(cmd);
  }

  aws_health_uri = pstrdup(aws_pool, (char *) cmd->argv[1]);

  if (cmd->argc >= 3) {
    const char *name;
    const pr_netaddr_t *addr;

    name = cmd->argv[2];
    addr = pr_netaddr_get_addr(cmd->tmp_pool, name, NULL);
    if (addr == NULL) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to resolve '", name,
        "': ", strerror(errno), NULL));
    }

    aws_health_addr = pstrdup(aws_pool, name);
  }

  if (cmd->argc == 4) {
    const char *port;
    int portno;

    port = cmd->argv[3];
    portno = atoi(port);
    if (portno < 0 ||
        portno > 65535) {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        "invalid port (", port, ")", NULL));
    }

    aws_health_port = portno;
  }

  aws_use_health = TRUE;
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
    if (strcmp(cmd->argv[i], "DryRun") == 0) {
      opts |= AWS_OPT_DRY_RUN;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AWSOption '",
        (char *) cmd->argv[i], "'", NULL));
    }
  }

  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = opts;

  return PR_HANDLED(cmd);
}

/* usage: AWSProfile name */
MODRET set_awsprofile(cmd_rec *cmd) {
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);

  return PR_HANDLED(cmd);
}

/* usage: AWSRegion region */
MODRET set_awsregion(cmd_rec *cmd) {
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pstrdup(c->pool, cmd->argv[1]);

  return PR_HANDLED(cmd);
}

/* usage: AWSSecurityGroup sg-id */
MODRET set_awssecuritygroup(cmd_rec *cmd) {
  const char *sg_id;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  sg_id = cmd->argv[1];
  if (strncmp(sg_id, "sg-", 3) != 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": Invalid security group ID '",
      sg_id, "': does not start with 'sg-'", NULL));
  }

  aws_adjust_sg_id = sg_id;
  return PR_HANDLED(cmd);
}

/* usage: AWSServices service ... */
MODRET set_awsservices(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long services = 0UL;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "CloudWatch") == 0) {
      services |= AWS_SERVICE_CLOUDWATCH;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": unknown AWSService '",
        (char *) cmd->argv[i], "'", NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = palloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = services;

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

/* usage: AWSCloudWatchDimensions ... */
MODRET set_awscloudwatchdimensions(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  unsigned long dimensions = 0UL;

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  for (i = 1; i < cmd->argc; i++) {
    if (strcasecmp(cmd->argv[i], "Protocol") == 0) {
      dimensions |= AWS_CLOUDWATCH_DIMENSION_PROTOCOL;

    } else if (strcasecmp(cmd->argv[i], "InstanceId") == 0) {
      dimensions |= AWS_CLOUDWATCH_DIMENSION_INSTANCE_ID;

    } else if (strcasecmp(cmd->argv[i], "AvailabilityZone") == 0) {
      dimensions |= AWS_CLOUDWATCH_DIMENSION_AVAIL_ZONE;

    } else {
      CONF_ERROR(cmd, pstrcat(cmd->tmp_pool,
        ": unknown AWSCloudWatchDimension '", (char *) cmd->argv[i], "'",
        NULL));
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(unsigned long));
  *((unsigned long *) c->argv[0]) = dimensions;

  return PR_HANDLED(cmd);
}

/* usage: AWSCloudWatchNamespace namespace */
MODRET set_awscloudwatchnamespace(cmd_rec *cmd) {
  char *namespace;
  size_t namespace_len;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  namespace = cmd->argv[1];
  namespace_len = strlen(namespace);

  if (namespace_len < 1) {
    CONF_ERROR(cmd, "namespace parameter too short");
  }

  if (namespace_len > 255) {
    CONF_ERROR(cmd, "namespace parameter too long");
  }

  if (strncmp(namespace, "AWS/", 4) == 0) {
    CONF_ERROR(cmd, "reserved namespace used");
  }

  (void) add_config_param_str(cmd->argv[0], 1, namespace);
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

static void log_tls_metrics(pool *p, cmd_rec *cmd, int had_error,
    uint64_t duration_ms, array_header *dimensions) {
  if (pr_module_exists("mod_tls.c") != TRUE) {
    return;
  }

  if (pr_cmd_cmp(cmd, PR_CMD_AUTH_ID) == 0 &&
      cmd->argc == 2) {
    char *tls_mode;

    /* Find out if the args are one of the mod_tls (vs GSSAPI et al) ones. */

    tls_mode = cmd->argv[1];
    if (strcasecmp(tls_mode, "TLS") == 0 ||
        strcasecmp(tls_mode, "TLS-C") == 0 ||
        strcasecmp(tls_mode, "TLS-P") == 0 ||
        strcasecmp(tls_mode, "SSL") == 0) {
      if (had_error == FALSE) {
        char *protocol_env, *cipher_env;

        aws_cloudwatch_metric_counter(p, aws_cloudwatch, "Connection.FTPS", 1.0,
          dimensions, 0);
        aws_cloudwatch_metric_timer(p, aws_cloudwatch, "TLSHandshake.Elapsed",
         (double) duration_ms, dimensions, 0);

        protocol_env = pr_env_get(p, "TLS_PROTOCOL");
        if (protocol_env != NULL) {
          char *metric;

          metric = pstrcat(p, "TLSProtocol.", protocol_env, NULL);
          aws_cloudwatch_metric_counter(p, aws_cloudwatch, metric, 1.0,
            dimensions, 0);
        }

        cipher_env = pr_env_get(p, "TLS_CIPHER");
        if (cipher_env != NULL) {
          char *metric;

          metric = pstrcat(p, "TLSCipher.", cipher_env, NULL);
          aws_cloudwatch_metric_counter(p, aws_cloudwatch, metric, 1.0,
            dimensions, 0);
        }
      }
    }
  }
}

static void log_cmd_metrics(cmd_rec *cmd, int had_error) {
  pool *tmp_pool;
  array_header *dimensions;
  const uint64_t *start_ms = NULL;
  uint64_t now_ms = 0, duration_ms = 0;

  if (aws_cloudwatch == NULL) {
    return;
  }

  pr_gettimeofday_millis(&now_ms);

  tmp_pool = make_sub_pool(cmd->tmp_pool);
  dimensions = aws_cloudwatch_dimension_get(tmp_pool, aws_cloudwatch_dimensions,
    instance_info);

  start_ms = pr_table_get(cmd->notes, "start_ms", NULL);
  if (start_ms != NULL) {
    duration_ms = now_ms - *start_ms;
  }

  log_tls_metrics(tmp_pool, cmd, had_error, duration_ms, dimensions);

  switch (cmd->cmd_id) {
    case PR_CMD_LIST_ID:
    case PR_CMD_MLSD_ID:
    case PR_CMD_NLST_ID:
      if (had_error == FALSE) {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch,
          "DirectoryList.Success", 1.0, dimensions, 0);

      } else {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch,
          "DirectoryList.Failed", 1.0, dimensions, 0);
      }

      aws_cloudwatch_metric_timer(tmp_pool, aws_cloudwatch, "DirectoryList.Elapsed",
        (double) duration_ms, dimensions, 0);
      break;

    case PR_CMD_RETR_ID:
      if (had_error == FALSE) {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch,
          "FileDownload.Success", 1.0, dimensions, 0);

      } else {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch,
          "FileDownload.Failed", 1.0, dimensions, 0);
      }

      aws_cloudwatch_metric_timer(tmp_pool, aws_cloudwatch, "FileDownload.Elapsed",
        (double) duration_ms, dimensions, 0);
      break;

    case PR_CMD_APPE_ID:
    case PR_CMD_STOR_ID:
    case PR_CMD_STOU_ID:
      if (had_error == FALSE) {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch,
          "FileUpload.Success", 1.0, dimensions, 0);

      } else {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch,
          "FileUpload.Failed", 1.0, dimensions, 0);
      }

      aws_cloudwatch_metric_timer(tmp_pool, aws_cloudwatch, "FileUpload.Elapsed",
        (double) duration_ms, dimensions, 0);
      break;

    case PR_CMD_PASS_ID:
      if (had_error == FALSE) {
        const char *proto;

        proto = pr_session_get_protocol(0);
        if (strcmp(proto, "ftp") == 0) {
          /* At this point in time, we are certain that we have a plain FTP
           * connection, not FTPS or anything else.
           */
          aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch, "Connection.FTP",
            1.0, dimensions, 0);
        }

        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch, "Login.Success",
          1.0, dimensions, 0);

      } else {
        aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch, "Login.Failed",
          1.0, dimensions, 0);
      }

      aws_cloudwatch_metric_timer(tmp_pool, aws_cloudwatch, "Login.Elapsed",
        (double) duration_ms, dimensions, 0);
      break;

    default:
      /* Ignore */
      break;
  }

  aws_cloudwatch_conn_flush(tmp_pool, aws_cloudwatch);
  destroy_pool(tmp_pool);
}

MODRET aws_log_any(cmd_rec *cmd) {
  if (aws_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  log_cmd_metrics(cmd, FALSE);
  return PR_DECLINED(cmd);
}

MODRET aws_log_any_err(cmd_rec *cmd) {
  if (aws_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  log_cmd_metrics(cmd, TRUE);
  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void aws_exit_ev(const void *event_data, void *user_data) {
  if (aws_cloudwatch != NULL) {
    const char *metric;
    array_header *dimensions;
    unsigned char *authenticated;

    metric = "Connection";
    dimensions = aws_cloudwatch_dimension_get(aws_pool,
      aws_cloudwatch_dimensions, instance_info);
    aws_cloudwatch_metric_counter(aws_pool, aws_cloudwatch, metric, -1.0,
      dimensions, 0);

    authenticated = get_param_ptr(main_server->conf, "authenticated", FALSE);
    if (authenticated != NULL &&
        *authenticated == TRUE) {
      uint64_t now_ms = 0, sess_ms;

      aws_cloudwatch_metric_counter(aws_pool, aws_cloudwatch, metric, -1.0,
        dimensions, 0);

      pr_gettimeofday_millis(&now_ms);
      sess_ms = now_ms - aws_sess_start_ms;
      aws_cloudwatch_metric_timer(aws_pool, aws_cloudwatch, metric,
        (double) sess_ms, dimensions, 0);
    }

    aws_cloudwatch_conn_destroy(aws_pool, aws_cloudwatch);
    aws_cloudwatch = NULL;
  }
}

#if defined(PR_SHARED_MODULE)
static void aws_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp((const char *) event_data, "mod_aws.c") != 0) {
    return;
  }

  /* Unregister ourselves from all events and timers. */
  pr_event_unregister(&aws_module, NULL, NULL);
  pr_timer_remove(-1, &aws_module);

  if (instance_health != NULL) {
    if (aws_health_listener_destroy(aws_pool, instance_health) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error destroying healthcheck listener: %s", strerror(errno));
    }

    instance_health = NULL;
  }

  aws_http_free();
  aws_xml_free();
  destroy_pool(aws_pool);
  aws_pool = NULL;

  if (aws_logfd >= 0) {
    (void) close(aws_logfd);
    aws_logfd = -1;
  }
}
#endif /* PR_SHARED_MODULE */

static void aws_restart_ev(const void *event_data, void *user_data) {
  int res;
  const char *http_details = NULL;

  if (instance_health != NULL) {
    if (aws_health_listener_destroy(aws_pool, instance_health) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error destroying healthcheck listener: %s", strerror(errno));
    }

    instance_health = NULL;
  }

  aws_http_free();

  /* Note: We explicitly do NOT call aws_xml_free() here. */

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

  /* Reset timeouts. */
  aws_connect_timeout_secs = AWS_CONNECT_DEFAULT_TIMEOUT;
  aws_request_timeout_secs = AWS_REQUEST_DEFAULT_TIMEOUT;

  if (aws_logfd >= 0) {
    (void) close(aws_logfd);
    open_logfile();
  }
}

static void aws_shutdown_ev(const void *event_data, void *user_data) {
  /* XXX Unregister from ELB, or Route53 */

  if (instance_health != NULL) {
    if (aws_health_listener_destroy(aws_pool, instance_health) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error destroying healthcheck listener: %s", strerror(errno));
    }

    instance_health = NULL;
  }

  aws_http_free();
  aws_xml_free();

  destroy_pool(aws_pool);
  aws_pool = NULL;

  if (aws_logfd >= 0) {
    (void) close(aws_logfd);
    aws_logfd = -1;
  }
}

static void incr_metric(const char *metric, double incr) {
  if (aws_cloudwatch != NULL) {
    pool *tmp_pool;
    array_header *dimensions;

    tmp_pool = make_sub_pool(aws_pool);
    dimensions = aws_cloudwatch_dimension_get(tmp_pool,
      aws_cloudwatch_dimensions, instance_info);
    aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch, metric, incr, dimensions,
      0);
    aws_cloudwatch_conn_flush(tmp_pool, aws_cloudwatch);
    destroy_pool(tmp_pool);
  }
}

static void aws_ssh2_scp_sess_opened_ev(const void *event_data, void *user_data) {
  incr_metric("Connection.SCP", 1.0);
}

static void aws_ssh2_sftp_sess_opened_ev(const void *event_data, void *user_data) {
  incr_metric("Connection.SFTP", 1.0);
}

static void aws_sql_db_conn_closed_ev(const void *event_data, void *user_data) {
  incr_metric("Connection.SQL", -1.0);
}

static void aws_sql_db_conn_opened_ev(const void *event_data, void *user_data) {
  incr_metric("Connection.SQL", 1.0);
}

static void aws_sql_db_error_ev(const void *event_data, void *user_data) {
  incr_metric("Error.SQL", 1.0);
}

static int aws_health_listening(pool *p, const char *addr, int port,
    const char *uri) {
  int res = 0, xerrno = 0;

  (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
    "creating AWSHealthCheck listener for http://%s:%d%s", addr, port, uri);

  instance_health = aws_health_listener_create(aws_pool, addr, port, uri, -1,
    NULL);
  xerrno = errno;

  if (instance_health != NULL) {
    pr_trace_msg(trace_channel, 8,
      "listening for AWSHealthCheck http://%s:%d%s", addr, port, uri);

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "error listening for AWSHealthCheck http://%s:%d%s: %s",
      addr, port, uri, strerror(xerrno));
  }

  errno = xerrno;
  return res;
}

static void aws_startup_ev(const void *event_data, void *user_data) {
  server_rec *s = NULL;
  struct ec2_conn *ec2 = NULL;
  struct route53_conn *route53 = NULL;
  pr_table_t *security_groups = NULL;

  if (aws_engine == FALSE) {
    return;
  }

  open_logfile();

  /* If we should be listening for health checks, AND we have already been
   * given an explicit AWSHealthCheck address, then start our listener here.
   * Otherwise, we will wait until we have the EC2 instance' public IPv4
   * address.
   */
  if (aws_use_health == TRUE &&
      aws_health_addr != NULL) {
    (void) aws_health_listening(aws_pool, aws_health_addr, aws_health_port,
      aws_health_uri);
  }

  instance_info = aws_instance_get_info(aws_pool);
  if (instance_info == NULL) {
    pr_log_debug(DEBUG1, MOD_AWS_VERSION
      ": unable to discover EC2 instance metadata: %s", strerror(errno));
    return;
  }

  if (instance_info->domain == NULL) {
    /* Nothing more to do at this time; the subsequent code deals with the
     * EC2 environment.
     *
     * However, we DO provide other AWS functionality outside of EC2, so we
     * do not want to simply disable the module here.
     */

    pr_log_debug(DEBUG1, MOD_AWS_VERSION
      ": no EC2 instance metadata available (not running within AWS EC2)");
    instance_info = NULL;

    return;
  }

  log_instance_info(aws_pool, instance_info);

  if (aws_use_health == TRUE &&
      instance_health == NULL) {
    const char *addr = NULL;

    /* Use the public IPv4 address, if we have one.  If not, fall back to
     * the local/private IPv4 address.
     */
    if (instance_info->public_ipv4 != NULL) {
      addr = pstrndup(aws_pool, instance_info->public_ipv4,
        instance_info->public_ipv4sz);

    } else if (instance_info->local_ipv4 != NULL) {
      addr = pstrndup(aws_pool, instance_info->local_ipv4,
        instance_info->local_ipv4sz);
    }

    aws_health_addr = addr;

    if (aws_health_addr != NULL) {
      (void) aws_health_listening(aws_pool, aws_health_addr, aws_health_port,
        aws_health_uri);

    } else {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "unable to listen for AWSHealthCheck: unable to discover address");
    }
  }

  /* Assume that we can only perform discovery/configuration via AWS services
   * if we have an IAM role, which in turn means we have the necessary
   * credentials for constructing the necessary signatures for talking to
   * AWS services.
   */
  if (instance_info->iam_role != NULL) {
    const char *domain, *iam_role;
    struct aws_credential_info *cred_info = NULL;

    domain = pstrndup(aws_pool, instance_info->domain, instance_info->domainsz);
    iam_role = pstrndup(aws_pool, instance_info->iam_role,
      instance_info->iam_rolesz);

    cred_info = pcalloc(aws_pool, sizeof(struct aws_credential_info));
    cred_info->iam_role = iam_role;

    ec2 = aws_ec2_conn_alloc(aws_pool, aws_connect_timeout_secs,
      aws_request_timeout_secs, aws_cacerts, instance_info->region, domain,
      NULL, cred_info);

    route53 = aws_route53_conn_alloc(aws_pool, aws_connect_timeout_secs,
      aws_request_timeout_secs, aws_cacerts, domain, NULL, cred_info);

    if (instance_info->security_groups != NULL) {
      const char *vpc_id = NULL;

      if (instance_info->vpc_id != NULL) {
        vpc_id = pstrndup(aws_pool, instance_info->vpc_id,
          instance_info->vpc_idsz);
      }

      security_groups = aws_ec2_get_security_groups(aws_pool, ec2, vpc_id,
        instance_info->security_groups);
    }

  } else {
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "no IAM role configured for this instance, unable to auto-configure");
    (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
      "recommended commands will thus be logged");
  }

  for (s = (server_rec *) server_list->xas_list; s; s = s->next) {
    /* Verify control port access */
    verify_ctrl_port(aws_pool, instance_info, ec2, s, security_groups);

    /* Verify MasqueradeAddress */
    verify_masq_addr(aws_pool, instance_info, s);

    /* Verify PassivePorts access */
    verify_pasv_ports(aws_pool, instance_info, ec2, s, security_groups);
  }

  /* XXX Register with Route53 */

  if (ec2 != NULL) {
    aws_ec2_conn_destroy(aws_pool, ec2);
    ec2 = NULL;
  }

  if (route53 != NULL) {
    aws_route53_conn_destroy(aws_pool, route53);
    route53 = NULL;
  }

  /* XXX Watch out for any fds that should NOT be opened (0, 1, 2), but
   * which may be help open by e.g. libcurl.  If necessary, force-close them.
   */
}

static void aws_timeout_idle_ev(const void *event_data, void *user_data) {
  incr_metric("TimeoutIdle", 1.0);
}

static void aws_timeout_login_ev(const void *event_data, void *user_data) {
  incr_metric("TimeoutLogin", 1.0);
}

static void aws_timeout_noxfer_ev(const void *event_data, void *user_data) {
  incr_metric("TimeoutNoTransfer", 1.0);
}

static void aws_timeout_session_ev(const void *event_data, void *user_data) {
  incr_metric("TimeoutSession", 1.0);
}

static void aws_timeout_stalled_ev(const void *event_data, void *user_data) {
  incr_metric("TimeoutStalled", 1.0);
}

static void aws_tls_handshake_error_ev(const void *event_data,
    void *user_data) {
  incr_metric("TLSHandshake.Error", 1.0);
}

/* XXX Do we want to support any Controls/ftpctl actions? */

/* Initialization routines
 */

static int aws_init(void) {
  const char *http_details = NULL;

  aws_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(aws_pool, MOD_AWS_VERSION);

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

  aws_xml_init(aws_pool);

#if defined(PR_SHARED_MODULE)
  pr_event_register(&aws_module, "core.module-unload", aws_mod_unload_ev,
    NULL);
#endif
  pr_event_register(&aws_module, "core.restart", aws_restart_ev, NULL);
  pr_event_register(&aws_module, "core.shutdown", aws_shutdown_ev, NULL);
  pr_event_register(&aws_module, "core.startup", aws_startup_ev, NULL);

  return 0;
}

static int aws_sess_init(void) {
  config_rec *c;

  if (aws_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "AWSProfile", FALSE);
  if (c != NULL) {
    aws_profile = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "AWSCredentials", FALSE);
  if (c != NULL) {
    aws_creds_providers = c->argv[0];
  }

  c = find_config(main_server->conf, CONF_PARAM, "AWSRegion", FALSE);
  if (c != NULL) {
    aws_region = c->argv[0];

  } else {
    const char *region_env;

    region_env = pr_env_get(session.pool, "AWS_DEFAULT_REGION");
    if (region_env != NULL) {
      aws_region = pstrdup(session.pool, region_env);
    }
  }

  /* Remove all timers registered during e.g. startup; we only want those
   * timers firing in the daemon process, not in session processes.
   */
  pr_timer_remove(-1, &aws_module);

  /* Likewise, close any inherited health listeners. */
  if (instance_health != NULL) {
    if (aws_health_listener_destroy(aws_pool, instance_health) < 0) {
      (void) pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error destroying healthcheck listener: %s", strerror(errno));
    }

    instance_health = NULL;
  }

  if (instance_info != NULL) {
    /* Make all of the instance metadata available for logging by stashing the
     * metadata in the session's notes table.
     */

    set_sess_note(session.pool, "aws.domain",
      instance_info->domain, instance_info->domainsz);
    set_sess_note(session.pool, "aws.account-id",
      instance_info->account_id, 0);
    set_sess_note(session.pool, "aws.api-version",
      instance_info->api_version, 0);
    set_sess_note(session.pool, "aws.region",
      instance_info->region, 0);
    set_sess_note(session.pool, "aws.avail-zone",
      instance_info->avail_zone, instance_info->avail_zonesz);
    set_sess_note(session.pool, "aws.instance-type",
      instance_info->instance_type, instance_info->instance_typesz);
    set_sess_note(session.pool, "aws.instance-id",
      instance_info->instance_id, instance_info->instance_idsz);
    set_sess_note(session.pool, "aws.ami-id",
      instance_info->ami_id, instance_info->ami_idsz);
    set_sess_note(session.pool, "aws.iam-role",
      instance_info->iam_role, instance_info->iam_rolesz);
    set_sess_note(session.pool, "aws.mac",
      instance_info->hw_mac, instance_info->hw_macsz);
    set_sess_note(session.pool, "aws.vpc-id",
      instance_info->vpc_id, instance_info->vpc_idsz);
    set_sess_note(session.pool, "aws.subnet-id",
      instance_info->subnet_id, instance_info->subnet_idsz);
    set_sess_note(session.pool, "aws.local-ipv4",
      instance_info->local_ipv4, instance_info->local_ipv4sz);
    set_sess_note(session.pool, "aws.local-hostname",
      instance_info->local_hostname, instance_info->local_hostnamesz);
    set_sess_note(session.pool, "aws.public-ipv4",
      instance_info->public_ipv4, instance_info->public_ipv4sz);
    set_sess_note(session.pool, "aws.public-hostname",
      instance_info->public_hostname, instance_info->public_hostnamesz);

    if (instance_info->security_groups != NULL) {
      register unsigned int i;
      char **elts, *sg_ids = "";

      elts = instance_info->security_groups->elts;
      for (i = 0; i < instance_info->security_groups->nelts; i++) {
        sg_ids = pstrcat(session.pool, sg_ids, *sg_ids ? ", " : "", elts[i],
          NULL);
      }

      set_sess_note(session.pool, "aws.security-groups", sg_ids, 0);

    } else {
      set_sess_note(session.pool, "aws.security-groups", NULL, 0);
    }
  }

  c = find_config(main_server->conf, CONF_PARAM, "AWSServices", FALSE);
  while (c != NULL) {
    unsigned long services;

    pr_signals_handle();

    services = *((unsigned long *) c->argv[0]);
    aws_services |= services;

    c = find_config_next(c, c->next, CONF_PARAM, "AWSServices", FALSE);
  }

  if (aws_services & AWS_SERVICE_CLOUDWATCH) {
    pool *tmp_pool;
    const char *domain = NULL, *iam_role = NULL, *region = NULL;
    struct aws_credential_info *cred_info = NULL;
    array_header *dimensions;

    c = find_config(main_server->conf, CONF_PARAM, "AWSCloudWatchDimensions",
      FALSE);
    if (c != NULL) {
      aws_cloudwatch_dimensions = *((unsigned long *) c->argv[0]);
    }

    c = find_config(main_server->conf, CONF_PARAM, "AWSCloudWatchNamespace",
      FALSE);
    if (c != NULL) {
      aws_cloudwatch_namespace = c->argv[0];
    }

    tmp_pool = make_sub_pool(aws_pool);

    if (instance_info != NULL) {
      domain = pstrndup(tmp_pool, instance_info->domain,
        instance_info->domainsz);
      iam_role = pstrndup(tmp_pool, instance_info->iam_role,
        instance_info->iam_rolesz);
      region = instance_info->region;
      if (aws_region != NULL) {
        region = aws_region;
      }

    } else {
      /* Note: ASSUME that the domain is "amazonaws.com". */
      domain = pstrdup(tmp_pool, "amazonaws.com");
      region = aws_region;
    }

    cred_info = pcalloc(tmp_pool, sizeof(struct aws_credential_info));
    cred_info->iam_role = iam_role;

    aws_cloudwatch = aws_cloudwatch_conn_alloc(aws_pool,
      aws_connect_timeout_secs, aws_request_timeout_secs, aws_cacerts,
      region, domain, aws_creds_providers, cred_info, aws_cloudwatch_namespace);
    if (aws_cloudwatch != NULL) {
      pr_event_register(&aws_module, "core.timeout-idle",
        aws_timeout_idle_ev, NULL);
      pr_event_register(&aws_module, "core.timeout-login",
        aws_timeout_login_ev, NULL);
      pr_event_register(&aws_module, "core.timeout-no-transfer",
        aws_timeout_noxfer_ev, NULL);
      pr_event_register(&aws_module, "core.timeout-session",
        aws_timeout_session_ev, NULL);
      pr_event_register(&aws_module, "core.timeout-stalled",
        aws_timeout_stalled_ev, NULL);

      if (pr_module_exists("mod_sftp.c") == TRUE) {
        pr_event_register(&aws_module, "mod_sftp.sftp.session-opened",
          aws_ssh2_sftp_sess_opened_ev, NULL);
        pr_event_register(&aws_module, "mod_sftp.scp.session-opened",
          aws_ssh2_scp_sess_opened_ev, NULL);
      }

      if (pr_module_exists("mod_sql.c") == TRUE) {
        pr_event_register(&aws_module, "mod_sql.db.connection-opened",
          aws_sql_db_conn_opened_ev, NULL);
        pr_event_register(&aws_module, "mod_sql.db.connection-closed",
          aws_sql_db_conn_closed_ev, NULL);
        pr_event_register(&aws_module, "mod_sql.db.error",
          aws_sql_db_error_ev, NULL);
      }

      if (pr_module_exists("mod_tls.c") == TRUE) {
        pr_event_register(&aws_module, "mod_tls.ctrl-handshake-failed",
          aws_tls_handshake_error_ev, NULL);
        pr_event_register(&aws_module, "mod_tls.data-handshake-failed",
          aws_tls_handshake_error_ev, NULL);
      }

      /* We only want to set the session start time once; this function could be
       * called again due to e.g. a HOST command, and we do not want to reset
       * the start time in that case.
       */
      if (aws_sess_start_ms == 0) {
        pr_gettimeofday_millis(&aws_sess_start_ms);
      }

      dimensions = aws_cloudwatch_dimension_get(tmp_pool,
        aws_cloudwatch_dimensions, instance_info);
      aws_cloudwatch_metric_counter(tmp_pool, aws_cloudwatch, "Connection", 1.0,
        dimensions, 0);
      aws_cloudwatch_conn_flush(tmp_pool, aws_cloudwatch);

    } else {
      pr_log_writefile(aws_logfd, MOD_AWS_VERSION,
        "error opening CloudWatch connection: %s", strerror(errno));
    }

    destroy_pool(tmp_pool);
  }

  pr_event_register(&aws_module, "core.exit", aws_exit_ev, NULL);

  return 0;
}

/* Module API tables
 */

static conftable aws_conftab[] = {
  { "AWSAdjustments",		set_awsadjustments,	NULL },
  { "AWSCACertificateFile",	set_awscacertfile,	NULL },
  { "AWSCredentials",		set_awscredentials,	NULL },
  { "AWSEngine",		set_awsengine,		NULL },
  { "AWSHealthCheck",		set_awshealthcheck,	NULL },
  { "AWSLog",			set_awslog,		NULL },
  { "AWSOptions",		set_awsoptions,		NULL },
  { "AWSProfile",		set_awsprofile,		NULL },
  { "AWSRegion",		set_awsregion,		NULL },
  { "AWSSecurityGroup",		set_awssecuritygroup,	NULL },
  { "AWSServices",		set_awsservices,	NULL },
  { "AWSTimeoutConnect",	set_awstimeoutconnect,	NULL },
  { "AWSTimeoutRequest",	set_awstimeoutrequest,	NULL },

  /* CloudWatch */
  { "AWSCloudWatchDimensions",	set_awscloudwatchdimensions,	NULL },
  { "AWSCloudWatchNamespace",	set_awscloudwatchnamespace,	NULL },

  { NULL }
};

static cmdtable aws_cmdtab[] = {
  { LOG_CMD,		C_ANY,	G_NONE,	aws_log_any,		FALSE,	FALSE },
  { LOG_CMD_ERR,	C_ANY,	G_NONE,	aws_log_any_err,	FALSE,	FALSE },

  { 0, NULL }
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
  aws_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization */
  aws_init,

  /* Session initialization */
  aws_sess_init,

  /* Module version */
  MOD_AWS_VERSION
};
