/*
   SSSD

   SSS Client Responder, header file

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __SSS_RESPONDER_H__
#define __SSS_RESPONDER_H__

#include <stdint.h>
#include <sys/un.h>
#include <pcre.h>
#include "config.h"
#include "talloc.h"
#include "tevent.h"
#include "ldb.h"
#include "dhash.h"
#include "sbus/sssd_dbus.h"
#include "sss_client/sss_cli.h"

extern hash_table_t *dp_requests;

/* if there is a provider other than the special local */
#define NEED_CHECK_PROVIDER(provider) \
    (provider != NULL && strcmp(provider, "local") != 0)

/* needed until nsssrv.h is updated */
struct cli_request {

    /* original request from the wire */
    struct sss_packet *in;

    /* reply data */
    struct sss_packet *out;
};

struct cli_protocol_version {
    uint32_t version;
    const char *date;
    const char *description;
};

struct be_conn {
    struct be_conn *next;
    struct be_conn *prev;

    const char *cli_name;
    struct sss_domain_info *domain;

    char *sbus_address;
    struct sbus_interface *intf;
    struct sbus_connection *conn;
};

struct resp_ctx {
    struct tevent_context *ev;
    struct tevent_fd *lfde;
    int lfd;
    struct tevent_fd *priv_lfde;
    int priv_lfd;
    struct confdb_ctx *cdb;
    const char *sock_name;
    const char *priv_sock_name;

    struct sbus_connection *mon_conn;
    struct be_conn *be_conns;

    struct sss_domain_info *domains;
    struct sysdb_ctx_list *db_list;

    struct sss_cmd_table *sss_cmds;
    const char *sss_pipe_name;
    const char *confdb_service_path;

    struct sss_names_ctx *names;

    hash_table_t *dp_request_table;

    void *pvt_ctx;
};

/* Needed for the NSS responder */
struct getent_ref_tracker {
    void *pvt;
};

struct cli_ctx {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    int cfd;
    struct tevent_fd *cfde;
    struct sockaddr_un addr;
    struct cli_request *creq;
    struct cli_protocol_version *cli_protocol_version;
    int priv;
    int32_t client_euid;
    int32_t client_egid;
    int32_t client_pid;

    int pwent_dom_idx;
    int pwent_cur;

    int grent_dom_idx;
    int grent_cur;

    char *netgr_name;
    int netgrent_cur;

    time_t pam_timeout;
};

struct sss_cmd_table {
    enum sss_cli_command cmd;
    int (*fn)(struct cli_ctx *cctx);
};

/* responder_common.c */
int sss_process_init(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct confdb_ctx *cdb,
                     struct sss_cmd_table sss_cmds[],
                     const char *sss_pipe_name,
                     const char *sss_priv_pipe_name,
                     const char *confdb_service_path,
                     const char *svc_name,
                     uint16_t svc_version,
                     struct sbus_interface *monitor_intf,
                     const char *cli_name,
                     struct sbus_interface *dp_intf,
                     struct resp_ctx **responder_ctx);

int sss_parse_name(TALLOC_CTX *memctx,
                   struct sss_names_ctx *snctx,
                   const char *orig, char **domain, char **name);

int sss_dp_get_domain_conn(struct resp_ctx *rctx, const char *domain,
                           struct be_conn **_conn);
struct sss_domain_info *
responder_get_domain(struct sss_domain_info *doms, const char *domain);

/* responder_cmd.c */
int sss_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds);
void sss_cmd_done(struct cli_ctx *cctx, void *freectx);
int sss_cmd_get_version(struct cli_ctx *cctx);
struct cli_protocol_version *register_cli_protocol_version(void);

#define SSS_DP_USER 1
#define SSS_DP_GROUP 2
#define SSS_DP_INITGROUPS 3
#define SSS_DP_NETGR 4

typedef void (*sss_dp_callback_t)(uint16_t err_maj, uint32_t err_min,
                                  const char *err_msg, void *ptr);

struct dp_callback_ctx {
    sss_dp_callback_t callback;
    void *ptr;

    void *mem_ctx;
    struct cli_ctx *cctx;
};

void handle_requests_after_reconnect(void);

int responder_logrotate(DBusMessage *message,
                        struct sbus_connection *conn);

/* Send a request to the data provider
 * Once this function is called, the communication
 * with the data provider will always run to
 * completion. Freeing the returned tevent_req will
 * cancel the notification of completion, but not
 * the data provider action.
 */
struct tevent_req *
sss_dp_get_account_send(TALLOC_CTX *mem_ctx,
                        struct resp_ctx *rctx,
                        struct sss_domain_info *dom,
                        bool fast_reply,
                        int type,
                        const char *opt_name,
                        uint32_t opt_id);
errno_t
sss_dp_get_account_recv(TALLOC_CTX *mem_ctx,
                        struct tevent_req *req,
                        dbus_uint16_t *err_maj,
                        dbus_uint32_t *err_min,
                        char **err_msg);

bool sss_utf8_check(const uint8_t *s, size_t n);

#endif /* __SSS_RESPONDER_H__ */
