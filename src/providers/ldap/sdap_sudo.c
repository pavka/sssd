/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include <string.h>

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_sudo.h"

static void sdap_sudo_reply(struct sdap_sudo_ctx *sudo_ctx, int errcode)
{
    struct be_req *be_req = sudo_ctx->be_req;

    talloc_zfree(sudo_ctx);

    if (errcode == EOK) {
        sdap_handler_done(be_req, DP_ERR_OK, errcode, strerror(errcode));
    } else {
        sdap_handler_done(be_req, DP_ERR_FATAL, errcode, strerror(errcode));
    }
}

static void sdap_sudo_reply_offline(struct sdap_sudo_ctx *sudo_ctx)
{
    struct be_req *be_req = sudo_ctx->be_req;

    talloc_zfree(sudo_ctx);

    sdap_handler_done(be_req, DP_ERR_OFFLINE, EAGAIN, "Provider is offline");
}

static int  sdap_sudo_connect(struct sdap_sudo_ctx *sudo_ctx);
static void sdap_sudo_connect_done(struct tevent_req *subreq);
static int sdap_sudo_load_sudoers(struct sdap_sudo_ctx *sudo_ctx);
static void sdap_sudo_load_sudoers_done(struct tevent_req *subreq);
static int sdap_sudo_purge_sudoers(struct sdap_sudo_ctx *sudo_ctx);
static int sdap_sudo_store_sudoers(struct sdap_sudo_ctx *sudo_ctx,
                                   size_t replies_count,
                                   struct sysdb_attrs **replies);

void sdap_sudo_handler(struct be_req *be_req)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct sdap_id_ctx *id_ctx = NULL;
    int ret = EOK;

    DEBUG(SSSDBG_TRACE_FUNC, ("Entering sdap_sudo_handler()\n"));

    id_ctx = talloc_get_type(be_req->be_ctx->bet_info[BET_SUDO].pvt_bet_data,
                             struct sdap_id_ctx);

    sudo_ctx = talloc_zero(be_req, struct sdap_sudo_ctx);
    if (!sudo_ctx) {
        ret = ENOMEM;
        goto fail;
    }

    sudo_ctx->be_ctx = id_ctx->be;
    sudo_ctx->be_req = be_req;
    sudo_ctx->sdap_ctx = id_ctx;
    sudo_ctx->sdap_op = NULL;
    sudo_ctx->sdap_conn_cache = id_ctx->conn_cache;

    ret = sdap_sudo_connect(sudo_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    be_req->fn(be_req, DP_ERR_FATAL, ret, NULL);
}

int sdap_sudo_connect(struct sdap_sudo_ctx *sudo_ctx)
{
    struct tevent_req *subreq = NULL;
    int ret;

    if (be_is_offline(sudo_ctx->be_ctx)) {
        sdap_sudo_reply_offline(sudo_ctx);
        return EOK;
    }

    if (sudo_ctx->sdap_op == NULL) {
        sudo_ctx->sdap_op = sdap_id_op_create(sudo_ctx,
                                              sudo_ctx->sdap_conn_cache);
        if (sudo_ctx->sdap_op == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("sdap_id_op_create() failed\n"));
            return EIO;
        }
    }

    subreq = sdap_id_op_connect_send(sudo_ctx->sdap_op, sudo_ctx, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("sdap_id_op_connect_send() failed: %d(%s)\n", ret, strerror(ret)));
        talloc_zfree(sudo_ctx->sdap_op);
        return ret;
    }

    tevent_req_set_callback(subreq, sdap_sudo_connect_done, sudo_ctx);

    return EOK;
}

void sdap_sudo_connect_done(struct tevent_req *subreq)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    int dp_error;
    int ret;

    sudo_ctx = tevent_req_callback_data(subreq, struct sdap_sudo_ctx);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (dp_error == DP_ERR_OFFLINE) {
        talloc_zfree(sudo_ctx->sdap_op);
        sdap_sudo_reply_offline(sudo_ctx);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("SUDO LDAP connection failed - %s\n", strerror(ret)));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("SUDO LDAP connection successful\n"));

    ret = sdap_sudo_purge_sudoers(sudo_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to purge sudoers cache\n"));
        goto fail;
    }

    ret = sdap_sudo_load_sudoers(sudo_ctx);
    if (ret != EOK) {
        goto fail;
    }

    return;

fail:
    sdap_sudo_reply(sudo_ctx, ret);
}

int sdap_sudo_load_sudoers(struct sdap_sudo_ctx *sudo_ctx)
{
    struct tevent_req *subreq = NULL;
    struct be_ctx *be_ctx = sudo_ctx->be_ctx;
    struct sdap_id_ctx *sdap_ctx = sudo_ctx->sdap_ctx;
    struct sdap_search_base *search_base = NULL;
    struct sdap_search_base **search_bases = NULL;
    const char *filter = NULL;
    static const char *attrs[] = {
        SDAP_SUDO_ATTR_CN,
        SDAP_SUDO_ATTR_USER,
        SDAP_SUDO_ATTR_HOST,
        SDAP_SUDO_ATTR_COMMAND,
        SDAP_SUDO_ATTR_OPTION,
        SDAP_SUDO_ATTR_RUNASUSER,
        SDAP_SUDO_ATTR_RUNASGROUP,
        SDAP_SUDO_ATTR_NOTBEFORE,
        SDAP_SUDO_ATTR_NOTAFTER,
        SDAP_SUDO_ATTR_ORDER,
        NULL
    };

    for (search_bases = sdap_ctx->opts->sudo_search_bases;
         *search_bases != NULL; search_bases++) {
        search_base = *search_bases;

        if (search_base->filter != NULL) {
            filter = talloc_asprintf(sudo_ctx, "(&%s" SDAP_SUDO_FILTER ")",
                                     search_base->filter);
            if (filter == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf() failed\n"));
                return ENOMEM;
            }
        } else {
            filter = talloc_strdup(sudo_ctx, SDAP_SUDO_FILTER);
        }

        DEBUG(0, ("\n\n\nFilter: %s\n\n\n", filter));

        subreq = sdap_get_generic_send(sudo_ctx,
                                       be_ctx->ev,
                                       sdap_ctx->opts,
                                       sdap_id_op_handle(sudo_ctx->sdap_op),
                                       search_base->basedn,
                                       search_base->scope,
                                       filter,
                                       attrs,
                                       NULL, /* map */
                                       0,    /* num map */
                                       dp_opt_get_int(sdap_ctx->opts->basic,
                                                      SDAP_ENUM_SEARCH_TIMEOUT));
        if (subreq == NULL) {
            return EIO;
        }

        tevent_req_set_callback(subreq, sdap_sudo_load_sudoers_done, sudo_ctx);
    }

    return EOK;
}

void sdap_sudo_load_sudoers_done(struct tevent_req *subreq)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    struct sysdb_attrs **replies = NULL;
    size_t replies_count = 0;
    int ret;

    DEBUG(SSSDBG_TRACE_FUNC, ("Entering sdap_sudo_load_sudoers_done()\n"));

    sudo_ctx = tevent_req_callback_data(subreq, struct sdap_sudo_ctx);

    ret = sdap_get_generic_recv(subreq, sudo_ctx, &replies_count, &replies);
    if (ret != EOK) {
        goto fail;
    }

    ret = sdap_sudo_store_sudoers(sudo_ctx, replies_count, replies);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to store sudoers in cache\n"));
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sudoers is successfuly stored in cache\n"));

    sdap_sudo_reply(sudo_ctx, EOK);

    return;

fail:
    sdap_sudo_reply(sudo_ctx, ret);
}

int sdap_sudo_purge_sudoers(struct sdap_sudo_ctx *sudo_ctx)
{
    struct sysdb_ctx *sysdb_ctx = sudo_ctx->be_ctx->sysdb;
    struct ldb_dn *base_dn = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_sudo_dn(sysdb_ctx, tmp_ctx, sudo_ctx->be_ctx->domain->name);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_delete_recursive(sysdb_ctx, base_dn, true);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("sysdb_delete_recursive() failed.\n"));
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sdap_sudo_store_sudoers(struct sdap_sudo_ctx *sudo_ctx,
                            size_t replies_count,
                            struct sysdb_attrs **replies)
{
    struct sysdb_ctx *sysdb_ctx = sudo_ctx->be_ctx->sysdb;
    const char *name = NULL;
    bool in_transaction = false;
    int ret = EOK;
    int i = 0;

    ret = sysdb_transaction_start(sysdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Could not start transaction\n"));
        goto fail;
    }
    in_transaction = true;

    for (i = 0; i < replies_count; i++) {
        ret = sysdb_attrs_get_string(replies[i], SDAP_SUDO_ATTR_CN, &name);
        if (ret != EOK) {
            goto fail;
        }

        ret = sysdb_add_sudorule(sysdb_ctx, name, replies[i], 0, 0);
        if (ret != EOK) {
            goto fail;
        }
    }

    ret = sysdb_transaction_commit(sysdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to commit transaction\n"));
        goto fail;
    }

    return EOK;

fail:
    if (in_transaction) {
        ret = sysdb_transaction_cancel(sysdb_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Could not cancel transaction\n"));
        }
    }

    return ret;
}
