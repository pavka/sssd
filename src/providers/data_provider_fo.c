/*
    SSSD

    Data Provider Helpers

    Copyright (C) Simo Sorce <ssorce@redhat.com> 2009

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

#include <netdb.h>
#include <arpa/inet.h>
#include "providers/dp_backend.h"
#include "resolv/async_resolv.h"

struct be_svc_callback {
    struct be_svc_callback *prev;
    struct be_svc_callback *next;

    struct be_svc_data *svc;

    be_svc_callback_fn_t *fn;
    void *private_data;
};

struct be_svc_data {
    struct be_svc_data *prev;
    struct be_svc_data *next;

    const char *name;
    struct fo_service *fo_service;

    struct fo_server *last_good_srv;
    time_t last_status_change;
    bool run_callbacks;

    struct be_svc_callback *callbacks;
};

struct be_failover_ctx {
    struct fo_ctx *fo_ctx;
    struct resolv_ctx *resolv;

    struct be_svc_data *svcs;
};

static const char *proto_table[] = { FO_PROTO_TCP, FO_PROTO_UDP, NULL };

int be_fo_is_srv_identifier(const char *server)
{
    return server && strcasecmp(server, BE_SRV_IDENTIFIER) == 0;
}

static int be_fo_get_options(struct be_ctx *ctx,
                             struct fo_options *opts)
{
    errno_t ret;

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_RESOLV_TIMEOUT,
                         FO_DEFAULT_SVC_TIMEOUT,
                         &opts->service_resolv_timeout);
    if (ret != EOK) {
        return ret;
    }

    opts->retry_timeout = 30;
    opts->srv_retry_timeout = 14400;

    ret = resolv_get_family_order(ctx->cdb, ctx->conf_path,
                                  &opts->family_order);
    if (ret != EOK) {
        return ret;
    }

    return EOK;
}

int be_init_failover(struct be_ctx *ctx)
{
    int ret;
    int resolv_timeout;
    struct fo_options fopts;

    if (ctx->be_fo != NULL) {
        return EOK;
    }

    ctx->be_fo = talloc_zero(ctx, struct be_failover_ctx);
    if (!ctx->be_fo) {
        return ENOMEM;
    }

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_RESOLV_OP_TIMEOUT,
                         RESOLV_DEFAULT_TIMEOUT, &resolv_timeout);
    if (ret != EOK) {
        return ret;
    }

    ret = resolv_init(ctx, ctx->ev, resolv_timeout, &ctx->be_fo->resolv);
    if (ret != EOK) {
        talloc_zfree(ctx->be_fo);
        return ret;
    }

    ret = be_fo_get_options(ctx, &fopts);
    if (ret != EOK) {
        talloc_zfree(ctx->be_fo);
        return ret;
    }

    ctx->be_fo->fo_ctx = fo_context_init(ctx->be_fo, &fopts);
    if (!ctx->be_fo->fo_ctx) {
        talloc_zfree(ctx->be_fo);
        return ENOMEM;
    }

    return EOK;
}

static int be_svc_data_destroy(void *memptr)
{
    struct be_svc_data *svc;

    svc = talloc_get_type(memptr, struct be_svc_data);

    while (svc->callbacks) {
        /* callbacks removes themselves from the list,
         * so this while will freem them all and then terminate */
        talloc_free(svc->callbacks);
    }

    return 0;
}

/*
 * Find registered be_svc_data by service name.
 */
static struct be_svc_data *be_fo_find_svc_data(struct be_ctx *ctx,
                                               const char *service_name)
{
    struct be_svc_data *svc;

    if (!ctx || !ctx->be_fo) {
        return 0;
    }

    DLIST_FOR_EACH(svc, ctx->be_fo->svcs) {
        if (strcmp(svc->name, service_name) == 0) {
            return svc;
        }
    }

    return 0;
}

int be_fo_add_service(struct be_ctx *ctx, const char *service_name)
{
    struct fo_service *service;
    struct be_svc_data *svc;
    int ret;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (svc) {
        DEBUG(6, ("Failover service already initialized!\n"));
        /* we already have a service up and configured,
         * can happen when using both id and auth provider
         */
        return EOK;
    }

    /* if not in the be service list, try to create new one */

    ret = fo_new_service(ctx->be_fo->fo_ctx, service_name, &service);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(1, ("Failed to create failover service!\n"));
        return ret;
    }

    svc = talloc_zero(ctx->be_fo, struct be_svc_data);
    if (!svc) {
        return ENOMEM;
    }
    talloc_set_destructor((TALLOC_CTX *)svc, be_svc_data_destroy);

    svc->name = talloc_strdup(svc, service_name);
    if (!svc->name) {
        talloc_zfree(svc);
        return ENOMEM;
    }
    svc->fo_service = service;

    DLIST_ADD(ctx->be_fo->svcs, svc);

    return EOK;
}

static int be_svc_callback_destroy(void *memptr)
{
    struct be_svc_callback *callback;

    callback = talloc_get_type(memptr, struct be_svc_callback);

    if (callback->svc) {
        DLIST_REMOVE(callback->svc->callbacks, callback);
    }

    return 0;
}

int be_fo_service_add_callback(TALLOC_CTX *memctx,
                               struct be_ctx *ctx, const char *service_name,
                               be_svc_callback_fn_t *fn, void *private_data)
{
    struct be_svc_callback *callback;
    struct be_svc_data *svc;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    callback = talloc_zero(memctx, struct be_svc_callback);
    if (!callback) {
        return ENOMEM;
    }
    talloc_set_destructor((TALLOC_CTX *)callback, be_svc_callback_destroy);

    callback->svc = svc;
    callback->fn = fn;
    callback->private_data = private_data;

    DLIST_ADD(svc->callbacks, callback);

    return EOK;
}

int be_fo_add_srv_server(struct be_ctx *ctx,
                         const char *service_name,
                         const char *query_service,
                         const char *default_discovery_domain,
                         enum be_fo_protocol proto,
                         bool proto_fallback, void *user_data)
{
    struct be_svc_data *svc;
    char *domain;
    int ret;
    int i;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    ret = confdb_get_string(ctx->cdb, svc, ctx->conf_path,
                            CONFDB_DOMAIN_DNS_DISCOVERY_NAME,
                            default_discovery_domain, &domain);
    if (ret != EOK) {
        DEBUG(1, ("Failed reading %s from confdb\n",
                  CONFDB_DOMAIN_DNS_DISCOVERY_NAME));
        return ret;
    }

    /* Add the first protocol as the primary lookup */
    ret = fo_add_srv_server(svc->fo_service, query_service,
                            domain, ctx->domain->name,
                            proto_table[proto], user_data);
    if (ret && ret != EEXIST) {
        DEBUG(1, ("Failed to add SRV lookup reference to failover service\n"));
        return ret;
    }

    if (proto_fallback) {
        i = (proto + 1) % BE_FO_PROTO_SENTINEL;
        /* All the rest as fallback */
        while (i != proto) {
            ret = fo_add_srv_server(svc->fo_service, query_service,
                                    domain, ctx->domain->name,
                                    proto_table[i], user_data);
            if (ret && ret != EEXIST) {
                DEBUG(1, ("Failed to add SRV lookup reference to failover service\n"));
                return ret;
            }

            i = (i + 1) % BE_FO_PROTO_SENTINEL;
        }
    }

    return EOK;
}

int be_fo_get_server_count(struct be_ctx *ctx, const char *service_name)
{
    struct be_svc_data *svc_data;

    svc_data = be_fo_find_svc_data(ctx, service_name);
    if (!svc_data) {
        return 0;
    }

    return fo_get_server_count(svc_data->fo_service);
}

int be_fo_add_server(struct be_ctx *ctx, const char *service_name,
                     const char *server, int port, void *user_data)
{
    struct be_svc_data *svc;
    int ret;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    ret = fo_add_server(svc->fo_service, server, port, user_data);
    if (ret && ret != EEXIST) {
        DEBUG(1, ("Failed to add server to failover service\n"));
        return ret;
    }

    return EOK;
}

struct be_fo_lookup {
    const char *service_name;
    struct be_svc_data *svc;

    int attempts;

    struct fo_server *current;
    struct fo_server *first;
};

struct be_resolve_service_state {
    struct be_fo_lookup *lookup;
};

static void be_resolve_service_done(struct tevent_req *subreq);

struct tevent_req *be_resolve_service_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct be_ctx *ctx,
                                           const char *service_name)
{
    struct tevent_req *req, *subreq;
    struct be_resolve_service_state *state;
    errno_t ret;

    req = tevent_req_create(memctx, &state, struct be_resolve_service_state);
    if (!req) return NULL;

    state->lookup = talloc_zero(state, struct be_fo_lookup);
    if (!state->lookup) {
        ret = ENOMEM;
        goto fail;
    }

    state->lookup->attempts = 0;

    state->lookup->service_name = talloc_strdup(state->lookup, service_name);
    if (!state->lookup->service_name) {
        ret = ENOMEM;
        goto fail;
    }

    state->lookup->svc = be_fo_find_svc_data(ctx, service_name);
    if (!state->lookup->svc) {
        ret = EINVAL;
        goto fail;
    }

    subreq = be_resolve_server_send(state, ev, ctx, state->lookup);
    if (!subreq) {
        ret = EIO;
        goto fail;
    }
    tevent_req_set_callback(subreq, be_resolve_service_done, req);

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
be_resolve_service_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    errno_t ret;

    ret = be_resolve_server_recv(subreq, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("Cannot resolve service [%d]: %s\n",
              ret, strerror(ret)));
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_done(req);
}

errno_t
be_resolve_service_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req,
                        struct be_fo_lookup **lookup, struct fo_server **srv)
{
    struct be_resolve_service_state *state = tevent_req_data(req,
                                             struct be_resolve_service_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (lookup) {
        *lookup = state->lookup;
    }

    if (srv) {
        *srv = state->lookup->current;
    }

    return EOK;
}

struct be_resolve_server_state {
    struct tevent_context *ev;
    struct be_ctx *ctx;

    struct be_svc_data *svc;
    struct be_fo_lookup *lookup;
};

static void be_resolve_server_done(struct tevent_req *subreq);

struct tevent_req *be_resolve_server_send(TALLOC_CTX *memctx,
                                          struct tevent_context *ev,
                                          struct be_ctx *ctx,
                                          struct be_fo_lookup *lookup)
{
    struct tevent_req *req, *subreq;
    struct be_resolve_server_state *state;

    req = tevent_req_create(memctx, &state, struct be_resolve_server_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->lookup = lookup;
    state->svc = lookup->svc;

    subreq = fo_resolve_service_send(state, ev,
                                     ctx->be_fo->resolv,
                                     ctx->be_fo->fo_ctx,
                                     state->svc->fo_service);
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, be_resolve_server_done, req);

    return req;
}

static void be_resolve_server_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct be_resolve_server_state *state = tevent_req_data(req,
                                             struct be_resolve_server_state);
    struct be_svc_callback *callback;
    int ret;
    time_t srv_status_change;
    struct fo_server *srv;

    ret = fo_resolve_service_recv(subreq, &srv);
    talloc_zfree(subreq);
    switch (ret) {
    case EOK:
        if (!srv) {
            tevent_req_error(req, EFAULT);
            return;
        }
        break;

    case ENOENT:
        /* all servers have been tried and none
         * was found good, go offline */
        tevent_req_error(req, EIO);
        return;

    default:
        /* mark server as bad and retry */
        if (!srv) {
            tevent_req_error(req, EFAULT);
            return;
        }
        DEBUG(6, ("Couldn't resolve server (%s), resolver returned (%d)\n",
                  fo_get_server_str_name(srv), ret));

        state->lookup->attempts++;
        if (state->lookup->attempts >= 10) {
            DEBUG(2, ("Failed to find a server after 10 attempts\n"));
            tevent_req_error(req, EIO);
            return;
        }

        /* now try next one */
        DEBUG(6, ("Trying with the next one!\n"));
        subreq = fo_resolve_service_send(state, state->ev,
                                         state->ctx->be_fo->resolv,
                                         state->ctx->be_fo->fo_ctx,
                                         state->svc->fo_service);
        if (!subreq) {
            tevent_req_error(req, ENOMEM);
            return;
        }
        tevent_req_set_callback(subreq, be_resolve_server_done, req);

        return;
    }

    /* all fine we got the server */

    /* Check if we looped around the server list */
    if (state->lookup->first == NULL) {
        state->lookup->first = srv;
        DEBUG(SSSDBG_TRACE_INTERNAL, ("Setting the first seen server to %s\n",
              fo_get_server_str_name(state->lookup->first)));
    } else {
        if (srv == state->lookup->first) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("This server has already been "
                  "resolved. No servers are available\n"));
            tevent_req_error(req, EIO);
        }
    }

    state->lookup->current = srv;

    if (DEBUG_IS_SET(SSSDBG_CONF_SETTINGS) && fo_get_server_name(srv)) {
        struct resolv_hostent *srvaddr;
        char ipaddr[128];
        srvaddr = fo_get_server_hostent(srv);
        if (!srvaddr) {
            DEBUG(3, ("FATAL: No hostent available for server (%s)\n",
                      fo_get_server_str_name(srv)));
            tevent_req_error(req, EFAULT);
            return;
        }

        inet_ntop(srvaddr->family, srvaddr->addr_list[0]->ipaddr,
                  ipaddr, 128);

        DEBUG(4, ("Found address for server %s: [%s] TTL %d\n",
                fo_get_server_str_name(srv), ipaddr,
                srvaddr->addr_list[0]->ttl));
    }

    srv_status_change = fo_get_server_hostname_last_change(srv);

    /* now call all svc callbacks if server changed or if it is explicitly
     * requested or if the server is the same but changed status since last time*/
    if (srv != state->svc->last_good_srv ||
        state->svc->run_callbacks ||
        srv_status_change > state->svc->last_status_change) {
        state->svc->last_good_srv = srv;
        state->svc->last_status_change = srv_status_change;
        state->svc->run_callbacks = false;

        DLIST_FOR_EACH(callback, state->svc->callbacks) {
            callback->fn(callback->private_data, srv);
        }
    }

    tevent_req_done(req);
}

int be_resolve_server_recv(struct tevent_req *req, struct fo_server **srv)
{
    struct be_resolve_server_state *state = tevent_req_data(req,
                                             struct be_resolve_server_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (srv) {
        *srv = state->lookup->current;
    }

    return EOK;
}

void be_fo_try_next_server(struct be_ctx *ctx, const char *service_name)
{
    struct be_svc_data *svc;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (svc) {
        fo_try_next_server(svc->fo_service);
    }
}

int be_fo_run_callbacks_at_next_request(struct be_ctx *ctx,
                                        const char *service_name)
{
    struct be_svc_data *svc;

    svc = be_fo_find_svc_data(ctx, service_name);
    if (NULL == svc) {
        return ENOENT;
    }

    svc->run_callbacks = true;

    return EOK;
}

void reset_fo(struct be_ctx *be_ctx)
{
    fo_reset_services(be_ctx->be_fo->fo_ctx);
}

