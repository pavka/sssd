/*
   SSSD

   SSS Client Responder, command parser

   Copyright (C) Simo Sorce <ssorce@redhat.com> 2008

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
#include <errno.h>
#include "db/sysdb.h"
#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"

int sss_cmd_send_error(struct cli_ctx *cctx, int err)
{
    int ret;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Cannot create new packet: %d\n", ret));
        return ret;
    }

    sss_packet_set_error(cctx->creq->out, err);
    return EOK;
}

int sss_cmd_empty_packet(struct sss_packet *packet)
{
    uint8_t *body;
    size_t blen;
    int ret;

    ret = sss_packet_grow(packet, 2*sizeof(uint32_t));
    if (ret != EOK) return ret;

    sss_packet_get_body(packet, &body, &blen);
    ((uint32_t *)body)[0] = 0; /* num results */
    ((uint32_t *)body)[1] = 0; /* reserved */

    return EOK;
}

int sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    int ret;

    /* create response packet */
    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    ret = sss_cmd_empty_packet(cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }

    sss_packet_set_error(cctx->creq->out, EOK);
    sss_cmd_done(cctx, freectx);
    return EOK;
}

void sss_cmd_done(struct cli_ctx *cctx, void *freectx)
{
    /* now that the packet is in place, unlock queue
     * making the event writable */
    TEVENT_FD_WRITEABLE(cctx->cfde);

    /* free all request related data through the talloc hierarchy */
    talloc_free(freectx);
}

int sss_cmd_get_version(struct cli_ctx *cctx)
{
    uint8_t *req_body;
    size_t req_blen;
    uint8_t *body;
    size_t blen;
    int ret;
    uint32_t client_version;
    int i;
    static struct cli_protocol_version *cli_protocol_version = NULL;

    cctx->cli_protocol_version = NULL;

    if (cli_protocol_version == NULL) {
        cli_protocol_version = register_cli_protocol_version();
    }

    if (cli_protocol_version != NULL) {
        cctx->cli_protocol_version = &cli_protocol_version[0];

        sss_packet_get_body(cctx->creq->in, &req_body, &req_blen);
        if (req_blen == sizeof(uint32_t)) {
            memcpy(&client_version, req_body, sizeof(uint32_t));
            DEBUG(5, ("Received client version [%d].\n", client_version));

            i=0;
            while(cli_protocol_version[i].version>0) {
                if (cli_protocol_version[i].version == client_version) {
                    cctx->cli_protocol_version = &cli_protocol_version[i];
                    break;
                }
                i++;
            }
        }
    }

    /* create response packet */
    ret = sss_packet_new(cctx->creq, sizeof(uint32_t),
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(cctx->creq->out, &body, &blen);
    ((uint32_t *)body)[0] = cctx->cli_protocol_version!=NULL ?
                                cctx->cli_protocol_version->version : 0;
    DEBUG(5, ("Offered version [%d].\n", ((uint32_t *)body)[0]));

    sss_cmd_done(cctx, NULL);
    return EOK;
}

int sss_cmd_execute(struct cli_ctx *cctx, struct sss_cmd_table *sss_cmds)
{
    enum sss_cli_command cmd;
    int i;

    cmd = sss_packet_get_cmd(cctx->creq->in);

    for (i = 0; sss_cmds[i].cmd != SSS_CLI_NULL; i++) {
        if (cmd == sss_cmds[i].cmd) {
            return sss_cmds[i].fn(cctx);
        }
    }

    return EINVAL;
}

struct setent_req_list {
    struct setent_req_list *prev;
    struct setent_req_list *next;
    /* Need to modify the list from a talloc destructor */
    struct setent_req_list **head;

    void *pvt;

    struct tevent_req *req;
};

struct tevent_req *
setent_get_req(struct setent_req_list *sl)
{
    return sl->req;
}

int setent_remove_ref(TALLOC_CTX *ctx)
{
    struct setent_req_list *entry =
            talloc_get_type(ctx, struct setent_req_list);
    DLIST_REMOVE(*(entry->head), entry);
    return 0;
}

errno_t setent_add_ref(TALLOC_CTX *memctx,
                       void *pvt,
                       struct setent_req_list **list,
                       struct tevent_req *req)
{
    struct setent_req_list *entry;

    entry = talloc_zero(memctx, struct setent_req_list);
    if (!entry) {
        return ENOMEM;
    }

    entry->req = req;
    entry->pvt = pvt;
    DLIST_ADD_END(*list, entry, struct setent_req_list *);
    entry->head = list;

    talloc_set_destructor((TALLOC_CTX *)entry, setent_remove_ref);
    return EOK;
}

void setent_notify(struct setent_req_list **list, errno_t err)
{
    struct setent_req_list *reql;

    /* Notify the waiting clients */
    while ((reql = *list) != NULL) {
        /* Each tevent_req_done() call will free
         * the request, removing it from the list.
         */
        if (err == EOK) {
            tevent_req_done(reql->req);
        } else {
            tevent_req_error(reql->req, err);
        }

        if (reql == *list) {
            /* The consumer failed to free the
             * request. Log a bug and continue.
             */
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("BUG: a callback did not free its request. "
                   "May leak memory\n"));
            /* Skip to the next since a memory leak is non-fatal */
            *list = (*list)->next;
        }
    }
}

void setent_notify_done(struct setent_req_list **list)
{
    return setent_notify(list, EOK);
}

/*
 * Return values:
 *  EOK     -   cache hit
 *  EAGAIN  -   cache hit, but schedule off band update
 *  ENOENT  -   cache miss
 */
errno_t
sss_cmd_check_cache(struct ldb_message *msg,
                    int cache_refresh_percent,
                    uint64_t cache_expire)
{
    uint64_t lastUpdate;
    uint64_t midpoint_refresh = 0;
    time_t now;

    now = time(NULL);
    lastUpdate = ldb_msg_find_attr_as_uint64(msg, SYSDB_LAST_UPDATE, 0);
    midpoint_refresh = 0;

    if(cache_refresh_percent) {
        midpoint_refresh = lastUpdate +
            (cache_expire - lastUpdate)*cache_refresh_percent/100;
        if (midpoint_refresh - lastUpdate < 10) {
            /* If the percentage results in an expiration
             * less than ten seconds after the lastUpdate time,
             * that's too often we will simply set it to 10s
             */
            midpoint_refresh = lastUpdate+10;
        }
    }

    if (cache_expire > now) {
        /* cache still valid */

        if (midpoint_refresh && midpoint_refresh < now) {
            /* We're past the the cache refresh timeout
             * We'll return the value from the cache, but we'll also
             * queue the cache entry for update out-of-band.
             */
            return EAGAIN;
        } else {
            /* Cache is still valid. */
            return EOK;
        }
    }

    /* Cache needs to be updated */
    return ENOENT;
}

struct getent_state {
    struct tevent_context *ev;
    struct cli_ctx *cctx;
    struct getent_ops *ops;

    struct sss_domain_info **domains;
    size_t dom_idx;

    void *pvt;
    const char *db_name;

    struct ldb_result *res;
};

static errno_t getent_lookup_step(struct tevent_req *req);
static void getent_lookup_done(struct tevent_req *subreq);

struct tevent_req *
getent_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
            struct cli_ctx *cctx, bool multidomain,
            int cache_refresh_percent, struct getent_ops *ops,
            const char *db_name, void *pvt)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct getent_state *state;
    struct sss_domain_info *dom;
    size_t dom_idx = 0;
    size_t num_domains = 0;
    struct sysdb_ctx *sysdb;
    uint64_t lastUpdate;
    uint64_t cacheExpire;
    uint64_t midpoint_refresh;
    time_t now = time(NULL);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct getent_state);
    if (!req) return NULL;
    state->cctx = cctx;

    for (dom = cctx->rctx->domains; dom; dom = dom->next) num_domains++;

    /* Create an array of domains to check. To save resizes, we'll
     * assume that all will be checked
     */
    state->domains = talloc_zero_array(state,
                                       struct sss_domain_info *,
                                       num_domains + 1);
    if (!state->domains) {
        ret = ENOMEM;
        goto immediate;
    }

    /* FIXME - steal pvt? */
    state->pvt = pvt;
    state->ops = ops;
    state->db_name = db_name;

    dom = cctx->rctx->domains;
    while (dom) {
        /* if it is a domainless search, skip domains that require fully
          * qualified names instead */
         while (dom && multidomain && dom->fqnames) {
             dom = dom->next;
         }
         if (!dom) break;

         sysdb = dom->sysdb;
         if (sysdb == NULL) {
             DEBUG(SSSDBG_CRIT_FAILURE,
                   ("Critical: Sysdb CTX not found for [%s]!\n", dom->name));
             ret = EINVAL;
             goto immediate;
         }

         ret = state->ops->check_ncache(dom, pvt);
         if (ret == EEXIST) {
             /* FIXME - for services, define a macro that yields
              * name:protocol
              */
             DEBUG(SSSDBG_TRACE_FUNC,
                     ("%s [%s] does not exist in [%s]! "
                      "(negative cache)\n",
                      state->db_name, state->ops->get_ent_name(dom, pvt),
                      dom->name));

             /* If this is a multi-domain search, try the next one */
             if (multidomain) {
                 dom = dom->next;
             } else {
                 /* This was a single-domain search.
                  * exit the loop. Since it was negatively-
                  * cached, don't add it to the eligible
                  * domains list.
                  */
                 dom = NULL;
             }

             continue;
         }

        /* Check the cache */
        DEBUG(SSSDBG_TRACE_FUNC,
              ("Checking cache for %s [%s@%s]\n",
               state->db_name, state->ops->get_ent_name(dom, pvt),
               dom->name));

        ret = state->ops->check_sysdb(state, sysdb, dom, pvt, &state->res);
        if (ret != EOK && ret != ENOENT) goto immediate;
        if (ret == ENOENT) {
             /* Not found in the cache. Add this domain to the
              * list of eligible domains to check the provider.
              */
             if (NEED_CHECK_PROVIDER(dom->provider)) {
                 state->domains[dom_idx] = dom;
                 dom_idx++;
             } else {
                 /* No provider to check. Set the negative cache here */
                 ret = state->ops->set_ncache(dom, pvt);
                 if (ret != EOK) {
                     /* Failure to set the negative cache is non-fatal.
                      * We'll log an error and continue.
                      */
                    DEBUG(SSSDBG_MINOR_FAILURE,
                        ("Could not set negative cache for %s [%s@%s]\n",
                        state->db_name, state->ops->get_ent_name(dom, pvt),
                        dom->name));
                 }
             }

             /* If this is a multi-domain search, try the next one */
             if (multidomain) {
                 dom = dom->next;
             } else {
                 /* This was a single-domain search.
                  * exit the loop.
                  */
                 dom = NULL;
             }
             continue;
         }

         /* Found a result. Check its validity */
         if (state->res->count > 1) {
             DEBUG(SSSDBG_OP_FAILURE,
                   ("getservby* returned more than one result!\n"));
             ret = ENOENT;
             goto immediate;
         }

         /* FIXME - reuse sss_cmd_check_cache? */
         lastUpdate = ldb_msg_find_attr_as_uint64(state->res->msgs[0],
                                                  SYSDB_LAST_UPDATE, 0);

         /* FIXME - parametrize CACHE_EXPIRE to be reusable by initgroups */
         cacheExpire = ldb_msg_find_attr_as_uint64(state->res->msgs[0],
                                                   SYSDB_CACHE_EXPIRE, 0);

         midpoint_refresh = 0;
         if (cache_refresh_percent) {
             midpoint_refresh = lastUpdate +
               (cacheExpire - lastUpdate)*cache_refresh_percent/100;
             if (midpoint_refresh - lastUpdate < 10) {
                 /* If the percentage results in an expiration
                  * less than ten seconds after the lastUpdate time,
                  * that's too often we will simply set it to 10s
                  */
                 midpoint_refresh = lastUpdate+10;
             }
         }

         if (cacheExpire > now) {
             /* cache still valid */
             if (NEED_CHECK_PROVIDER(dom->provider)
                     && midpoint_refresh
                     && midpoint_refresh < now) {
                 /* We're past the the cache refresh timeout
                  * We'll return the value from the cache, but we'll also
                  * queue the cache entry for update out-of-band.
                  */
                 DEBUG(SSSDBG_TRACE_FUNC,
                       ("Performing midpoint cache update\n"));

                 /* Update the cache */
                 subreq = state->ops->update_cache(dom, pvt);
                 if (!subreq) {
                     DEBUG(SSSDBG_CRIT_FAILURE,
                           ("Out of memory sending out-of-band data provider "
                            "request\n"));
                     /* This is non-fatal, so we'll continue here */
                 }
                 /* We don't need to listen for a reply, so we will free the
                  * request here.
                  */
                 talloc_zfree(subreq);
             }

             /* The cache is valid. Return it */
             ret = EOK;
             goto immediate;
         } else {
             /* Cache is expired. Add this domain to the
              * list of eligible domains to check the provider.
              */
             if (NEED_CHECK_PROVIDER(dom->provider)) {
                 state->domains[dom_idx] = dom;
                 dom_idx++;
             }

             /* If this is a multi-domain search, try the next one */
             if (multidomain) {
                 dom = dom->next;
             } else {
                 /* This was a single-domain search.
                  * exit the loop.
                  */
                 dom = NULL;
             }
         }
    }

    /* No valid cached entries found and
     * not found in negative caches.
     * Iterate through the domains and try
     * to look the data up.
     */

    state->dom_idx = 0;
    if (!state->domains[state->dom_idx]) {
        /* No domains to search. Return ENOENT */
        ret = ENOENT;
        goto immediate;
    }

    ret = getent_lookup_step(req);
    if (ret != EOK) goto immediate;

    return req;

    ret = EFAULT; /* We should never get here */
immediate:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t
getent_lookup_step(struct tevent_req *req)
{
    struct getent_state *state =
            tevent_req_data(req, struct getent_state);
    struct sss_domain_info *dom =
            state->domains[state->dom_idx];
    struct tevent_req *subreq;

    subreq = state->ops->update_cache(dom, state->pvt);
    if (!subreq) return ENOMEM;
    tevent_req_set_callback(subreq, getent_lookup_done, req);

    return EOK;
}

static void
getent_lookup_done(struct tevent_req *subreq)
{
    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;
    struct sysdb_ctx *sysdb;

    struct tevent_req *req =
            tevent_req_callback_data(subreq, struct tevent_req);
    struct getent_state *state =
            tevent_req_data(req, struct getent_state);
    struct sss_domain_info *dom = state->domains[state->dom_idx];

    ret = state->ops->cache_updated(state, subreq,
                                    &err_maj, &err_min,
                                    &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Unable to get information from Data Provider\n"
               "dp_error: [%u], errno: [%u], error_msg: [%s]\n"
               "Will try to return what we have in cache\n",
               (unsigned int)err_maj, (unsigned int)err_min,
               err_msg ? err_msg : "none"));
    }

    /* Recheck the cache after the lookup.
     * We can ignore the expiration values here, because
     * either we have just updated it or the provider is
     * offline. Either way, whatever is in the cache should
     * be returned, if it exists. Otherwise, move to the
     * next provider.
     */
    sysdb = dom->sysdb;
    if (sysdb == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Critical: Sysdb CTX not found for [%s]!\n",
                dom->name));
        ret = EINVAL;
        goto done;
    }

    ret = state->ops->check_sysdb(state, sysdb, dom,
                                  state->pvt, &state->res);
    DEBUG(SSSDBG_TRACE_FUNC,
          ("Re-checking cache for %s [%s@%s]\n",
           state->db_name, state->ops->get_ent_name(dom, state->pvt),
           dom->name));
    if (ret == ENOENT) {
        ret = state->ops->set_ncache(dom, state->pvt);
        if (ret != EOK) {
            /* Failure to set the negative cache is non-fatal.
             * We'll log an error and continue.
             */
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Could not set negative cache for %s [%s@%s]\n",
                   state->db_name, state->ops->get_ent_name(dom, state->pvt),
                   dom->name));
        }

        /* Need to check other domains */
        state->dom_idx++;
        if (!state->domains[state->dom_idx]) {
            /* No more domains to search. Return ENOENT */
            ret = ENOENT;
            goto done;
        }

        ret = getent_lookup_step(req);
        if (ret != EOK) goto done;

        /* Set EAGAIN so we will re-enter the mainloop */
        ret = EAGAIN;
    }

done:
    if (ret == EOK) {
        /* Cache contained results. Return them */
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        /* An error occurred, fail the request */
        tevent_req_error(req, ret);
    }

    /* ret == EAGAIN: Reenter mainloop */
    return;
}

errno_t
getent_recv(TALLOC_CTX *mem_ctx,
            struct tevent_req *req,
            struct sysdb_ctx **_db,
            struct ldb_result **_res)
{
    struct getent_state *state =
            tevent_req_data(req, struct getent_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_res = talloc_steal(mem_ctx, state->res);
    if (_db) *_db = state->domains[state->dom_idx]->sysdb;
    return EOK;
}
