/*
   SSSD

   Async resolver keeping results in cache

   Authors:
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2011

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
#include <time.h>

#include "src/util/util.h"
#include "src/resolv/async_resolv.h"

#define NCACHE_TIMEOUT  30

/* FIXME - use talloc_get_type instead of pure typing? */
/* FIXME - use object-like structure for hostname, txt, srv
 * with all the functions for compare etc. ?? */

enum resolv_item {
    RESOLV_HOSTBYNAME,
    RESOLV_SRV,
    RESOLV_TXT
};

struct resolve_request {
    struct resolve_request *prev;
    struct resolve_request *next;

    struct cached_resolv_ctx *ctx;

    void *data;
    struct tevent_req *req;
};

struct cache_item {
    struct cache_item *next;
    struct cache_item *prev;

    struct cached_resolv_ctx *ctx;

    time_t cache_in;
    union {
        struct resolv_hostent *hcache;
    } data;
    enum resolv_item item_type;
};

struct cached_resolv_ctx {
    struct resolv_ctx *res;
    struct resolve_request *request_list;

    struct cache_item *cache;
    struct cache_item *ncache;
};

static const char *
str_resolv_item(enum resolv_item item_type)
{
    switch (item_type) {
        case RESOLV_HOSTBYNAME:
            return "host name";
        case RESOLV_SRV:
            return "SRV record";
        case RESOLV_TXT:
            return "TXT record";
    }

    return "unknown resolv item type";
}

struct cached_resolv_ctx *
cres_init(TALLOC_CTX *mem_ctx, struct resolv_ctx *res)
{
    struct cached_resolv_ctx *cctx;

    cctx = talloc_zero(mem_ctx, struct cached_resolv_ctx);
    if (!cctx) return NULL;

    cctx->res = res;
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Initialized caching resolver\n"));
    return cctx;
}

static void
cres_cache_reset(struct cache_item *cache)
{
    struct cache_item *item;
    struct cache_item *prev = NULL;

    DLIST_FOR_EACH(item, cache) {
        if (prev) talloc_free(prev);
        prev = item;
    }
    talloc_free(prev);
}

void
cres_reset(struct cached_resolv_ctx *cctx)
{
    DEBUG(SSSDBG_TRACE_INTERNAL, ("Pruning resolver cache\n"));
    if (!cctx) return;

    cres_cache_reset(cctx->cache);
    cres_cache_reset(cctx->ncache);
}

static int
cache_item_destructor(struct cache_item *item)
{
    DLIST_REMOVE(item->ctx->cache, item);
    return 0;
}

static int
ncache_item_destructor(struct cache_item *item)
{
    DLIST_REMOVE(item->ctx->ncache, item);
    return 0;
}

static errno_t
_cres_cache_enter(struct cached_resolv_ctx *cctx, struct cache_item **cptr,
                  enum resolv_item item_type, const char *cache_type,
                  int (*destructor)(struct cache_item *), void *data)
{
    struct cache_item *item;

    item = talloc_zero(cctx, struct cache_item);
    if (!item) return ENOMEM;

    item->ctx = cctx;
    item->cache_in = time(NULL);
    item->item_type = item_type;

    switch (item_type) {
        case RESOLV_HOSTBYNAME:
            item->data.hcache = (struct resolv_hostent *) data;
            break;
        default:
            talloc_free(item);
            return ENOSYS;
    }

    talloc_steal(item, data);
    talloc_set_destructor(item, destructor);
    DLIST_ADD(*cptr, item);
    DEBUG(SSSDBG_TRACE_INTERNAL,
          ("%s: cached %s [%p] time in [%llu]\n",
          cache_type, str_resolv_item(item->item_type), item, item->cache_in));
    return EOK;
}

#define cres_cache_enter(cctx, item_type, data) \
    _cres_cache_enter((cctx), &cctx->cache, (item_type), \
                       "positive", cache_item_destructor, (data))

#define cres_ncache_enter(cctx, item_type, data) \
    _cres_cache_enter((cctx), &cctx->ncache, (item_type), \
                      "negative", ncache_item_destructor, (data))

typedef bool (*ttl_check_fn_t)(const void *, time_t, time_t);
typedef bool (*cache_item_cmp_fn_t)(const void *, const struct cache_item *);

static struct cache_item *
_cres_cache_check(struct cache_item *cache,
                  enum resolv_item item_type, ttl_check_fn_t ttl_is_valid,
                  cache_item_cmp_fn_t cmp_item, const void *data)
{
    struct cache_item *item;
    time_t now;
    int i;

    DLIST_FOR_EACH(item, cache) {
        if (item->item_type == item_type &&
            cmp_item(data, item) == true) break;
    }

    if (!item) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Cache miss\n"));
        return NULL;
    }

    now = time(NULL);
    if (ttl_is_valid(item, item->cache_in, now) == true) {
        DEBUG(SSSDBG_TRACE_FUNC, ("Cache hit\n"));
        return item;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, ("Removing expired cache item\n"));
    talloc_free(item);  /* remove the item and free data */
    return NULL;
}

#define cres_cache_check(ctx, item_type, is_valid, cmp_item, data) \
    _cres_cache_check(ctx->cache, item_type, is_valid, cmp_item, data)

#define cres_ncache_check(ctx, item_type, is_valid, cmp_item, data) \
    _cres_cache_check(ctx->ncache, item_type, is_valid, cmp_item, data)

static int
resolve_request_destructor(struct resolve_request *request)
{
    DLIST_REMOVE(request->ctx->request_list, request);
    return 0;
}

static errno_t
set_lookup_hook(struct cached_resolv_ctx *ctx,
                struct tevent_req *req, void *data)
{
    struct resolve_request *request;

    request = talloc(req, struct resolve_request);
    if (request == NULL) {
        talloc_free(request);
        return ENOMEM;
    }

    request->data = data;
    request->req = req;

    DLIST_ADD(ctx->request_list, request);
    talloc_set_destructor(request, resolve_request_destructor);
    return EOK;
}

typedef bool (*request_cmp_fn_t)(const void *, const struct resolve_request *);

static errno_t
request_notify(struct cached_resolv_ctx *ctx,
               request_cmp_fn_t cmp_request,
               const void *data, int status)
{
    struct resolve_request *request;

    DLIST_FOR_EACH(request, ctx->request_list) {
        DLIST_REMOVE(ctx->request_list, request);
        if (cmp_request(request, data) == true) {
            if  (status == EOK) {
                tevent_req_done(request->req);
            } else {
                tevent_req_error(request->req, status);
            }
        }
    }

    return EOK;
}

static bool
resolv_hostent_ttl_hit(const void *item, time_t cache_in, time_t now)
{
    const struct cache_item *cache_item = (const struct cache_item *) item;
    const struct resolv_hostent *rhostent =
                    (const struct resolv_hostent *) cache_item->data.hcache;
    struct resolv_addr *addr;
    size_t i;

    if (!rhostent || !rhostent->addr_list) return false;

    for (i=0; rhostent->addr_list[i]; i++) {
        if (rhostent->addr_list[i]->ttl < now - cache_in) {
            return false;
        }
    }

    return true;
}

static bool
resolv_hostent_cmp(const void *data, const struct cache_item *cache_item)
{
    if (cache_item->item_type != RESOLV_HOSTBYNAME) return false;

    return strcasecmp((const char *) data, cache_item->data.hcache->name) == 0;
}

static bool
hostname_notify_request_cmp(const void *data,
                            const struct resolve_request *request)
{
    return strcasecmp((const char *) data, (const char *) request->data) == 0;
}

struct cres_gethostbyname_state {
    struct cached_resolv_ctx *ctx;

    const char *name;
    enum restrict_family family_order;
    enum host_database *db;
    struct resolv_hostent *rhostent;
};

static errno_t
cres_gethostbyname_check_caches(struct cached_resolv_ctx *ctx,
                                const char *name,
                                struct resolv_hostent **rhostent);
static void cres_gethostbyname_done(struct tevent_req *subreq);

struct tevent_req *
cres_gethostbyname_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                        struct cached_resolv_ctx *ctx, const char *name,
                        enum restrict_family family_order,
                        enum host_database *db)
{
    errno_t ret;
    struct tevent_req *req, *subreq;
    struct cres_gethostbyname_state *state;

    req = tevent_req_create(mem_ctx, &state, struct cres_gethostbyname_state);
    if (req == NULL) {
        return NULL;
    }

    state->ctx = ctx;
    state->name = name;
    state->family_order = family_order;
    state->db = db;

    ret = cres_gethostbyname_check_caches(state->ctx, state->name,
                                          &state->rhostent);
    if (ret == EOK || ret == ENOENT) {
        /* Cache hit - positive or negative. Done. */
        goto immediate;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_MINOR_FAILURE, ("error searching cache\n"));
        goto immediate;
    }

    /* EAGAIN means cache miss, search hosts databases */
    subreq = resolv_gethostbyname_send(req, ev, ctx->res,
                                       name, family_order, db);
    if (!subreq) {
        ret = EIO;
        goto immediate;
    }

    tevent_req_set_callback(subreq, cres_gethostbyname_done, req);
    return req;

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
cres_gethostbyname_check_caches(struct cached_resolv_ctx *ctx,
                                const char *name,
                                struct resolv_hostent **rhostent)
{
    struct cache_item *item;

    item = cres_ncache_check(ctx, RESOLV_HOSTBYNAME,
                             resolv_hostent_ttl_hit,
                             resolv_hostent_cmp, name);
    if (item) {
        return ENOENT;
    }

    item = cres_cache_check(ctx, RESOLV_HOSTBYNAME,
                            resolv_hostent_ttl_hit,
                            resolv_hostent_cmp, name);
    if (item) {
        *rhostent = item->data.hcache;
        return EOK;
    }

    return EAGAIN;
}

static struct resolv_hostent *
get_negative_rhostent(TALLOC_CTX *mem_ctx, const char *name)
{
    struct resolv_hostent *r;

    r = talloc_zero(mem_ctx, struct resolv_hostent);
    if (!r) return NULL;

    r->name = talloc_strdup(r, name);
    r->addr_list = talloc_array(r, struct resolv_addr *, 2);
    if (!r->name || !r->addr_list) {
        talloc_free(r);
        return NULL;
    }

    r->addr_list[0] = talloc_zero(r->addr_list, struct resolv_addr);
    if (!r->addr_list[0]) {
        talloc_free(r);
        return NULL;
    }

    r->addr_list[0]->ipaddr = NULL;
    r->addr_list[0]->ttl = NCACHE_TIMEOUT;
    r->addr_list[1] = NULL;

    return r;
}

static void
cres_gethostbyname_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct cres_gethostbyname_state *state = tevent_req_data(req,
                                                struct cres_gethostbyname_state);
    errno_t ret, cret;
    int resolv_status;
    struct resolv_hostent *neg;

    ret = resolv_gethostbyname_recv(subreq, state, NULL, NULL,
                                    &state->rhostent);
    talloc_zfree(subreq);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, ("putting %s into cache\n",
              state->rhostent->name));

        cret = cres_cache_enter(state->ctx, RESOLV_HOSTBYNAME, state->rhostent);
        if (cret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("cache_enter failed (%d): %s\n",
                  cret, strerror(cret)));
            ret = cret;
            goto notify;
        }
    } else if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, ("putting %s into negative cache\n",
              state->rhostent->name));

        neg = get_negative_rhostent(state->ctx->ncache, state->name);
        if (!neg) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("get_negative_rhostent failed\n"));
            ret = ENOMEM;
            goto notify;
        }

        cret = cres_ncache_enter(state->ctx, RESOLV_HOSTBYNAME, neg);
        if (cret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("negaive cache_enter failed (%d): %s\n",
                  cret, strerror(cret)));
            ret = cret;
            goto notify;
        }
    }

notify:
    DEBUG(SSSDBG_TRACE_INTERNAL, ("cached resolv: %s\n",
          ret == EOK ? "done" : strerror(ret)));
    /* Notify all the requests, including self */
    request_notify(state->ctx, hostname_notify_request_cmp, state->name, ret);
}

int
cres_gethostbyname_recv(struct tevent_req *req,
                        struct resolv_hostent **rhostent)
{
    struct cres_gethostbyname_state *state = tevent_req_data(req,
                                                struct cres_gethostbyname_state);
    /*FIXME - instead of status, convert to errno by
     * exposing the conversion function */
    if (rhostent) *rhostent = state->rhostent;

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
