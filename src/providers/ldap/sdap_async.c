/*
    SSSD

    Async LDAP Helper routines

    Copyright (C) Simo Sorce <ssorce@redhat.com> - 2009

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

#include <ctype.h>
#include "util/util.h"
#include "providers/ldap/sdap_async_private.h"

#define REALM_SEPARATOR '@'
#define REPLY_REALLOC_INCREMENT 10

void make_realm_upper_case(const char *upn)
{
    char *c;

    c = strchr(upn, REALM_SEPARATOR);
    if (c == NULL) {
        DEBUG(9, ("No realm delimiter found in upn [%s].\n", upn));
        return;
    }

    while(*(++c) != '\0') {
        c[0] = toupper(*c);
    }

    return;
}

/* ==LDAP-Memory-Handling================================================= */

static int lmsg_destructor(void *mem)
{
    ldap_msgfree((LDAPMessage *)mem);
    return 0;
}

static int sdap_msg_attach(TALLOC_CTX *memctx, LDAPMessage *msg)
{
    void *h;

    if (!msg) return EINVAL;

    h = sss_mem_attach(memctx, msg, lmsg_destructor);
    if (!h) return ENOMEM;

    return EOK;
}

/* ==sdap-hanlde-utility-functions======================================== */

static inline void sdap_handle_release(struct sdap_handle *sh);
static int sdap_handle_destructor(void *mem);

struct sdap_handle *sdap_handle_create(TALLOC_CTX *memctx)
{
    struct sdap_handle *sh;

    sh = talloc_zero(memctx, struct sdap_handle);
    if (!sh) return NULL;

    talloc_set_destructor((TALLOC_CTX *)sh, sdap_handle_destructor);

    return sh;
}

static int sdap_handle_destructor(void *mem)
{
    struct sdap_handle *sh = talloc_get_type(mem, struct sdap_handle);

    /* if the structure is currently locked, then mark it to be released
     * and prevent talloc from freeing the memory */
    if (sh->destructor_lock) {
        sh->release_memory = true;
        return -1;
    }

    sdap_handle_release(sh);
    return 0;
}

static void sdap_handle_release(struct sdap_handle *sh)
{
    struct sdap_op *op;

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], ldap[%p], "
              "destructor_lock[%d], release_memory[%d]\n",
              sh, (int)sh->connected, sh->ops, sh->ldap,
              (int)sh->destructor_lock, (int)sh->release_memory));

    if (sh->destructor_lock) return;
    sh->destructor_lock = true;

    /* make sure nobody tries to reuse this connection from now on */
    sh->connected = false;

    remove_ldap_connection_callbacks(sh);

    while (sh->ops) {
        op = sh->ops;
        op->callback(op, NULL, EIO, op->data);
        /* calling the callback may result in freeing the op */
        /* check if it is still the same or avoid freeing */
        if (op == sh->ops) talloc_free(op);
    }

    if (sh->ldap) {
        ldap_unbind_ext(sh->ldap, NULL, NULL);
        sh->ldap = NULL;
    }

    /* ok, we have done the job, unlock now */
    sh->destructor_lock = false;

    /* finally if a destructor was ever called, free sh before
     * exiting */
    if (sh->release_memory) {
        /* neutralize the destructor as we already handled
         * all was needed to be released */
        talloc_set_destructor((TALLOC_CTX *)sh, NULL);
        talloc_free(sh);
    }
}

/* ==Parse-Results-And-Handle-Disconnections============================== */
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg);
static void sdap_process_result(struct tevent_context *ev, void *pvt);
static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt);

void sdap_ldap_result(struct tevent_context *ev, struct tevent_fd *fde,
                      uint16_t flags, void *pvt)
{
    sdap_process_result(ev, pvt);
}

static void sdap_ldap_next_result(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval tv, void *pvt)
{
    sdap_process_result(ev, pvt);
}

static void sdap_process_result(struct tevent_context *ev, void *pvt)
{
    struct sdap_handle *sh = talloc_get_type(pvt, struct sdap_handle);
    struct timeval no_timeout = {0, 0};
    struct tevent_timer *te;
    LDAPMessage *msg;
    int ret;

    DEBUG(8, ("Trace: sh[%p], connected[%d], ops[%p], ldap[%p]\n",
              sh, (int)sh->connected, sh->ops, sh->ldap));

    if (!sh->connected || !sh->ldap) {
        DEBUG(2, ("ERROR: LDAP connection is not connected!\n"));
        sdap_handle_release(sh);
        return;
    }

    ret = ldap_result(sh->ldap, LDAP_RES_ANY, 0, &no_timeout, &msg);
    if (ret == 0) {
        /* this almost always means we have reached the end of
         * the list of received messages */
        DEBUG(8, ("Trace: ldap_result found nothing!\n"));
        return;
    }

    if (ret == -1) {
        DEBUG(4, ("ldap_result gave -1, something bad happend!\n"));
        sdap_handle_release(sh);
        return;
    }

    /* We don't know if this will be the last result.
     *
     * important: we must do this before actually processing the message
     * because the message processing might even free the sdap_handler
     * so it must be the last operation.
     * FIXME: use tevent_immediate/tevent_queues, when avilable */
    memset(&no_timeout, 0, sizeof(struct timeval));

    te = tevent_add_timer(ev, sh, no_timeout, sdap_ldap_next_result, sh);
    if (!te) {
        DEBUG(1, ("Failed to add critical timer to fetch next result!\n"));
    }

    /* now process this message */
    sdap_process_message(ev, sh, msg);
}

/* process a messgae calling the right operation callback.
 * msg is completely taken care of (including freeeing it)
 * NOTE: this function may even end up freeing the sdap_handle
 * so sdap_hanbdle must not be used after this function is called
 */
static void sdap_process_message(struct tevent_context *ev,
                                 struct sdap_handle *sh, LDAPMessage *msg)
{
    struct sdap_msg *reply;
    struct sdap_op *op;
    int msgid;
    int msgtype;
    int ret;

    msgid = ldap_msgid(msg);
    if (msgid == -1) {
        DEBUG(2, ("can't fire callback, message id invalid!\n"));
        ldap_msgfree(msg);
        return;
    }

    msgtype = ldap_msgtype(msg);

    for (op = sh->ops; op; op = op->next) {
        if (op->msgid == msgid) break;
    }

    if (op == NULL) {
        DEBUG(2, ("Unmatched msgid, discarding message (type: %0x)\n",
                  msgtype));
        ldap_msgfree(msg);
        return;
    }

    /* shouldn't happen */
    if (op->done) {
        DEBUG(2, ("Operation [%p] already handled (type: %0x)\n", op, msgtype));
        ldap_msgfree(msg);
        return;
    }

    switch (msgtype) {
    case LDAP_RES_SEARCH_ENTRY:
        /* go and process entry */
        break;

    case LDAP_RES_SEARCH_REFERENCE:
        /* more ops to come with this msgid */
        /* just ignore */
        ldap_msgfree(msg);
        return;

    case LDAP_RES_BIND:
    case LDAP_RES_SEARCH_RESULT:
    case LDAP_RES_MODIFY:
    case LDAP_RES_ADD:
    case LDAP_RES_DELETE:
    case LDAP_RES_MODDN:
    case LDAP_RES_COMPARE:
    case LDAP_RES_EXTENDED:
    case LDAP_RES_INTERMEDIATE:
        /* no more results expected with this msgid */
        op->done = true;
        break;

    default:
        /* unkwon msg type ?? */
        DEBUG(1, ("Couldn't figure out the msg type! [%0x]\n", msgtype));
        ldap_msgfree(msg);
        return;
    }

    reply = talloc_zero(op, struct sdap_msg);
    if (!reply) {
        ldap_msgfree(msg);
        ret = ENOMEM;
    } else {
        reply->msg = msg;
        ret = sdap_msg_attach(reply, msg);
        if (ret != EOK) {
            ldap_msgfree(msg);
            talloc_zfree(reply);
        }
    }

    if (op->list) {
        /* list exist, queue it */

        op->last->next = reply;
        op->last = reply;

    } else {
        /* create list, then call callback */
        op->list = op->last = reply;

        /* must be the last operation as it may end up freeing all memory
         * including all ops handlers */
        op->callback(op, reply, ret, op->data);
    }
}

static void sdap_unlock_next_reply(struct sdap_op *op)
{
    struct timeval tv;
    struct tevent_timer *te;
    struct sdap_msg *next_reply;

    if (op->list) {
        next_reply = op->list->next;
        /* get rid of the previous reply, it has been processed already */
        talloc_zfree(op->list);
        op->list = next_reply;
    }

    /* if there are still replies to parse, queue a new operation */
    if (op->list) {
        /* use a very small timeout, so that fd operations have a chance to be
         * served while processing a long reply */
        tv = tevent_timeval_current();

        /* wait 5 microsecond */
        tv.tv_usec += 5;
        tv.tv_sec += tv.tv_usec / 1000000;
        tv.tv_usec = tv.tv_usec % 1000000;

        te = tevent_add_timer(op->ev, op, tv,
                              sdap_process_next_reply, op);
        if (!te) {
            DEBUG(1, ("Failed to add critical timer for next reply!\n"));
            op->callback(op, NULL, EFAULT, op->data);
        }
    }
}

static void sdap_process_next_reply(struct tevent_context *ev,
                                    struct tevent_timer *te,
                                    struct timeval tv, void *pvt)
{
    struct sdap_op *op = talloc_get_type(pvt, struct sdap_op);

    op->callback(op, op->list, EOK, op->data);
}

/* ==LDAP-Operations-Helpers============================================== */

static int sdap_op_destructor(void *mem)
{
    struct sdap_op *op = (struct sdap_op *)mem;

    DLIST_REMOVE(op->sh->ops, op);

    if (op->done) return 0;

    /* we don't check the result here, if a message was really abandoned,
     * hopefully the server will get an abandon.
     * If the operation was already fully completed, this is going to be
     * just a noop */
    ldap_abandon_ext(op->sh->ldap, op->msgid, NULL, NULL);

    return 0;
}

static void sdap_op_timeout(struct tevent_req *req)
{
    struct sdap_op *op = tevent_req_callback_data(req, struct sdap_op);

    /* should never happen, but just in case */
    if (op->done) {
        DEBUG(2, ("Timeout happened after op was finished !?\n"));
        return;
    }

    /* signal the caller that we have a timeout */
    op->callback(op, NULL, ETIMEDOUT, op->data);
}

int sdap_op_add(TALLOC_CTX *memctx, struct tevent_context *ev,
                struct sdap_handle *sh, int msgid,
                sdap_op_callback_t *callback, void *data,
                int timeout, struct sdap_op **_op)
{
    struct sdap_op *op;

    op = talloc_zero(memctx, struct sdap_op);
    if (!op) return ENOMEM;

    op->sh = sh;
    op->msgid = msgid;
    op->callback = callback;
    op->data = data;
    op->ev = ev;

    /* check if we need to set a timeout */
    if (timeout) {
        struct tevent_req *req;
        struct timeval tv;

        tv = tevent_timeval_current();
        tv = tevent_timeval_add(&tv, timeout, 0);

        /* allocate on op, so when it get freed the timeout is removed */
        req = tevent_wakeup_send(op, ev, tv);
        if (!req) {
            talloc_zfree(op);
            return ENOMEM;
        }
        tevent_req_set_callback(req, sdap_op_timeout, op);
    }

    DLIST_ADD(sh->ops, op);

    talloc_set_destructor((TALLOC_CTX *)op, sdap_op_destructor);

    *_op = op;
    return EOK;
}

/* ==Modify-Password====================================================== */

struct sdap_exop_modify_passwd_state {
    struct sdap_handle *sh;

    struct sdap_op *op;

    int result;
    char *user_error_message;
};

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt);

struct tevent_req *sdap_exop_modify_passwd_send(TALLOC_CTX *memctx,
                                           struct tevent_context *ev,
                                           struct sdap_handle *sh,
                                           char *user_dn,
                                           char *password,
                                           char *new_password)
{
    struct tevent_req *req = NULL;
    struct sdap_exop_modify_passwd_state *state;
    int ret;
    BerElement *ber = NULL;
    struct berval *bv = NULL;
    int msgid;
    LDAPControl **request_controls = NULL;
    LDAPControl *ctrls[2] = { NULL, NULL };

    req = tevent_req_create(memctx, &state,
                            struct sdap_exop_modify_passwd_state);
    if (!req) return NULL;

    state->sh = sh;
    state->user_error_message = NULL;

    ber = ber_alloc_t( LBER_USE_DER );
    if (ber == NULL) {
        DEBUG(7, ("ber_alloc_t failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_printf( ber, "{tststs}", LDAP_TAG_EXOP_MODIFY_PASSWD_ID,
                     user_dn,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, password,
                     LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, new_password);
    if (ret == -1) {
        DEBUG(1, ("ber_printf failed.\n"));
        ber_free(ber, 1);
        talloc_zfree(req);
        return NULL;
    }

    ret = ber_flatten(ber, &bv);
    ber_free(ber, 1);
    if (ret == -1) {
        DEBUG(1, ("ber_flatten failed.\n"));
        talloc_zfree(req);
        return NULL;
    }

    ret = sdap_control_create(state->sh, LDAP_CONTROL_PASSWORDPOLICYREQUEST,
                              0, NULL, 0, &ctrls[0]);
    if (ret != LDAP_SUCCESS && ret != LDAP_NOT_SUPPORTED) {
        DEBUG(1, ("sdap_control_create failed to create "
                  "Password Policy control.\n"));
        goto fail;
    }
    request_controls = ctrls;

    DEBUG(4, ("Executing extended operation\n"));

    ret = ldap_extended_operation(state->sh->ldap, LDAP_EXOP_MODIFY_PASSWD,
                                  bv, request_controls, NULL, &msgid);
    ber_bvfree(bv);
    if (ctrls[0]) ldap_control_free(ctrls[0]);
    if (ret == -1 || msgid == -1) {
        DEBUG(1, ("ldap_extended_operation failed\n"));
        goto fail;
    }
    DEBUG(8, ("ldap_extended_operation sent, msgid = %d\n", msgid));

    /* FIXME: get timeouts from configuration, for now 5 secs. */
    ret = sdap_op_add(state, ev, state->sh, msgid,
                      sdap_exop_modify_passwd_done, req, 5, &state->op);
    if (ret) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, EIO);
    tevent_req_post(req, ev);
    return req;
}

static void sdap_exop_modify_passwd_done(struct sdap_op *op,
                                         struct sdap_msg *reply,
                                         int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);
    char *errmsg = NULL;
    int ret;
    LDAPControl **response_controls = NULL;
    int c;
    ber_int_t pp_grace;
    ber_int_t pp_expire;
    LDAPPasswordPolicyError pp_error;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    ret = ldap_parse_result(state->sh->ldap, reply->msg,
                            &state->result, NULL, &errmsg, NULL,
                            &response_controls, 0);
    if (ret != LDAP_SUCCESS) {
        DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
        ret = EIO;
        goto done;
    }

    if (response_controls == NULL) {
        DEBUG(5, ("Server returned no controls.\n"));
    } else {
        for (c = 0; response_controls[c] != NULL; c++) {
            DEBUG(9, ("Server returned control [%s].\n",
                      response_controls[c]->ldctl_oid));
            if (strcmp(response_controls[c]->ldctl_oid,
                       LDAP_CONTROL_PASSWORDPOLICYRESPONSE) == 0) {
                ret = ldap_parse_passwordpolicy_control(state->sh->ldap,
                                                        response_controls[c],
                                                        &pp_expire, &pp_grace,
                                                        &pp_error);
                if (ret != LDAP_SUCCESS) {
                    DEBUG(1, ("ldap_parse_passwordpolicy_control failed.\n"));
                    ret = EIO;
                    goto done;
                }

                DEBUG(7, ("Password Policy Response: expire [%d] grace [%d] "
                          "error [%s].\n", pp_expire, pp_grace,
                          ldap_passwordpolicy_err2txt(pp_error)));
            }
        }
    }

    DEBUG(3, ("ldap_extended_operation result: %s(%d), %s\n",
            sss_ldap_err2string(state->result), state->result, errmsg));

    if (state->result != LDAP_SUCCESS) {
        if (errmsg) {
            state->user_error_message = talloc_strdup(state, errmsg);
            if (state->user_error_message == NULL) {
                DEBUG(1, ("talloc_strdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        }
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    ldap_controls_free(response_controls);
    ldap_memfree(errmsg);

    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
}

int sdap_exop_modify_passwd_recv(struct tevent_req *req,
                                 TALLOC_CTX * mem_ctx,
                                 enum sdap_result *result,
                                 char **user_error_message)
{
    struct sdap_exop_modify_passwd_state *state = tevent_req_data(req,
                                         struct sdap_exop_modify_passwd_state);

    *user_error_message = talloc_steal(mem_ctx, state->user_error_message);

    switch (state->result) {
        case LDAP_SUCCESS:
            *result = SDAP_SUCCESS;
            break;
        case LDAP_CONSTRAINT_VIOLATION:
            *result = SDAP_AUTH_PW_CONSTRAINT_VIOLATION;
            break;
        default:
            *result = SDAP_ERROR;
            break;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* ==Fetch-RootDSE============================================= */

struct sdap_get_rootdse_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;

    struct sysdb_attrs *rootdse;
};

static void sdap_get_rootdse_done(struct tevent_req *subreq);

struct tevent_req *sdap_get_rootdse_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh)
{
    struct tevent_req *req, *subreq;
    struct sdap_get_rootdse_state *state;
    const char *attrs[] = {
            "*",
            "altServer",
            SDAP_ROOTDSE_ATTR_NAMING_CONTEXTS,
            "supportedControl",
            "supportedExtension",
            "supportedFeatures",
            "supportedLDAPVersion",
            "supportedSASLMechanisms",
            SDAP_ROOTDSE_ATTR_DEFAULT_NAMING_CONTEXT,
            SDAP_IPA_LAST_USN, SDAP_AD_LAST_USN,
            NULL
    };

    DEBUG(9, ("Getting rootdse\n"));

    req = tevent_req_create(memctx, &state, struct sdap_get_rootdse_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->rootdse = NULL;

    subreq = sdap_get_generic_send(state, ev, opts, sh,
                                   "", LDAP_SCOPE_BASE,
                                   "(objectclass=*)", attrs, NULL, 0,
                                   dp_opt_get_int(state->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT));
    if (!subreq) {
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, sdap_get_rootdse_done, req);

    return req;
}

static void sdap_get_rootdse_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct sdap_get_rootdse_state *state = tevent_req_data(req,
                                             struct sdap_get_rootdse_state);
    struct sysdb_attrs **results;
    size_t num_results;
    int ret;

    ret = sdap_get_generic_recv(subreq, state, &num_results, &results);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    if (num_results == 0 || !results) {
        DEBUG(2, ("RootDSE could not be retrieved. "
                  "Please check that anonymous access to RootDSE is allowed\n"
              ));
        tevent_req_error(req, ENOENT);
        return;
    }

    if (num_results > 1) {
        DEBUG(2, ("Multiple replies when searching for RootDSE ??\n"));
        tevent_req_error(req, EIO);
        return;
    }

    state->rootdse = talloc_steal(state, results[0]);
    talloc_zfree(results);

    DEBUG(9, ("Got rootdse\n"));

    tevent_req_done(req);
}

int sdap_get_rootdse_recv(struct tevent_req *req,
                          TALLOC_CTX *memctx,
                          struct sysdb_attrs **rootdse)
{
    struct sdap_get_rootdse_state *state = tevent_req_data(req,
                                             struct sdap_get_rootdse_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *rootdse = talloc_steal(memctx, state->rootdse);

    return EOK;
}

/* ==Generic Search============================================ */

struct sdap_get_generic_state {
    struct tevent_context *ev;
    struct sdap_options *opts;
    struct sdap_handle *sh;
    const char *search_base;
    int scope;
    const char *filter;
    const char **attrs;
    struct sdap_attr_map *map;
    int map_num_attrs;
    int timeout;

    struct sdap_op *op;

    struct berval cookie;

    size_t reply_max;
    size_t reply_count;
    struct sysdb_attrs **reply;
};

static errno_t sdap_get_generic_step(struct tevent_req *req);
static void sdap_get_generic_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt);
static errno_t add_to_reply(struct sdap_get_generic_state *state,
                            struct sysdb_attrs *msg);

struct tevent_req *sdap_get_generic_send(TALLOC_CTX *memctx,
                                         struct tevent_context *ev,
                                         struct sdap_options *opts,
                                         struct sdap_handle *sh,
                                         const char *search_base,
                                         int scope,
                                         const char *filter,
                                         const char **attrs,
                                         struct sdap_attr_map *map,
                                         int map_num_attrs,
                                         int timeout)
{
    errno_t ret;
    struct sdap_get_generic_state *state;
    struct tevent_req *req;

    req = tevent_req_create(memctx, &state, struct sdap_get_generic_state);
    if (!req) return NULL;

    state->ev = ev;
    state->opts = opts;
    state->sh = sh;
    state->search_base = search_base;
    state->scope = scope;
    state->filter = filter;
    state->attrs = attrs;
    state->map = map;
    state->map_num_attrs = map_num_attrs;
    state->op = NULL;
    state->reply_max = 0;
    state->reply_count = 0;
    state->reply = NULL;
    state->timeout = timeout;
    state->cookie.bv_len = 0;
    state->cookie.bv_val = NULL;

    ret = sdap_get_generic_step(req);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
        return req;
    }

    return req;
}

static errno_t sdap_get_generic_step(struct tevent_req *req)
{
    struct sdap_get_generic_state *state =
            tevent_req_data(req, struct sdap_get_generic_state);
    char *errmsg;
    int lret;
    int optret;
    errno_t ret;
    int msgid;
    bool disable_paging;

    LDAPControl *page_control = NULL;
    LDAPControl *m_controls[2] = { NULL, NULL };

    /* Make sure to free any previous operations so
     * if we are handling a large number of pages we
     * don't waste memory.
     */
    talloc_zfree(state->op);

    DEBUG(6, ("calling ldap_search_ext with [%s][%s].\n", state->filter,
                                                          state->search_base));
    if (debug_level >= 7) {
        int i;

        if (state->attrs) {
            for (i = 0; state->attrs[i]; i++) {
                DEBUG(7, ("Requesting attrs: [%s]\n", state->attrs[i]));
            }
        }
    }

    disable_paging = dp_opt_get_bool(state->opts->basic, SDAP_DISABLE_PAGING);

    if (!disable_paging
            && sdap_is_control_supported(state->sh,
                                         LDAP_CONTROL_PAGEDRESULTS)) {
        lret = ldap_create_page_control(state->sh->ldap,
                                        state->sh->page_size,
                                        state->cookie.bv_val ?
                                            &state->cookie :
                                            NULL,
                                        false,
                                        &page_control);
        if (lret != LDAP_SUCCESS) {
            ret = EIO;
            goto done;
        }
        m_controls[0] = page_control;
    }

    lret = ldap_search_ext(state->sh->ldap, state->search_base,
                           state->scope, state->filter,
                           discard_const(state->attrs),
                           false, m_controls, NULL, NULL, 0, &msgid);
    ldap_control_free(page_control);
    m_controls[0] = NULL;
    if (lret != LDAP_SUCCESS) {
        DEBUG(3, ("ldap_search_ext failed: %s\n", sss_ldap_err2string(lret)));
        if (lret == LDAP_SERVER_DOWN) {
            ret = ETIMEDOUT;
            optret = ldap_get_option(state->sh->ldap,
                                     SDAP_DIAGNOSTIC_MESSAGE,
                                     (void*)&errmsg);
            if (optret == LDAP_SUCCESS) {
                DEBUG(3, ("Connection error: %s\n", errmsg));
                sss_log(SSS_LOG_ERR, "LDAP connection error: %s", errmsg);
                ldap_memfree(errmsg);
            }
            else {
                sss_log(SSS_LOG_ERR, "LDAP connection error, %s",
                                     sss_ldap_err2string(lret));
            }
        }

        else {
            ret = EIO;
        }
        goto done;
    }
    DEBUG(8, ("ldap_search_ext called, msgid = %d\n", msgid));

    ret = sdap_op_add(state, state->ev, state->sh, msgid,
                      sdap_get_generic_done, req,
                      state->timeout,
                      &state->op);
    if (ret != EOK) {
        DEBUG(1, ("Failed to set up operation!\n"));
        goto done;
    }

done:
    return ret;
}

static void sdap_get_generic_done(struct sdap_op *op,
                                 struct sdap_msg *reply,
                                 int error, void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    struct sdap_get_generic_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_state);
    struct sysdb_attrs *attrs;
    char *errmsg = NULL;
    int result;
    int ret;
    int lret;
    ber_int_t total_count;
    struct berval cookie;
    LDAPControl **returned_controls = NULL;
    LDAPControl *page_control;

    if (error) {
        tevent_req_error(req, error);
        return;
    }

    switch (ldap_msgtype(reply->msg)) {
    case LDAP_RES_SEARCH_REFERENCE:
        /* ignore references for now */
        talloc_free(reply);

        /* unlock the operation so that we can proceed with the next result */
        sdap_unlock_next_reply(state->op);
        break;

    case LDAP_RES_SEARCH_ENTRY:
        ret = sdap_parse_entry(state, state->sh, reply,
                               state->map, state->map_num_attrs,
                               &attrs, NULL);
        if (ret != EOK) {
            DEBUG(1, ("sdap_parse_generic_entry failed.\n"));
            tevent_req_error(req, ENOMEM);
            return;
        }

        ret = add_to_reply(state, attrs);
        if (ret != EOK) {
            DEBUG(1, ("add_to_reply failed.\n"));
            tevent_req_error(req, ret);
            return;
        }

        sdap_unlock_next_reply(state->op);
        break;

    case LDAP_RES_SEARCH_RESULT:
        ret = ldap_parse_result(state->sh->ldap, reply->msg,
                                &result, NULL, &errmsg, NULL,
                                &returned_controls, 0);
        if (ret != LDAP_SUCCESS) {
            DEBUG(2, ("ldap_parse_result failed (%d)\n", state->op->msgid));
            tevent_req_error(req, EIO);
            return;
        }

        DEBUG(6, ("Search result: %s(%d), %s\n",
                  sss_ldap_err2string(result), result, errmsg));

        if (result != LDAP_SUCCESS && result != LDAP_NO_SUCH_OBJECT) {
            DEBUG(2, ("Unexpected result from ldap: %s(%d), %s\n",
                      sss_ldap_err2string(result), result, errmsg));
        }
        ldap_memfree(errmsg);

        /* Determine if there are more pages to retrieve */
        page_control = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS,
                                         returned_controls, NULL );
        if (!page_control) {
            /* No paging support. We are done */
            tevent_req_done(req);
            return;
        }

        lret = ldap_parse_pageresponse_control(state->sh->ldap, page_control,
                                               &total_count, &cookie);
        ldap_controls_free(returned_controls);
        if (lret != LDAP_SUCCESS) {
            DEBUG(1, ("Could not determine page control"));
            tevent_req_error(req, EIO);
            return;
        }
        DEBUG(7, ("Total count [%lu]\n", total_count));

        if (cookie.bv_val != NULL && cookie.bv_len > 0) {
            /* Cookie contains data, which means there are more requests
             * to be processed.
             */
            talloc_zfree(state->cookie.bv_val);
            state->cookie.bv_len = cookie.bv_len;
            state->cookie.bv_val = talloc_memdup(state,
                                                 cookie.bv_val,
                                                 cookie.bv_len);
            if (!state->cookie.bv_val) {
                tevent_req_error(req, ENOMEM);
                return;
            }
            ber_memfree(cookie.bv_val);

            ret = sdap_get_generic_step(req);
            if (ret != EOK) {
                tevent_req_error(req, ENOMEM);
                return;
            }

            return;
        }
        /* The cookie must be freed even if len == 0 */
        ber_memfree(cookie.bv_val);

        /* This was the last page. We're done */

        tevent_req_done(req);
        return;

    default:
        /* what is going on here !? */
        tevent_req_error(req, EIO);
        return;
    }
}

static errno_t add_to_reply(struct sdap_get_generic_state *state,
                            struct sysdb_attrs *msg)
{
    if (state->reply == NULL || state->reply_max == state->reply_count) {
        state->reply_max += REPLY_REALLOC_INCREMENT;
        state->reply = talloc_realloc(state, state->reply,
                                      struct sysdb_attrs *,
                                      state->reply_max);
        if (state->reply == NULL) {
            DEBUG(1, ("talloc_realloc failed.\n"));
            return ENOMEM;
        }
    }

    state->reply[state->reply_count++] = talloc_steal(state->reply, msg);

    return EOK;
}

int sdap_get_generic_recv(struct tevent_req *req,
                          TALLOC_CTX *mem_ctx,
                          size_t *reply_count,
                          struct sysdb_attrs ***reply)
{
    struct sdap_get_generic_state *state = tevent_req_data(req,
                                            struct sdap_get_generic_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *reply_count = state->reply_count;
    *reply = talloc_steal(mem_ctx, state->reply);

    return EOK;
}

errno_t sdap_check_aliases(struct sysdb_ctx *sysdb,
                           struct sysdb_attrs *user_attrs,
                           struct sss_domain_info *dom,
                           struct sdap_options *opts,
                           bool steal_memberships)
{
    errno_t ret;
    const char **aliases = NULL;
    const char *name = NULL;
    struct ldb_message *msg;
    TALLOC_CTX *tmp_ctx = NULL;
    char **parents;
    uid_t alias_uid;
    int i;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    ret = sysdb_attrs_primary_name(sysdb, user_attrs,
                                   opts->user_map[SDAP_AT_USER_NAME].name,
                                   &name);
    if (ret != EOK) {
        DEBUG(1, ("Could not get the primary name\n"));
        goto done;
    }

    ret = sysdb_attrs_get_aliases(tmp_ctx, user_attrs, name, &aliases);
    if (ret != EOK) {
        DEBUG(1, ("Failed to get the alias list\n"));
        goto done;
    }

    for (i = 0; aliases[i]; i++) {
        /* In RFC2307 schema, another group might be referencing user
         * using secondary name, so there might be fake users in the cache
         * from a previous getgr call */
        ret = sysdb_search_user_by_name(tmp_ctx, sysdb, dom,
                                        aliases[i], NULL, &msg);
        if (ret && ret != ENOENT) {
            DEBUG(1, ("Error searching the cache\n"));
            goto done;
        } else if (ret == ENOENT) {
            DEBUG(9, ("No user with primary name same as alias %s\n", aliases[i]));
            continue;
        }

        alias_uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
        if (alias_uid) {
            DEBUG(1, ("Cache contains non-fake user with same name "
                      "as alias %s\n", aliases[i]));
            ret = EIO;
            goto done;
        }
        DEBUG(7, ("%s is a fake user\n", aliases[i]));

        if (steal_memberships) {
            /* Get direct sysdb parents */
            ret = sysdb_get_direct_parents(tmp_ctx, sysdb, dom,
                                           SYSDB_MEMBER_USER,
                                           aliases[i], &parents);
            if (ret) {
                DEBUG(1, ("Could not get direct parents for %s: %d [%s]\n",
                          aliases[i], ret, strerror(ret)));
                goto done;
            }

            ret = sysdb_update_members(sysdb, dom, name, SYSDB_MEMBER_USER,
                                       (const char *const *) parents,
                                       NULL);
            if (ret != EOK) {
                DEBUG(1, ("Membership update failed [%d]: %s\n",
                          ret, strerror(ret)));
                goto done;
            }
        }

        ret = sysdb_delete_user(tmp_ctx, sysdb, dom, aliases[i], alias_uid);
        if (ret) {
            DEBUG(1, ("Error deleting fake user %s\n", aliases[i]));
            goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

