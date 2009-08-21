/*
   SSSD

   sss_groupdel

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009

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

#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "db/sysdb.h"
#include "util/util.h"
#include "tools/tools_util.h"

#ifndef GROUPDEL
#define GROUPDEL SHADOW_UTILS_PATH"/groupdel "
#endif

#ifndef GROUPDEL_GROUPNAME
#define GROUPDEL_GROUPNAME "%s "
#endif


static void groupdel_req_done(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);

    data->error = sysdb_transaction_commit_recv(req);
    data->done = true;
}

/* sysdb callback */
static void groupdel_done(void *pvt, int error, struct ldb_result *ignore)
{
    struct ops_ctx *data = talloc_get_type(pvt, struct ops_ctx);
    struct tevent_req *req;

    if (error != EOK) {
        goto fail;
    }

    req = sysdb_transaction_commit_send(data, data->ev, data->handle);
    if (!req) {
        error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, groupdel_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->done = true;
}

static void group_del_done(struct tevent_req *subreq);

static void group_del(struct tevent_req *req)
{
    struct ops_ctx *data = tevent_req_callback_data(req, struct ops_ctx);
    struct tevent_req *subreq;
    struct ldb_dn *group_dn;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return groupdel_done(data, ret, NULL);
    }

    group_dn = sysdb_group_dn(data->ctx->sysdb, data,
                              data->domain->name, data->name);
    if (group_dn == NULL) {
        DEBUG(1, ("Could not construct a group DN\n"));
        return groupdel_done(data, ENOMEM, NULL);
    }

    subreq = sysdb_delete_entry_send(data, data->ev, data->handle, group_dn, false);
    if (!subreq)
        return groupdel_done(data, ENOMEM, NULL);

    tevent_req_set_callback(subreq, group_del_done, data);
}

static void group_del_done(struct tevent_req *subreq)
{
    struct ops_ctx *data = tevent_req_callback_data(subreq, struct ops_ctx);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);

    return groupdel_done(data, ret, NULL);
}

static int groupdel_legacy(struct ops_ctx *ctx)
{
    int ret = EOK;
    char *command = NULL;

    APPEND_STRING(command, GROUPDEL);
    APPEND_PARAM(command, GROUPDEL_GROUPNAME, ctx->name);

    ret = system(command);
    if (ret) {
        if (ret == -1) {
            DEBUG(1, ("system(3) failed\n"));
        } else {
            DEBUG(1, ("Could not exec '%s', return code: %d\n",
                      command, WEXITSTATUS(ret)));
        }
        talloc_free(command);
        return EFAULT;
    }

    talloc_free(command);
    return ret;
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;
    int pc_debug = 0;
    struct ops_ctx *data = NULL;
    struct tools_ctx *ctx = NULL;
    struct tevent_req *req;
    struct sss_domain_info *dom;
    struct group *grp_info;
    const char *pc_groupname = NULL;
    enum id_domain domain_type;

    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    CHECK_ROOT(ret, debug_prg_name);

    ret = init_sss_tools(&ctx);
    if(ret != EOK) {
        DEBUG(1, ("init_sss_tools failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error initializing the tools\n");
        ret = EXIT_FAILURE;
        goto fini;
    }

    data = talloc_zero(NULL, struct ops_ctx);
    if (data == NULL) {
        DEBUG(1, ("Could not allocate memory for data context\n"));
        ERROR("Out of memory\n");
        return ENOMEM;
    }
    data->ctx = ctx;
    data->ev = ctx->ev;

    /* parse ops_ctx */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "USERNAME");
    if((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        ret = EXIT_FAILURE;
        goto fini;
    }

    debug_level = pc_debug;

    pc_groupname = poptGetArg(pc);
    if(pc_groupname == NULL) {
        usage(pc, _("Specify group to delete\n"));
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = parse_name_domain(data, pc_groupname);
    if (ret != EOK) {
        ret = EXIT_FAILURE;
        goto fini;
    }

    /* arguments processed, go on to actual work */
    grp_info = getgrnam(data->name);
    if (grp_info) {
        data->gid = grp_info->gr_gid;
    }

    /* arguments processed, go on to actual work */
    ret = get_domain_by_id(data->ctx, data->gid, &dom);
    if (ret != EOK) {
        ERROR("Cannot get domain info\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    if (data->domain && data->gid && data->domain != dom) {
        ERROR("Selected domain %s conflicts with selected GID %llu\n",
                data->domain->name, (unsigned long long int) data->gid);
        ret = EXIT_FAILURE;
        goto fini;
    }
    if (data->domain == NULL && dom) {
        data->domain = dom;
    }

    domain_type = get_domain_type(data->ctx, data->domain);
    switch (domain_type) {
        case ID_IN_LOCAL:
            break;

        case ID_IN_LEGACY_LOCAL:
            ret = groupdel_legacy(data);
            if(ret != EOK) {
                ERROR("Cannot delete group from domain using the legacy tools\n");
                ret = EXIT_FAILURE;
                goto fini;
            }
            break; /* Also delete possible cached entries in sysdb */

        case ID_OUTSIDE:
            ERROR("The selected GID is outside all domain ranges\n");
            ret = EXIT_FAILURE;
            goto fini;

        case ID_IN_OTHER:
            DEBUG(1, ("Cannot remove group from domain %s\n", dom->name));
            ERROR("Unsupported domain type\n");
            ret = EXIT_FAILURE;
            goto fini;

        default:
            DEBUG(1, ("Unknown return code %d from get_domain_type\n", domain_type));
            ERROR("Error looking up domain\n");
            ret = EXIT_FAILURE;
            goto fini;
    }

    /* groupdel */
    req = sysdb_transaction_send(ctx, ctx->ev, ctx->sysdb);
    if (!req) {
        DEBUG(1, ("Could not start transaction (%d)[%s]\n", ret, strerror(ret)));
        ERROR("Transaction error. Could not remove group.\n");
        ret = EXIT_FAILURE;
        goto fini;
    }
    tevent_req_set_callback(req, group_del, data);

    while (!data->done) {
        tevent_loop_once(ctx->ev);
    }

    if (data->error) {
        ret = data->error;
        DEBUG(1, ("sysdb operation failed (%d)[%s]\n", ret, strerror(ret)));
        switch (ret) {
            case ENOENT:
                /* if we got ENOENT after deleting group from legacy domain
                 * that just means there was no cached entry to delete */
                if (domain_type == ID_IN_LEGACY_LOCAL) {
                    ret = EXIT_SUCCESS;
                    goto fini;
                }
                ERROR("No such user\n");
                break;

            default:
                ERROR("Internal error. Could not remove group.\n");
                break;
        }
        ret = EXIT_FAILURE;
        goto fini;
    }

    ret = EXIT_SUCCESS;

fini:
    talloc_free(ctx);
    talloc_free(data);
    poptFreeContext(pc);
    exit(ret);
}

