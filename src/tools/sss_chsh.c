/*
   SSSD

   sss_chsh

   Authors:
       Jakub Hrozek <jhrozek@redhat.com>

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

/* FIXME - set shell before first login
 *       - reset shell to original value
 *       - what happens after entry is cleared from the cache?
 *       - maybe a special override container would be better
 *         -- the container would *not* be read after every getpwnam, but just
 *            when the user is about to be saved from the central DB, the entry
 *            from central DB would be updated with the shell override
 *         -- also when a shell override is set for a cached user
 */

#include <stdio.h>
#include <stdlib.h>
#include <talloc.h>
#include <popt.h>
#include <pwd.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "tools/sss_sync_ops.h"

#define SSS_CHSH_PAMSRV_NAME "sss_chsh"

#define EXIT_ERROR() do { \
    ret = EXIT_FAILURE;   \
    goto fini;            \
} while(0);

struct chsh_ctx {
    struct confdb_ctx *cdb;
    struct sysdb_ctx_list *db_list;
    struct sss_domain_info *domains;
};

static struct pam_conv pam_conv = {
    misc_conv, /* Use the default conversation from libpam_misc */
    NULL
};

static bool check_etc_shells(const char *user_shell)
{
    bool found = false;
    char *shell;

    setusershell();
    while((shell = getusershell())) {
        if (strcmp(shell, user_shell) == 0) {
            found = true;
        }
    }

    endusershell();
    return found;
}

static int ask_pam(struct passwd *pwd)
{
    int ret;
    int eret;
    pam_handle_t *pamh = NULL;

    ret = pam_start(SSS_CHSH_PAMSRV_NAME, pwd->pw_name, &pam_conv, &pamh);
    if (ret != PAM_SUCCESS) {
        DEBUG(1, ("Cannot start PAM conversation (%d)\n", ret));
        goto done;
    }

    ret = pam_authenticate(pamh, 0);
    if (ret != PAM_SUCCESS) {
        DEBUG(1, ("Cannot authenticate using PAM (%d): %s\n",
              ret, pam_strerror(pamh, ret)));
        goto done;
    }

    ret = pam_acct_mgmt(pamh, 0);
    if (ret != PAM_SUCCESS) {
        DEBUG(1, ("PAM account management failed (%d): %s\n",
              ret, pam_strerror(pamh, ret)));
        goto done;
    }

done:
    if (pamh) {
        eret = pam_end(pamh, ret);
        if (eret != PAM_SUCCESS) {
            DEBUG(1, ("Cannot end PAM conversation (%d): %s\n",
                  eret, pam_strerror(pamh, eret)));
            ret = eret;
        }
    }

    return ret;
}

static errno_t chsh_init(TALLOC_CTX *mem_ctx, struct chsh_ctx **_cctx)
{
    errno_t ret;
    struct chsh_ctx *cctx;
    TALLOC_CTX *tmp_ctx;
    const char *cdb_file;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    cctx = talloc_zero(tmp_ctx, struct chsh_ctx);
    if (!cctx) {
        ret = ENOMEM;
        goto done;
    }

    cdb_file = talloc_asprintf(tmp_ctx, "%s/%s", DB_PATH, CONFDB_FILE);
    if (cdb_file == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = confdb_init(cctx, &cctx->cdb, cdb_file);
    if (ret != EOK) {
        DEBUG(1, ("The confdb initialization failed\n"));
        goto done;
    }

    ret = confdb_get_domains(cctx->cdb, &cctx->domains);
    if (ret != EOK) {
        DEBUG(1, ("Could not get the list of domains\n"));
        goto done;
    }

    ret = sysdb_init(cctx, cctx->cdb, NULL, false, &cctx->db_list);
    if (ret != EOK) {
        DEBUG(1, ("The sysdb initialization failed\n"));
        goto done;
    }

    *_cctx = talloc_steal(mem_ctx, cctx);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}


static errno_t get_user_from_domain(TALLOC_CTX *mem_ctx,
                                    struct chsh_ctx *cctx,
                                    const char *name,
                                    struct sss_domain_info *dom,
                                    struct ldb_result **_res)
{
    struct ldb_result *res;
    struct sysdb_ctx *db;
    int ret;

    ret = sysdb_get_ctx_from_list(cctx->db_list, dom, &db);
    if (ret != EOK) {
        DEBUG(1, ("Cannot get sysdb handle for domain %s\n",
                dom->name));
        return ret;
    }

    ret = sysdb_getpwnam(mem_ctx, db, dom, name, &res);
    if (ret != EOK) {
        DEBUG(1, ("sysdb_getpwnam failed: [%d][%s]\n",
                ret, strerror(ret)));
        return ret;
    }

    if (res->count == 0) {
        *_res = NULL;
        return ENOENT;
    }

    *_res = res;
    return EOK;
}

static errno_t set_shell(struct chsh_ctx *cctx,
                         const char *name,
                         struct sss_domain_info *domain,
                         const char *shell)
{
    struct sysdb_attrs *attrs;
    struct sysdb_ctx *db;
    TALLOC_CTX *tmp_ctx;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    attrs = sysdb_new_attrs(tmp_ctx);
    if (!attrs) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_get_ctx_from_list(cctx->db_list, domain, &db);
    if (ret != EOK) {
        DEBUG(1, ("Cannot get sysdb handle for domain %s\n",
                  domain->name));
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_SHELL_OVERRIDE, shell);
    if (ret) goto done;

    ret = sysdb_set_user_attr(tmp_ctx, db,
                              domain, name, attrs, SYSDB_MOD_REP);
    goto done;

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t change_shell(struct chsh_ctx *cctx,
                            struct passwd *pwd,
                            struct sss_domain_info *user_domain,
                            const char *shell)
{
    struct sss_domain_info *dom;
    struct ldb_result *res;
    TALLOC_CTX *tmp_ctx;
    int ret;
    uid_t db_uid;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) return ENOMEM;

    if (user_domain) {
        ret = get_user_from_domain(tmp_ctx, cctx, pwd->pw_name,
                                   user_domain, &res);
        if (ret) {
            DEBUG(1, ("FQDN lookup for %s@%s failed [%d]: %s\n",
                      pwd->pw_name, user_domain->name, ret, strerror(ret)));
            goto done;
        }
    } else {
        for (dom = cctx->domains; dom; dom = dom->next) {
            ret = get_user_from_domain(tmp_ctx, cctx, pwd->pw_name,
                                       dom, &res);
            if (ret == EOK) {
                break;
            } else if (ret == ENOENT) {
                /* No such user in this domain, try another one */
                continue;
            } else {
                DEBUG(1, ("lookup for %s@%s failed [%d]: %s\n",
                        pwd->pw_name, user_domain->name, ret, strerror(ret)));
                goto done;
            }

        }
    }

    if (res->count == 0) {
        /* Did not find a user */
        ret = ENOENT;
        goto done;
    }

    /* Got a user, check UID match */
    db_uid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 0);
    if (!db_uid) {
        DEBUG(1, ("No UID found\n"));
        ret = EIO;
        goto done;
    }

    if (pwd->pw_uid != db_uid) {
        DEBUG(1, ("UID mismatch\n"));
        ret = EIO;
        goto done;
    }

    /* Set the new shell */
    ret = set_shell(cctx, pwd->pw_name, dom, shell);
    if (ret) {
        DEBUG(1, ("Cannot set shell\n"));
        ret = EIO;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

int main(int argc, const char **argv)
{
    int ret = EXIT_SUCCESS;

    TALLOC_CTX *mem_ctx;
    struct chsh_ctx *cctx;

    uid_t uid;
    struct passwd *pwd = NULL;

    const char *pc_shell = NULL;
    char *pc_user = NULL;
    int pc_debug = 0;
    poptContext pc = NULL;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug", '\0', POPT_ARG_INT | POPT_ARGFLAG_DOC_HIDDEN, &pc_debug,
                    0, _("The debug level to run with"), NULL },
        { "user", 'u', POPT_ARG_STRING, &pc_user,
                    0, _("Set login shell of this user"), NULL },
        POPT_TABLEEND
    };

    debug_prg_name = argv[0];

    ret = set_locale();
    if (ret != EOK) {
        DEBUG(1, ("set_locale failed (%d): %s\n", ret, strerror(ret)));
        ERROR("Error setting the locale\n");
        EXIT_ERROR();
    }

    mem_ctx = talloc_new(NULL);
    if (!mem_ctx) EXIT_ERROR();

    ret = chsh_init(mem_ctx, &cctx);
    if (ret) EXIT_ERROR();

    /* parse parameters */
    pc = poptGetContext(NULL, argc, argv, long_options, 0);
    poptSetOtherOptionHelp(pc, "SHELL");
    while ((ret = poptGetNextOpt(pc)) > 0) {
        switch (ret) {
            case 'u':
                pc_user = poptGetOptArg(pc);
                if (!pc_user) {
                    BAD_POPT_PARAMS(pc, _("Specify the user name\n"),
                                    ret, fini);
                }
                break;
        }
    }
    if (ret != -1) {
        BAD_POPT_PARAMS(pc, poptStrerror(ret), ret, fini);
    }

    pc_shell = poptGetArg(pc);
    if (pc_shell == NULL) {
        BAD_POPT_PARAMS(pc, _("Specify the shell to set\n"), ret, fini);
    }

    debug_level = pc_debug;

    if (!check_etc_shells(pc_shell)) {
        DEBUG(1, ("The shell %s was not found on this machine\n", pc_shell));
        ERROR("The shell %s was not found on this machine\n", pc_shell);
        EXIT_ERROR();
    }

    /* Root can set anyone's shell and does not have to authenticate */
    uid = getuid();
    if (uid != 0) {
        if (pc_user) {
            ERROR("Only root can set shell for an other user\n");
            EXIT_ERROR();
        }

        errno = 0;
        pwd = getpwuid(uid);
        if (!pwd) {
            ret = errno;
            DEBUG(1, ("Cannot get info for uid %llu (%d): %s\n",
                  uid, ret, strerror(ret)));
            EXIT_ERROR();
        }
    } else {
        if (!pc_user) {
            ERROR("root is not handled by sssd\n");
            EXIT_ERROR();
        }

        errno = 0;
        pwd = getpwnam(pc_user);
        if (!pwd) {
            ret = errno;
            DEBUG(1, ("Cannot get info for user %s (%d): %s\n",
                  pc_user, ret, strerror(ret)));
            EXIT_ERROR();
        }
    }

    ret = ask_pam(pwd);
    if (ret) {
        ERROR("Could not authenticate user\n");
        EXIT_ERROR();
    }

    ret = change_shell(cctx, pwd, NULL, pc_shell);
    if (ret) {
        ERROR("Could not change the shell for %s\n", pwd->pw_name);
        EXIT_ERROR();
    }

    DEBUG(0, ("setting %s for %s\n", pc_shell, pwd->pw_name));
    ret = EXIT_SUCCESS;
fini:
    talloc_free(mem_ctx);
    poptFreeContext(pc);
    exit(ret);
}
