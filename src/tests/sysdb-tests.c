/*
   SSSD

   System Database

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <stdlib.h>
#include <check.h>
#include <talloc.h>
#include <tevent.h>
#include <popt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "util/util.h"
#include "confdb/confdb_setup.h"
#include "db/sysdb_private.h"
#include "tests/common.h"

#define TESTS_PATH "tests_sysdb"
#define TEST_CONF_FILE "tests_conf.ldb"

#define TEST_ATTR_NAME "test_attr_name"
#define TEST_ATTR_VALUE "test_attr_value"
#define TEST_ATTR_UPDATE_VALUE "test_attr_update_value"
#define TEST_ATTR_ADD_NAME "test_attr_add_name"
#define TEST_ATTR_ADD_VALUE "test_attr_add_value"
#define CUSTOM_TEST_CONTAINER "custom_test_container"
#define CUSTOM_TEST_OBJECT "custom_test_object"

#define ASQ_TEST_USER "testuser27010"
#define ASQ_TEST_USER_UID 27010

#define MBO_USER_BASE 27500
#define MBO_GROUP_BASE 28500

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};

static int setup_sysdb_tests(struct sysdb_test_ctx **ctx)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    if (ret == -1 && errno != EEXIST) {
        fail("Could not create %s directory", TESTS_PATH);
        return EFAULT;
    }

    test_ctx = talloc_zero(NULL, struct sysdb_test_ctx);
    if (test_ctx == NULL) {
        fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        fail("Could not create event context");
        talloc_free(test_ctx);
        return EIO;
    }

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    if (conf_db == NULL) {
        fail("Out of memory, aborting!");
        talloc_free(test_ctx);
        return ENOMEM;
    }
    DEBUG(3, ("CONFDB: %s\n", conf_db));

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    if (ret != EOK) {
        fail("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    if (ret != EOK) {
        fail("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = confdb_get_domain(test_ctx->confdb, "local", &test_ctx->domain);
    if (ret != EOK) {
        fail("Could not retrieve LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sysdb_domain_init(test_ctx,
                            test_ctx->domain, TESTS_PATH, &test_ctx->sysdb);
    if (ret != EOK) {
        fail("Could not initialize connection to the sysdb (%d)", ret);
        talloc_free(test_ctx);
        return ret;
    }

    *ctx = test_ctx;
    return EOK;
}

struct test_data {
    struct tevent_context *ev;
    struct sysdb_test_ctx *ctx;

    const char *username;
    const char *groupname;
    const char *netgrname;
    const char *sudocmdname;
    uid_t uid;
    gid_t gid;
    const char *shell;

    bool finished;
    int error;

    struct sysdb_attrs *attrs;
    const char **attrlist;
    struct ldb_message *msg;

    size_t msgs_count;
    struct ldb_message **msgs;
};

static int test_add_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    ret = sysdb_add_user(data->ctx->sysdb, data->username,
                         data->uid, 0, gecos, homedir, "/bin/bash",
                         NULL, 0, 0);
    return ret;
}

static int test_store_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    ret = sysdb_store_user(data->ctx->sysdb, data->username, "x",
                           data->uid, 0, gecos, homedir,
                           data->shell ? data->shell : "/bin/bash",
                           NULL, NULL, -1, 0);
    return ret;
}

static int test_remove_user(struct test_data *data)
{
    struct ldb_dn *user_dn;
    int ret;

    user_dn = sysdb_user_dn(data->ctx->sysdb, data, "LOCAL", data->username);
    if (!user_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, user_dn, true);
    return ret;
}

static int test_remove_user_by_uid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_user(data->ctx->sysdb, NULL, data->uid);
    return ret;
}

static int test_remove_nonexistent_group(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data->ctx->sysdb, NULL, data->uid);
    return ret;
}

static int test_remove_nonexistent_user(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_user(data->ctx->sysdb, NULL, data->uid);
    return ret;
}

static int test_add_group(struct test_data *data)
{
    int ret;

    ret = sysdb_add_group(data->ctx->sysdb, data->groupname,
                          data->gid, NULL, 0, 0);
    return ret;
}

static int test_add_incomplete_group(struct test_data *data)
{
    int ret;

    ret = sysdb_add_incomplete_group(data->ctx->sysdb, data->groupname,
                                     data->gid, NULL, true, 0);
    return ret;
}

static int test_store_group(struct test_data *data)
{
    int ret;

    ret = sysdb_store_group(data->ctx->sysdb, data->groupname,
                            data->gid, NULL, -1, 0);
    return ret;
}

static int test_remove_group(struct test_data *data)
{
    struct ldb_dn *group_dn;
    int ret;

    group_dn = sysdb_group_dn(data->ctx->sysdb, data, "LOCAL", data->groupname);
    if (!group_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, group_dn, true);
    return ret;
}

static int test_remove_group_by_gid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data->ctx->sysdb, NULL, data->gid);
    if (ret == ENOENT) {
        ret = EOK;
    }
    return ret;
}

static int test_set_user_attr(struct test_data *data)
{
    int ret;

    ret = sysdb_set_user_attr(data->ctx->sysdb, data->username,
                              data->attrs, SYSDB_MOD_REP);
    return ret;
}

static int test_add_group_member(struct test_data *data)
{
    const char *username;
    int ret;

    username = talloc_asprintf(data, "testuser%d", data->uid);
    if (username == NULL) {
        return ENOMEM;
    }

    ret = sysdb_add_group_member(data->ctx->sysdb,
                                 data->groupname, username,
                                 SYSDB_MEMBER_USER);
    return ret;
}

static int test_remove_group_member(struct test_data *data)
{
    const char *username;
    int ret;

    username = talloc_asprintf(data, "testuser%d", data->uid);
    if (username == NULL) {
        return ENOMEM;
    }

    ret = sysdb_remove_group_member(data->ctx->sysdb,
                                    data->groupname, username,
                                    SYSDB_MEMBER_USER);
    return ret;
}

static int test_store_custom(struct test_data *data)
{
    char *object_name;
    int ret;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, data->uid);
    if (!object_name) {
        return ENOMEM;
    }

    ret = sysdb_store_custom(data->ctx->sysdb, object_name,
                             CUSTOM_TEST_CONTAINER, data->attrs);
    return ret;
}

static int test_delete_custom(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_custom(data->ctx->sysdb,
                              CUSTOM_TEST_OBJECT, CUSTOM_TEST_CONTAINER);
    return ret;
}

static int test_search_all_users(struct test_data *data)
{
    struct ldb_dn *base_dn;
    int ret;

    base_dn = ldb_dn_new_fmt(data, data->ctx->sysdb->ldb, SYSDB_TMPL_USER_BASE,
                             "LOCAL");
    if (base_dn == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_entry(data, data->ctx->sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, "objectClass=user",
                             data->attrlist, &data->msgs_count, &data->msgs);
    return ret;
}

static int test_delete_recursive(struct test_data *data)
{
    struct ldb_dn *dn;
    int ret;

    dn = ldb_dn_new_fmt(data, data->ctx->sysdb->ldb, SYSDB_DOM_BASE,
                        "LOCAL");
    if (!dn) {
        return ENOMEM;
    }

    ret = sysdb_delete_recursive(data->ctx->sysdb, dn, false);
    fail_unless(ret == EOK, "sysdb_delete_recursive returned [%d]", ret);
    return ret;
}

static int test_memberof_store_group(struct test_data *data)
{
    int ret;
    struct sysdb_attrs *attrs = NULL;
    char *member;
    int i;

    attrs = sysdb_new_attrs(data);
    if (!attrs) {
        return ENOMEM;
    }
    for (i = 0; data->attrlist && data->attrlist[i]; i++) {
        member = sysdb_group_strdn(data, data->ctx->domain->name,
                                   data->attrlist[i]);
        if (!member) {
            return ENOMEM;
        }
        ret = sysdb_attrs_steal_string(attrs, SYSDB_MEMBER, member);
        if (ret != EOK) {
            return ret;
        }
    }

    ret = sysdb_store_group(data->ctx->sysdb, data->groupname,
                            data->gid, attrs, -1, 0);
    return ret;
}

static int test_add_basic_netgroup(struct test_data *data)
{
    const char *description;
    int ret;

    description = talloc_asprintf(data, "Test Netgroup %d", data->uid);

    ret = sysdb_add_basic_netgroup(data->ctx->sysdb,
                                   data->netgrname, description);
    return ret;
}

static int test_remove_netgroup_entry(struct test_data *data)
{
    struct ldb_dn *netgroup_dn;
    int ret;

    netgroup_dn = sysdb_netgroup_dn(data->ctx->sysdb, data, "LOCAL", data->netgrname);
    if (!netgroup_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, netgroup_dn, true);
    return ret;
}

static int test_remove_netgroup_by_name(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_netgroup(data->ctx->sysdb, data->netgrname);
    return ret;
}

static int test_set_netgroup_attr(struct test_data *data)
{
    int ret;
    const char *description;
    struct sysdb_attrs *attrs = NULL;

    description = talloc_asprintf(data, "Sysdb Netgroup %d", data->uid);

    attrs = sysdb_new_attrs(data);
    if (!attrs) {
        return ENOMEM;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_DESCRIPTION, description);
    if (ret) {
        return ret;
    }

    ret = sysdb_set_netgroup_attr(data->ctx->sysdb,
                                  data->netgrname, attrs, SYSDB_MOD_REP);
    return ret;
}

static int test_add_basic_sudocmd(struct test_data *data)
{
    return sysdb_add_basic_sudocmd(data->ctx->sysdb,
                                   data->sudocmdname);
}

static int test_add_sudocmd(struct test_data *data)
{
    return sysdb_add_sudocmd(data->ctx->sysdb,
                             data->sudocmdname,
                             NULL, 30, 0);
}

static int test_remove_sudocmd(struct test_data *data)
{
    return sysdb_delete_sudocmd(data->ctx->sysdb, data->sudocmdname);
}

START_TEST (test_sysdb_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = test_store_user(data);

    fail_if(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_user_existing)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->username = talloc_asprintf(data, "testuser%d", _i);
    data->shell = talloc_asprintf(data, "/bin/ksh");

    ret = test_store_user(data);

    fail_if(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_store_group(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = test_remove_user(data);

    fail_if(ret != EOK, "Could not remove user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_user_by_uid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;

    ret = test_remove_user_by_uid(data);

    fail_if(ret != EOK, "Could not remove user with uid %d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_remove_group(data);

    fail_if(ret != EOK, "Could not remove group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_group_by_gid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;

    ret = test_remove_group_by_gid(data);

    fail_if(ret != EOK, "Could not remove group with gid %d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = test_add_user(data);

    fail_if(ret != EOK, "Could not add user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_add_group(data);

    fail_if(ret != EOK, "Could not add group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_incomplete_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_add_incomplete_group(data);

    fail_if(ret != EOK, "Could not add incomplete group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwnam)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *username;
    uid_t uid;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->sysdb,
                         username, &res);
    if (ret) {
        fail("sysdb_getpwnam failed for username %s (%d: %s)",
             username, ret, strerror(ret));
        goto done;
    }

    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    fail_unless(uid == _i, "Did not find the expected UID");

    /* Search for the user with the wrong case */
    username = talloc_asprintf(test_ctx, "TESTUSER%d", _i);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->sysdb,
                         username, &res);
    if (ret) {
        fail("sysdb_getpwnam failed for username %s (%d: %s)",
             username, ret, strerror(ret));
        goto done;
    }

    if (res->count != 0) {
        fail("The upper-case username search should fail.");
    }

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrnam)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *groupname;
    gid_t gid;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);

    ret = sysdb_getgrnam(test_ctx,
                         test_ctx->sysdb,
                         groupname, &res);
    if (ret) {
        fail("sysdb_getgrnam failed for groupname %s (%d: %s)",
             groupname, ret, strerror(ret));
        goto done;
    }

    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    fail_unless(gid == _i,
                "Did not find the expected GID (found %d expected %d)",
                gid, _i);

    /* Search for the group with the wrong case */
    groupname = talloc_asprintf(test_ctx, "TESTGROUP%d", _i);

    ret = sysdb_getgrnam(test_ctx,
                         test_ctx->sysdb,
                         groupname, &res);
    if (ret) {
        fail("sysdb_getgrnam failed for groupname %s (%d: %s)",
             groupname, ret, strerror(ret));
        goto done;
    }

    if (res->count != 0) {
        fail("The upper-case groupname search should fail.");
    }

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrgid)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *e_groupname;
    const char *groupname;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_getgrgid(test_ctx,
                         test_ctx->sysdb,
                         _i, &res);
    if (ret) {
        fail("sysdb_getgrgid failed for gid %d (%d: %s)",
             _i, ret, strerror(ret));
        goto done;
    }

    groupname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);

    e_groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);
    if (e_groupname == NULL) {
        fail("Cannot allocate memory");
        goto done;
    }

    fail_unless(strcmp(groupname, e_groupname) == 0,
                "Did not find the expected groupname (found %s expected %s)",
                groupname, e_groupname);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwuid)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *e_username;
    const char *username;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_getpwuid(test_ctx,
                         test_ctx->sysdb,
                         _i, &res);
    if (ret) {
        fail("sysdb_getpwuid failed for uid %d (%d: %s)",
             _i, ret, strerror(ret));
        goto done;
    }

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);

    e_username = talloc_asprintf(test_ctx, "testuser%d", _i);
    if (username == NULL) {
        fail("Cannot allocate memory");
        goto done;
    }

    fail_unless(strcmp(username, e_username) == 0,
                "Did not find the expected username (found %s expected %s)",
                username, e_username);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_enumgrent)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_enumgrent(test_ctx,
                          test_ctx->sysdb,
                          &res);
    fail_unless(ret == EOK,
                "sysdb_enumgrent failed (%d: %s)",
                ret, strerror(ret));

    /* 10 groups + 10 users (we're MPG) */
    fail_if(res->count != 20, "Expected 20 users, got %d", res->count);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_enumpwent)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_enumpwent(test_ctx,
                          test_ctx->sysdb,
                          &res);
    fail_unless(ret == EOK,
                "sysdb_enumpwent failed (%d: %s)",
                ret, strerror(ret));

    fail_if(res->count != 10, "Expected 10 users, got %d", res->count);

    talloc_free(test_ctx);
}
END_TEST


START_TEST (test_sysdb_set_user_attr)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 SYSDB_SHELL,
                                 "/bin/ksh");
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    ret = test_set_user_attr(data);

    fail_if(ret != EOK, "Could not modify user %s", data->username);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_user_attr)
{
    struct sysdb_test_ctx *test_ctx;
    const char *attrs[] = { SYSDB_SHELL, NULL };
    struct ldb_result *res;
    const char *attrval;
    char *username;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);

    ret = sysdb_get_user_attr(test_ctx, test_ctx->sysdb,
                              username, attrs, &res);
    if (ret) {
        fail("Could not get attributes for user %s", username);
        goto done;
    }

    fail_if(res->count != 1,
            "Invalid number of entries, expected 1, got %d", res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, 0);
    fail_if(strcmp(attrval, "/bin/ksh"),
            "Got bad attribute value for user %s", username);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = _i - 1000; /* the UID of user to add */

    ret = test_add_group_member(data);

    fail_if(ret != EOK, "Could not modify group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = _i - 1000; /* the UID of user to add */

    ret = test_remove_group_member(data);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_nonexistent_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = 12345;

    ret = test_remove_nonexistent_user(data);

    fail_if(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_nonexistent_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = 12345;

    ret = test_remove_nonexistent_group(data);

    fail_if(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        fail("Could not create attribute list");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_NAME,
                                 TEST_ATTR_VALUE);
    if (ret != EOK) {
        fail("Could not add attribute");
        return;
    }

    ret = test_store_custom(data);

    fail_if(ret != EOK, "Could not add custom object");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_custom_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *object_name;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    fail_unless(data != NULL, "talloc_zero failed");
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(test_ctx, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = NULL;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, 29010);
    fail_unless(object_name != NULL, "talloc_asprintf failed");

    ret = sysdb_search_custom_by_name(data, data->ctx->sysdb,
                                      object_name,
                                      CUSTOM_TEST_CONTAINER,
                                      data->attrlist,
                                      &data->msgs_count,
                                      &data->msgs);

    fail_if(ret != EOK, "Could not search custom object");

    fail_unless(data->msgs_count == 1,
                "Wrong number of objects, exptected [1] got [%d]",
                data->msgs_count);
    fail_unless(data->msgs[0]->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msgs[0]->num_elements);
    fail_unless(strcmp(data->msgs[0]->elements[0].name, TEST_ATTR_NAME) == 0,
                "Wrong attribute name");
    fail_unless(data->msgs[0]->elements[0].num_values == 1,
                "Wrong number of attribute values");
    fail_unless(strncmp((const char *)data->msgs[0]->elements[0].values[0].data,
                        TEST_ATTR_VALUE,
                        data->msgs[0]->elements[0].values[0].length) == 0,
                "Wrong attribute value");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_update_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = 29010;
    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        fail("Could not create attribute list");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_NAME,
                                 TEST_ATTR_UPDATE_VALUE);
    if (ret != EOK) {
        fail("Could not add attribute");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_ADD_NAME,
                                 TEST_ATTR_ADD_VALUE);
    if (ret != EOK) {
        fail("Could not add attribute");
        return;
    }

    ret = test_store_custom(data);

    fail_if(ret != EOK, "Could not add custom object");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_custom_update)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *object_name;
    struct ldb_message_element *el;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    fail_unless(data != NULL, "talloc_zero failed");
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(test_ctx, const char *, 3);
    fail_unless(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = TEST_ATTR_ADD_NAME;
    data->attrlist[2] = NULL;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, 29010);
    fail_unless(object_name != NULL, "talloc_asprintf failed");

    ret = sysdb_search_custom_by_name(data, data->ctx->sysdb,
                                      object_name,
                                      CUSTOM_TEST_CONTAINER,
                                      data->attrlist,
                                      &data->msgs_count,
                                      &data->msgs);

    fail_if(ret != EOK, "Could not search custom object");

    fail_unless(data->msgs_count == 1,
                "Wrong number of objects, exptected [1] got [%d]",
                data->msgs_count);
    fail_unless(data->msgs[0]->num_elements == 2,
                "Wrong number of results, expected [2] got [%d]",
                data->msgs[0]->num_elements);

    el = ldb_msg_find_element(data->msgs[0], TEST_ATTR_NAME);
    fail_unless(el != NULL, "Attribute [%s] not found", TEST_ATTR_NAME);
    fail_unless(el->num_values == 1, "Wrong number ([%d] instead of 1) "
                "of attribute values for [%s]", el->num_values,
                TEST_ATTR_NAME);
    fail_unless(strncmp((const char *) el->values[0].data,
                TEST_ATTR_UPDATE_VALUE,
                el->values[0].length) == 0,
                "Wrong attribute value");

    el = ldb_msg_find_element(data->msgs[0], TEST_ATTR_ADD_NAME);
    fail_unless(el != NULL, "Attribute [%s] not found", TEST_ATTR_ADD_NAME);
    fail_unless(el->num_values == 1, "Wrong number ([%d] instead of 1) "
                "of attribute values for [%s]", el->num_values,
                TEST_ATTR_ADD_NAME);
    fail_unless(strncmp((const char *) el->values[0].data,
                TEST_ATTR_ADD_VALUE,
                el->values[0].length) == 0,
                "Wrong attribute value");


    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    const char *filter = "(distinguishedName=*)";

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    fail_unless(data != NULL, "talloc_zero failed");
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(test_ctx, const char *, 3);
    fail_unless(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = TEST_ATTR_ADD_NAME;
    data->attrlist[2] = NULL;

    ret = sysdb_search_custom(data, data->ctx->sysdb,
                              filter,
                              CUSTOM_TEST_CONTAINER,
                              data->attrlist,
                              &data->msgs_count,
                              &data->msgs);

    fail_if(ret != EOK, "Could not search custom object");

    fail_unless(data->msgs_count == 10,
                "Wrong number of objects, exptected [10] got [%d]",
                data->msgs_count);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_delete_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;

    ret = test_delete_custom(data);

    fail_if(ret != EOK, "Could not delete custom object");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_cache_password)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_cache_password(test_ctx->sysdb,
                               data->username, data->username);

    fail_unless(ret == EOK, "sysdb_cache_password request failed [%d].", ret);

    talloc_free(test_ctx);
}
END_TEST

static void cached_authentication_without_expiration(const char *username,
                                                     const char *password,
                                                     int expected_result)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    time_t expire_date = -1;
    time_t delayed_until = -1;
    const char *val[2];
    val[1] = NULL;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = username;

    val[0] = "0";
    ret = confdb_add_param(test_ctx->confdb, true, CONFDB_PAM_CONF_ENTRY,
                           CONFDB_PAM_CRED_TIMEOUT, val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return;
    }

    ret = sysdb_cache_auth(test_ctx->sysdb, data->username,
                           (const uint8_t *)password, strlen(password),
                           test_ctx->confdb, false, &expire_date, &delayed_until);

    fail_unless(ret == expected_result, "sysdb_cache_auth request does not "
                                        "return expected result [%d].",
                                        expected_result);

    fail_unless(expire_date == 0, "Wrong expire date, expected [%d], got [%d]",
                                  0, expire_date);

    fail_unless(delayed_until == -1, "Wrong delay, expected [%d], got [%d]",
                                  -1, delayed_until);

    talloc_free(test_ctx);
}

static void cached_authentication_with_expiration(const char *username,
                                                  const char *password,
                                                  int expected_result)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    time_t expire_date = -1;
    const char *val[2];
    val[1] = NULL;
    time_t now;
    time_t expected_expire_date;
    time_t delayed_until = -1;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = username;

    val[0] = "1";
    ret = confdb_add_param(test_ctx->confdb, true, CONFDB_PAM_CONF_ENTRY,
                           CONFDB_PAM_CRED_TIMEOUT, val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return;
    }

    now = time(NULL);
    expected_expire_date = now + (24 * 60 * 60);
    DEBUG(9, ("Setting SYSDB_LAST_ONLINE_AUTH to [%lld].\n", (long long) now));

    data->attrs = sysdb_new_attrs(data);
    ret = sysdb_attrs_add_time_t(data->attrs, SYSDB_LAST_ONLINE_AUTH, now);

    ret = sysdb_set_user_attr(data->ctx->sysdb, data->username,
                              data->attrs, SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Could not modify user %s", data->username);

    ret = sysdb_cache_auth(test_ctx->sysdb, data->username,
                           (const uint8_t *) password, strlen(password),
                           test_ctx->confdb, false, &expire_date, &delayed_until);

    fail_unless(ret == expected_result,
                "sysdb_cache_auth request does not return expected "
                "result [%d], got [%d].", expected_result, ret);

    fail_unless(expire_date == expected_expire_date,
                "Wrong expire date, expected [%d], got [%d]",
                expected_expire_date, expire_date);

    fail_unless(delayed_until == -1, "Wrong delay, expected [%d], got [%d]",
                                  -1, delayed_until);

    talloc_free(test_ctx);
}

START_TEST (test_sysdb_cached_authentication_missing_password)
{
    TALLOC_CTX *tmp_ctx;
    char *username;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed.");

    username = talloc_asprintf(tmp_ctx, "testuser%d", _i);
    fail_unless(username != NULL, "talloc_asprintf failed.");

    cached_authentication_without_expiration(username, "abc", ENOENT);
    cached_authentication_with_expiration(username, "abc", ENOENT);

    talloc_free(tmp_ctx);

}
END_TEST

START_TEST (test_sysdb_cached_authentication_wrong_password)
{
    TALLOC_CTX *tmp_ctx;
    char *username;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed.");

    username = talloc_asprintf(tmp_ctx, "testuser%d", _i);
    fail_unless(username != NULL, "talloc_asprintf failed.");

    cached_authentication_without_expiration(username, "abc", EINVAL);
    cached_authentication_with_expiration(username, "abc", EINVAL);

    talloc_free(tmp_ctx);

}
END_TEST

START_TEST (test_sysdb_cached_authentication)
{
    TALLOC_CTX *tmp_ctx;
    char *username;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed.");

    username = talloc_asprintf(tmp_ctx, "testuser%d", _i);
    fail_unless(username != NULL, "talloc_asprintf failed.");

    cached_authentication_without_expiration(username, username, EOK);
    cached_authentication_with_expiration(username, username, EOK);

    talloc_free(tmp_ctx);

}
END_TEST

START_TEST (test_sysdb_prepare_asq_test_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = ASQ_TEST_USER_UID;

    ret = test_add_group_member(data);

    fail_if(ret != EOK, "Could not modify group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_asq_search)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_dn *user_dn;
    int ret;
    size_t msgs_count;
    struct ldb_message **msgs;
    int i;
    char *gid_str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed");

    data->attrlist[0] = "gidNumber";
    data->attrlist[1] = NULL;

    user_dn = sysdb_user_dn(data->ctx->sysdb, data, "LOCAL", ASQ_TEST_USER);
    fail_unless(user_dn != NULL, "sysdb_user_dn failed");

    ret = sysdb_asq_search(data, test_ctx->sysdb,
                           user_dn, NULL, "memberof",
                           data->attrlist, &msgs_count, &msgs);

    fail_if(ret != EOK, "Failed to send ASQ search request.\n");

    fail_unless(msgs_count == 10, "wrong number of results, "
                                  "found [%d] expected [10]", msgs_count);

    for (i = 0; i < msgs_count; i++) {
        fail_unless(msgs[i]->num_elements == 1, "wrong number of elements, "
                                     "found [%d] expected [1]",
                                     msgs[i]->num_elements);

        fail_unless(msgs[i]->elements[0].num_values == 1,
                    "wrong number of values, found [%d] expected [1]",
                    msgs[i]->elements[0].num_values);

        gid_str = talloc_asprintf(data, "%d", 28010 + i);
        fail_unless(gid_str != NULL, "talloc_asprintf failed.");
        fail_unless(strncmp(gid_str,
                            (const char *) msgs[i]->elements[0].values[0].data,
                            msgs[i]->elements[0].values[0].length)  == 0,
                            "wrong value, found [%.*s] expected [%s]",
                            msgs[i]->elements[0].values[0].length,
                            msgs[i]->elements[0].values[0].data, gid_str);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_all_users)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    int i;
    char *uid_str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed");

    data->attrlist[0] = "uidNumber";
    data->attrlist[1] = NULL;

    ret = test_search_all_users(data);

    fail_if(ret != EOK, "Search failed");

    fail_unless(data->msgs_count == 10,
                "wrong number of results, found [%d] expected [10]",
                data->msgs_count);

    for (i = 0; i < data->msgs_count; i++) {
        fail_unless(data->msgs[i]->num_elements == 1,
                    "wrong number of elements, found [%d] expected [1]",
                    data->msgs[i]->num_elements);

        fail_unless(data->msgs[i]->elements[0].num_values == 1,
                    "wrong number of values, found [%d] expected [1]",
                    data->msgs[i]->elements[0].num_values);

        uid_str = talloc_asprintf(data, "%d", 27010 + i);
        fail_unless(uid_str != NULL, "talloc_asprintf failed.");
        fail_unless(strncmp(uid_str,
                            (char *) data->msgs[i]->elements[0].values[0].data,
                            data->msgs[i]->elements[0].values[0].length)  == 0,
                            "wrong value, found [%.*s] expected [%s]",
                            data->msgs[i]->elements[0].values[0].length,
                            data->msgs[i]->elements[0].values[0].data, uid_str);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_delete_recursive)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;

    ret = test_delete_recursive(data);

    fail_if(ret != EOK, "Recursive delete failed");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_attrs_replace_name)
{
    struct sysdb_attrs *attrs;
    struct ldb_message_element *el;
    int ret;

    attrs = sysdb_new_attrs(NULL);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, "foo", "bar");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_add_string(attrs, "fool", "bool");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_add_string(attrs, "foot", "boot");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_replace_name(attrs, "foo", "foot");
    fail_unless(ret == EEXIST,
                "sysdb_attrs_replace overwrites existing attribute");

    ret = sysdb_attrs_replace_name(attrs, "foo", "oof");
    fail_unless(ret == EOK, "sysdb_attrs_replace failed");

    ret = sysdb_attrs_get_el(attrs, "foo", &el);
    fail_unless(ret == EOK, "sysdb_attrs_get_el failed");
    fail_unless(el->num_values == 0, "Attribute foo is not empty.");

    ret = sysdb_attrs_get_el(attrs, "oof", &el);
    fail_unless(ret == EOK, "sysdb_attrs_get_el failed");
    fail_unless(el->num_values == 1,
                "Wrong number of values for attribute oof, "
                "expected [1] got [%d].", el->num_values);
    fail_unless(strncmp("bar", (char *) el->values[0].data,
                        el->values[0].length) == 0,
                "Wrong value, expected [bar] got [%.*s]", el->values[0].length,
                                                          el->values[0].data);

    talloc_free(attrs);
}
END_TEST

START_TEST (test_sysdb_memberof_store_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = MBO_GROUP_BASE + _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    if (_i == 0) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        fail_unless(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = talloc_asprintf(data, "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
    }

    ret = test_memberof_store_group(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", data->gid);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_close_loop)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = MBO_GROUP_BASE;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = talloc_asprintf(data, "testgroup%d", data->gid + 9);
    data->attrlist[1] = NULL;

    ret = test_memberof_store_group(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", data->gid);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = MBO_USER_BASE + _i;
    data->gid = 0; /* MPG domain */
    data->username = talloc_asprintf(data, "testuser%d", data->uid);

    ret = test_store_user(data);

    fail_if(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_add_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i + MBO_GROUP_BASE);
    data->uid = MBO_USER_BASE + _i;

    ret = test_add_group_member(data);

    fail_if(ret != EOK, "Could not modify group %s", data->groupname);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid_without_group_5)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);
    if (_i == 5) {
        fail_unless(ret == ENOENT,
                    "sysdb_search_group_by_gid found "
                    "already deleted group");
        if (ret == ENOENT) ret = EOK;

        fail_if(ret != EOK, "Could not check group %d", data->gid);
    } else {
        fail_if(ret != EOK, "Could not check group %d", data->gid);

        fail_unless(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d]",
                    data->msg->num_elements);
        fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                    "Wrong attribute name");
        fail_unless(data->msg->elements[0].num_values == ((_i + 1) % 6),
                    "Wrong number of attribute values, "
                    "expected [%d] got [%d]", ((_i + 1) % 6),
                    data->msg->elements[0].num_values);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);

    fail_if(ret != EOK, "Could not check group %d", data->gid);

    fail_unless(data->msg->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msg->num_elements);
    fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == _i + 1,
                "Wrong number of attribute values, expected [%d] got [%d]",
                _i + 1, data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid_loop)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);

    fail_if(ret != EOK, "Could not check group %d", data->gid);

    fail_unless(data->msg->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msg->num_elements);
    fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == 10,
                "Wrong number of attribute values, expected [%d] got [%d]",
                10, data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid_loop_without_group_5)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);

    if (_i == 5) {
        fail_unless(ret == ENOENT,
                    "sysdb_search_group_by_gid_send found "
                    "already deleted group");
        if (ret == ENOENT) ret = EOK;

        fail_if(ret != EOK, "Could not check group %d", data->gid);
    } else {
        fail_if(ret != EOK, "Could not check group %d", data->gid);

        fail_unless(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d]",
                    data->msg->num_elements);
        fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                    "Wrong attribute name");
        fail_unless(data->msg->elements[0].num_values == ((_i + 5) % 10),
                    "Wrong number of attribute values, expected [%d] got [%d]",
                    ((_i + 5) % 10), data->msg->elements[0].num_values);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_attrs_to_list)
{
    struct sysdb_attrs *attrs_list[3];
    char **list;
    errno_t ret;

    TALLOC_CTX *test_ctx = talloc_new(NULL);

    attrs_list[0] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[0], "test_attr", "attr1");
    fail_if(ret, "Add string failed");
    attrs_list[1] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[1], "test_attr", "attr2");
    fail_if(ret, "Add string failed");
    attrs_list[2] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[2], "nottest_attr", "attr3");
    fail_if(ret, "Add string failed");

    ret = sysdb_attrs_to_list(test_ctx, attrs_list, 3,
                              "test_attr", &list);
    fail_unless(ret == EOK, "sysdb_attrs_to_list failed with code %d", ret);

    fail_unless(strcmp(list[0],"attr1") == 0, "Expected [attr1], got [%s]",
                                              list[0]);
    fail_unless(strcmp(list[1],"attr2") == 0, "Expected [attr2], got [%s]",
                                              list[1]);
    fail_unless(list[2] == NULL, "List should be NULL-terminated");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_update_members)
{
    struct sysdb_test_ctx *test_ctx;
    char **add_groups;
    char **del_groups;
    const char *user = "testuser27000";
    errno_t ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    /* Add a user to two groups */
    add_groups = talloc_array(test_ctx, char *, 3);
    add_groups[0] = talloc_strdup(add_groups, "testgroup28001");
    add_groups[1] = talloc_strdup(add_groups, "testgroup28002");
    add_groups[2] = NULL;

    ret = sysdb_update_members(test_ctx->sysdb, user, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups, NULL);
    fail_unless(ret == EOK, "Could not add groups");
    talloc_zfree(add_groups);

    /* Remove a user from one group and add to another */
    del_groups = talloc_array(test_ctx, char *, 2);
    del_groups[0] = talloc_strdup(del_groups, "testgroup28001");
    del_groups[1] = NULL;
    add_groups = talloc_array(test_ctx, char *, 2);
    add_groups[0] = talloc_strdup(add_groups, "testgroup28003");
    add_groups[1] = NULL;

    ret = sysdb_update_members(test_ctx->sysdb, user, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups,
                               (const char *const *)del_groups);
    fail_unless(ret == EOK, "Group replace failed");
    talloc_zfree(add_groups);
    talloc_zfree(del_groups);

    /* Remove a user from two groups */
    del_groups = talloc_array(test_ctx, char *, 3);
    del_groups[0] = talloc_strdup(del_groups, "testgroup28002");
    del_groups[1] = talloc_strdup(del_groups, "testgroup28003");
    del_groups[2] = NULL;

    ret = sysdb_update_members(test_ctx->sysdb, user, SYSDB_MEMBER_USER,
                               NULL, (const char *const *)del_groups);
    fail_unless(ret == EOK, "Could not remove groups");

    talloc_zfree(test_ctx);
}
END_TEST


START_TEST (test_sysdb_group_dn_name)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    struct ldb_dn *group_dn;
    const char *groupname;
    char *parsed;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);
    group_dn = sysdb_group_dn(test_ctx->sysdb, test_ctx, "LOCAL", groupname);
    if (!group_dn || !groupname) {
        fail("Out of memory");
        return;
    }

    ret = sysdb_group_dn_name(test_ctx->sysdb, test_ctx,
                              ldb_dn_get_linearized(group_dn), &parsed);
    fail_if(ret != EOK, "Cannot get the group name from DN");

    fail_if(strcmp(groupname, parsed) != 0,
            "Names don't match (got %s)", parsed);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_basic_netgroup)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_add_basic_netgroup(data);

    fail_if(ret != EOK, "Could not add netgroup %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_netgroup_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *netgrname;
    struct ldb_message *msg;
    struct ldb_dn *netgroup_dn;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);

    ret = sysdb_search_netgroup_by_name(test_ctx, test_ctx->sysdb,
                                        netgrname, NULL, &msg);
    fail_if(ret != EOK, "Could not find netgroup with name %s", netgrname);

    netgroup_dn = sysdb_netgroup_dn(test_ctx->sysdb, test_ctx,
                                    test_ctx->domain->name, netgrname);
    fail_if(netgroup_dn == NULL);
    fail_if(ldb_dn_compare(msg->dn, netgroup_dn) != 0, "Found wrong netgroup!\n");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_netgroup_entry)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_remove_netgroup_entry(data);

    fail_if(ret != EOK, "Could not remove netgroup %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_netgroup_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_remove_netgroup_by_name(data);

    fail_if(ret != EOK, "Could not remove netgroup with name %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_set_netgroup_attr)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_set_netgroup_attr(data);

    fail_if(ret != EOK, "Could not set netgroup attribute %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_netgroup_attr)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *description;
    const char *netgrname;
    struct ldb_result *res;
    const char *attrs[] = { SYSDB_DESCRIPTION, NULL };
    const char *attrval;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    description = talloc_asprintf(test_ctx, "Sysdb Netgroup %d", _i);
    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);

    ret = sysdb_get_netgroup_attr(test_ctx, test_ctx->sysdb,
                                  netgrname, attrs, &res);

    fail_if(ret != EOK, "Could not get netgroup attributes");
    fail_if(res->count != 1,
            "Invalid number of entries, expected 1, got %d", res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_DESCRIPTION, 0);
    fail_if(strcmp(attrval, description),
            "Got bad attribute value for netgroup %s", netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_add_netgroup_tuple)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *netgrname;
    const char *hostname;
    const char *username;
    const char *domainname;
    struct ldb_result *res;
    struct sysdb_netgroup_ctx **entries;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);
    fail_if(netgrname == NULL, "Out of memory");

    hostname = talloc_asprintf(test_ctx, "hostname%d", _i);
    fail_if(hostname == NULL, "Out of memory");

    username = talloc_asprintf(test_ctx, "username%d", _i);
    fail_if(username == NULL, "Out of memory");

    domainname = talloc_asprintf(test_ctx, "domainname%d", _i);
    fail_if(domainname == NULL, "Out of memory");

    ret = sysdb_add_netgroup_tuple(test_ctx->sysdb,
                                   netgrname, hostname,
                                   username, domainname);
    fail_unless(ret == EOK, "Failed to add netgr tuple");

    ret = sysdb_getnetgr(test_ctx, test_ctx->sysdb,
                         netgrname, &res);
    fail_unless(ret == EOK, "Failed to retrieve netgr information");

    ret = sysdb_netgr_to_entries(test_ctx, res, &entries);
    fail_unless(ret == EOK, "Failed to convert entries");

    fail_unless(entries && entries[0] && !entries[1],
                "Got more than one triple back");

    fail_unless(strcmp(entries[0]->value.triple.hostname, hostname) == 0,
                "Got [%s], expected [%s] for hostname",
                entries[0]->value.triple.hostname, hostname);

    fail_unless(strcmp(entries[0]->value.triple.username, username) == 0,
                "Got [%s], expected [%s] for username",
                entries[0]->value.triple.username, username);

    fail_unless(strcmp(entries[0]->value.triple.domainname, domainname) == 0,
                "Got [%s], expected [%s] for domainname",
                entries[0]->value.triple.domainname, domainname);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_remove_netgroup_tuple)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *netgrname;
    const char *hostname;
    const char *username;
    const char *domainname;
    struct ldb_result *res;
    struct sysdb_netgroup_ctx **entries;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);
    fail_if(netgrname == NULL, "Out of memory");

    hostname = talloc_asprintf(test_ctx, "hostname%d", _i);
    fail_if(hostname == NULL, "Out of memory");

    username = talloc_asprintf(test_ctx, "username%d", _i);
    fail_if(username == NULL, "Out of memory");

    domainname = talloc_asprintf(test_ctx, "domainname%d", _i);
    fail_if(domainname == NULL, "Out of memory");

    ret = sysdb_remove_netgroup_tuple(test_ctx->sysdb,
                                       netgrname, hostname,
                                       username, domainname);
    fail_unless(ret == EOK, "Failed to remove netgr tuple");

    ret = sysdb_getnetgr(test_ctx, test_ctx->sysdb,
                         netgrname, &res);
    fail_unless(ret == EOK, "Failed to retrieve netgr information");

    ret = sysdb_netgr_to_entries(test_ctx, res, &entries);
    fail_unless(ret == EOK, "Failed to convert entries");

    fail_unless(entries && !entries[0],"Found entries unexpectedly");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_add_netgroup_member)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *netgrname;
    const char *membername;
    struct ldb_result *res;
    struct sysdb_netgroup_ctx **entries;

    char *hostname1;
    char *username1;
    char *domainname1;

    char *hostname2;
    char *username2;
    char *domainname2;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);
    fail_if(netgrname == NULL, "Out of memory");

    membername = talloc_asprintf(test_ctx, "testnetgr%d", _i+1);
    fail_if(membername == NULL, "Out of memory");

    hostname1 = talloc_asprintf(test_ctx, "hostname%d", _i);
    hostname2 = talloc_asprintf(test_ctx, "hostname%d", _i+1);

    username1 = talloc_asprintf(test_ctx, "username%d", _i);
    username2 = talloc_asprintf(test_ctx, "username%d", _i+1);

    domainname1 = talloc_asprintf(test_ctx, "domainname%d", _i);
    domainname2 = talloc_asprintf(test_ctx, "domainname%d", _i+1);

    ret = sysdb_add_netgroup_member(test_ctx->sysdb, netgrname, membername);
    fail_unless(ret == EOK, "Failed to add netgr member");

    ret = sysdb_getnetgr(test_ctx, test_ctx->sysdb,
                         netgrname, &res);
    fail_unless(ret == EOK, "Failed to retrieve netgr information");

    ret = sysdb_netgr_to_entries(test_ctx, res, &entries);
    fail_unless(ret == EOK, "Failed to convert entries");

    fail_if(!entries, "Received a NULL triple");
    fail_if(!entries[0], "Did not get any responses");
    fail_unless(entries[0] && entries[1] && !entries[2],
            "Did not get exactly two responses");

    fail_unless(strcmp(entries[0]->value.triple.hostname, hostname1) == 0,
                "Got [%s], expected [%s] for hostname",
                entries[0]->value.triple.hostname, hostname1);

    fail_unless(strcmp(entries[0]->value.triple.username, username1) == 0,
                "Got [%s], expected [%s] for username",
                entries[0]->value.triple.username, username1);

    fail_unless(strcmp(entries[0]->value.triple.domainname, domainname1) == 0,
                "Got [%s], expected [%s] for domainname",
                entries[0]->value.triple.domainname, domainname1);

    fail_unless(strcmp(entries[1]->value.triple.hostname, hostname2) == 0,
                "Got [%s], expected [%s] for hostname",
                entries[0]->value.triple.hostname, hostname2);

    fail_unless(strcmp(entries[1]->value.triple.username, username2) == 0,
                "Got [%s], expected [%s] for username",
                entries[0]->value.triple.username, username2);

    fail_unless(strcmp(entries[1]->value.triple.domainname, domainname2) == 0,
                "Got [%s], expected [%s] for domainname",
                entries[0]->value.triple.domainname, domainname2);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_remove_netgroup_member)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *netgrname;
    const char *membername;
    struct ldb_result *res;
    struct sysdb_netgroup_ctx **entries;

    char *hostname;
    char *username;
    char *domainname;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);
    fail_if(netgrname == NULL, "Out of memory");

    membername = talloc_asprintf(test_ctx, "testnetgr%d", _i+1);
    fail_if(membername == NULL, "Out of memory");

    hostname = talloc_asprintf(test_ctx, "hostname%d", _i);
    username = talloc_asprintf(test_ctx, "username%d", _i);
    domainname = talloc_asprintf(test_ctx, "domainname%d", _i);

    ret = sysdb_remove_netgroup_member(test_ctx->sysdb, netgrname, membername);
    fail_unless(ret == EOK, "Failed to add netgr member");

    ret = sysdb_getnetgr(test_ctx, test_ctx->sysdb,
                         netgrname, &res);
    fail_unless(ret == EOK, "Failed to retrieve netgr information");

    ret = sysdb_netgr_to_entries(test_ctx, res, &entries);
    fail_unless(ret == EOK, "Failed to convert entries");

    fail_if(!entries, "Received a NULL triple");
    fail_if(!entries[0], "Did not get any responses");
    fail_unless(entries[0] && !entries[1],
                "Did not get exactly one response");

    fail_unless(strcmp(entries[0]->value.triple.hostname, hostname) == 0,
                "Got [%s], expected [%s] for hostname",
                entries[0]->value.triple.hostname, hostname);

    fail_unless(strcmp(entries[0]->value.triple.username, username) == 0,
                "Got [%s], expected [%s] for username",
                entries[0]->value.triple.username, username);

    fail_unless(strcmp(entries[0]->value.triple.domainname, domainname) == 0,
                "Got [%s], expected [%s] for domainname",
                entries[0]->value.triple.domainname, domainname);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_basic_sudocmd)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->sudocmdname = talloc_asprintf(data, "testsudocmd%d", _i);

    ret = test_add_basic_sudocmd(data);

    fail_if(ret != EOK, "Could not add sudo command %s", data->sudocmdname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_sudocmd)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->sudocmdname = talloc_asprintf(data, "testsudocmd%d", _i);

    ret = test_add_sudocmd(data);
    fail_if(ret != EOK, "Could not add sudo command %s", data->sudocmdname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_sudocmd)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    const char *sudocmdname;
    struct ldb_message *msg;
    struct ldb_dn *sudocmddn;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    sudocmdname = talloc_asprintf(test_ctx, "testsudocmd%d", _i);

    ret = sysdb_search_sudocmd(test_ctx, test_ctx->sysdb,
                               sudocmdname, NULL, &msg);
    fail_if(ret != EOK, "Could not find sudo command with name %s", sudocmdname);

    sudocmddn = sysdb_sudocmd_dn(test_ctx->sysdb, test_ctx,
                                 test_ctx->domain->name, sudocmdname);
    fail_if(sudocmddn == NULL);
    fail_if(ldb_dn_compare(msg->dn, sudocmddn) != 0, "Found wrong sudo command!\n");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_delete_sudocmd)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->sudocmdname = talloc_asprintf(data, "testsudocmd%d", _i);

    ret = test_remove_sudocmd(data);

    fail_if(ret != EOK, "Could not remove sudo command with name %s", data->sudocmdname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_odd_characters)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct ldb_message *msg;
    const struct ldb_val *val;
    const char odd_username[] = "*(odd)\\user,name";
    const char odd_groupname[] = "*(odd\\*)\\group,name";
    const char odd_netgroupname[] = "*(odd\\*)\\netgroup,name";
    const char *received_user;
    const char *received_group;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    static const char *netgr_attrs[] = SYSDB_NETGR_ATTRS;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    /* ===== Groups ===== */

    /* Add */
    ret = sysdb_add_incomplete_group(test_ctx->sysdb,
                                     odd_groupname, 20000, NULL, true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_search_group_by_name(test_ctx, test_ctx->sysdb,
                                    odd_groupname, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_group_by_name error [%d][%s]",
                            ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_getgrnam(test_ctx, test_ctx->sysdb, odd_groupname, &res);
    fail_unless(ret == EOK, "sysdb_getgrnam error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    received_group = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(received_group, odd_groupname) == 0,
                "Expected [%s], got [%s]",
                odd_groupname, received_group);
    talloc_free(res);


    /* ===== Users ===== */

    /* Add */
    ret = sysdb_add_basic_user(test_ctx->sysdb,
                               odd_username,
                               10000, 10000,
                               "","","");
    fail_unless(ret == EOK, "sysdb_add_fake_user error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_search_user_by_name(test_ctx, test_ctx->sysdb,
                                    odd_username, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_name error [%d][%s]",
                            ret, strerror(ret));
    val = ldb_dn_get_component_val(msg->dn, 0);
    fail_unless(strcmp((char *)val->data, odd_username)==0,
                "Expected [%s] got [%s]\n",
                odd_username, (char *)val->data);
    talloc_zfree(msg);

    /* Add to the group */
    ret = sysdb_add_group_member(test_ctx->sysdb, odd_groupname, odd_username,
                                 SYSDB_MEMBER_USER);
    fail_unless(ret == EOK, "sysdb_add_group_member error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_getpwnam(test_ctx, test_ctx->sysdb, odd_username, &res);
    fail_unless(ret == EOK, "sysdb_getpwnam error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    received_user = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(received_user, odd_username) == 0,
                "Expected [%s], got [%s]",
                odd_username, received_user);
    talloc_zfree(res);

    /* Attributes */
    ret = sysdb_get_user_attr(test_ctx, test_ctx->sysdb,
                              odd_username, user_attrs, &res);
    fail_unless(ret == EOK, "sysdb_get_user_attr error [%d][%s]",
                            ret, strerror(ret));
    talloc_free(res);

    /* Delete User */
    ret = sysdb_delete_user(test_ctx->sysdb, odd_username, 10000);
    fail_unless(ret == EOK, "sysdb_delete_user error [%d][%s]",
                            ret, strerror(ret));


    /* Delete Group */
    ret = sysdb_delete_group(test_ctx->sysdb, odd_groupname, 20000);
    fail_unless(ret == EOK, "sysdb_delete_group error [%d][%s]",
                            ret, strerror(ret));

    /* ===== Netgroups ===== */
    /* Add */
    ret = sysdb_add_netgroup(test_ctx->sysdb,
                             odd_netgroupname, "No description",
                             NULL, 30, 0);
    fail_unless(ret == EOK, "sysdb_add_netgroup error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_getnetgr(test_ctx, test_ctx->sysdb,
                         odd_netgroupname, &res);
    fail_unless(ret == EOK, "sysdb_getnetgr error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    talloc_zfree(res);

    ret = sysdb_get_netgroup_attr(test_ctx, test_ctx->sysdb,
                                  odd_netgroupname, netgr_attrs, &res);
    fail_unless(ret == EOK, "sysdb_get_netgroup_attr error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    talloc_zfree(res);

    /* ===== Arbitrary Entries ===== */

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_has_enumerated)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    bool enumerated;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    ret = sysdb_has_enumerated(test_ctx->sysdb, &enumerated);
    fail_if(ret != EOK, "Error [%d][%s] checking enumeration",
                        ret, strerror(ret));

    fail_if(enumerated, "Enumeration should default to false");

    ret = sysdb_set_enumerated(test_ctx->sysdb,
                               true);
    fail_if(ret != EOK, "Error [%d][%s] setting enumeration",
                        ret, strerror(ret));

    /* Recheck enumeration status */
    ret = sysdb_has_enumerated(test_ctx->sysdb,
                               &enumerated);
    fail_if(ret != EOK, "Error [%d][%s] checking enumeration",
                        ret, strerror(ret));

    fail_unless(enumerated, "Enumeration should have been set to true");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_original_dn_case_insensitive)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *filter;
    struct ldb_dn *base_dn;
    const char *no_attrs[] = { NULL };
    struct ldb_message **msgs;
    size_t num_msgs;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    ret = sysdb_add_incomplete_group(test_ctx->sysdb,
                                     "case_sensitive_group1", 29000,
                                     "cn=case_sensitive_group1,cn=example,cn=com",
                                     true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_add_incomplete_group(test_ctx->sysdb,
                                     "case_sensitive_group2", 29001,
                                     "cn=CASE_SENSITIVE_GROUP1,cn=EXAMPLE,cn=COM",
                                     true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Search by originalDN should yield 2 entries */
    filter = talloc_asprintf(test_ctx, "%s=%s", SYSDB_ORIG_DN,
                             "cn=case_sensitive_group1,cn=example,cn=com");
    fail_if(filter == NULL, "Cannot construct filter\n");

    base_dn = sysdb_domain_dn(test_ctx->sysdb, test_ctx, test_ctx->domain->name);
    fail_if(base_dn == NULL, "Cannot construct basedn\n");

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb,
                             base_dn, LDB_SCOPE_SUBTREE, filter, no_attrs,
                             &num_msgs, &msgs);
    fail_unless(ret == EOK, "cache search error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(num_msgs == 2, "Did not find the expected number of entries using "
                               "case insensitive originalDN search");
}
END_TEST

Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    TCase *tc_sysdb = tcase_create("SYSDB Tests");

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_user,27000,27010);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27000, 27010);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group, 28000, 28010);

    /* Verify the groups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrnam, 28000, 28010);

    /* sysdb_group_dn_name returns the name of the group in question */
    tcase_add_loop_test(tc_sysdb, test_sysdb_group_dn_name, 28000, 28010);

    /* sysdb_store_user allows setting attributes for existing users */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_user_existing, 27000, 27010);

    /* test the change */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_user_attr, 27000, 27010);

    /* Add and remove users in a group with sysdb_update_members */
    tcase_add_test(tc_sysdb, test_sysdb_update_members);

    /* Remove the other half by gid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group_by_gid, 28000, 28010);

    /* Remove the other half by uid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user_by_uid, 27000, 27010);

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_user, 27010, 27020);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27010, 27020);

    /* Verify the users can be queried by UID */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwuid, 27010, 27020);

    /* Enumerate the users */
    tcase_add_test(tc_sysdb, test_sysdb_enumpwent);

    /* Change their attribute */
    tcase_add_loop_test(tc_sysdb, test_sysdb_set_user_attr, 27010, 27020);

    /* Verify the change */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_user_attr, 27010, 27020);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_group, 28010, 28020);

    /* Verify the groups were added */

    /* Verify the groups can be queried by GID */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrgid, 28010, 28020);

    /* Enumerate the groups */
    tcase_add_test(tc_sysdb, test_sysdb_enumgrent);

    /* Add some members to the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group_member, 28010, 28020);

    /* Authenticate with missing cached password */
    tcase_add_loop_test(tc_sysdb, test_sysdb_cached_authentication_missing_password,
                        27010, 27011);

    /* Add a cached password */
    tcase_add_loop_test(tc_sysdb, test_sysdb_cache_password, 27010, 27011);

    /* Authenticate against cached password */
    tcase_add_loop_test(tc_sysdb, test_sysdb_cached_authentication_wrong_password,
                        27010, 27011);
    tcase_add_loop_test(tc_sysdb, test_sysdb_cached_authentication, 27010, 27011);

    /* ASQ search test */
    tcase_add_loop_test(tc_sysdb, test_sysdb_prepare_asq_test_user, 28011, 28020);
    tcase_add_test(tc_sysdb, test_sysdb_asq_search);

    /* Test search with more than one result */
    tcase_add_test(tc_sysdb, test_sysdb_search_all_users);

    /* Remove the members from the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_group_member, 28010, 28020);

    /* Remove the users by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user, 27010, 27020);

    /* Remove the groups by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group, 28010, 28020);

    /* test the ignore_not_found parameter for users */
    tcase_add_test(tc_sysdb, test_sysdb_remove_nonexistent_user);

    /* test the ignore_not_found parameter for groups */
    tcase_add_test(tc_sysdb, test_sysdb_remove_nonexistent_group);

    /* Create incomplete groups - remove will fail if the LDB objects don't exist */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_incomplete_group, 28000, 28010);
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group_by_gid, 28000, 28010);

    /* test custom operations */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_custom, 29010, 29020);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom_by_name);
    tcase_add_test(tc_sysdb, test_sysdb_update_custom);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom_update);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom);
    tcase_add_test(tc_sysdb, test_sysdb_delete_custom);

    /* test recursive delete */
    tcase_add_test(tc_sysdb, test_sysdb_delete_recursive);

    tcase_add_test(tc_sysdb, test_sysdb_attrs_replace_name);

    tcase_add_test(tc_sysdb, test_sysdb_attrs_to_list);

    /* Test unusual characters */
    tcase_add_test(tc_sysdb, test_odd_characters);

    /* Test sysdb enumerated flag */
    tcase_add_test(tc_sysdb, test_sysdb_has_enumerated);

    /* Test originalDN searches */
    tcase_add_test(tc_sysdb, test_sysdb_original_dn_case_insensitive);

/* ===== NETGROUP TESTS ===== */

    /* Create a new netgroup */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_basic_netgroup, 27000, 27010);

    /* Verify the netgroups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_search_netgroup_by_name, 27000, 27010);

    /* Test setting attributes */
    tcase_add_loop_test(tc_sysdb, test_sysdb_set_netgroup_attr, 27000, 27010);

    /* Verify they have been changed */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_netgroup_attr, 27000, 27010);

    /* Add some tuples */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_netgroup_tuple, 27000, 27010);

    /* Add a nested netgroup */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_netgroup_member, 27000, 27009);

    /* Remove the nested netgroup */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_netgroup_member, 27000, 27009);

    /* Remove the tuples */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_netgroup_tuple, 27000, 27010);

    /* Remove half of them by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_netgroup_by_name, 27000, 27005);

    /* Remove the other half by DN */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_netgroup_entry, 27005, 27010);

/* ===== SUDO TESTS ===== */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_basic_sudocmd, 27010, 27015);
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_sudocmd, 27015, 27020);
    tcase_add_loop_test(tc_sysdb, test_sysdb_search_sudocmd, 27010, 27020);
    tcase_add_loop_test(tc_sysdb, test_sysdb_delete_sudocmd, 27010, 27020);

/* Add all test cases to the test suite */
    suite_add_tcase(s, tc_sysdb);

    TCase *tc_memberof = tcase_create("SYSDB member/memberof/memberuid Tests");

    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group, 0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_user, 0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_add_group_member,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_memberuid,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE + 5, MBO_GROUP_BASE + 6);
    tcase_add_loop_test(tc_memberof,
                        test_sysdb_memberof_check_memberuid_without_group_5,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group, 0, 10);
    tcase_add_test(tc_memberof, test_sysdb_memberof_close_loop);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_user, 0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_add_group_member,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_memberuid_loop,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE + 5, MBO_GROUP_BASE + 6);
    tcase_add_loop_test(tc_memberof,
                        test_sysdb_memberof_check_memberuid_loop_without_group_5,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

    suite_add_tcase(s, tc_memberof);

    return s;
}

int main(int argc, const char *argv[]) {
    int opt;
    int ret;
    poptContext pc;
    int failure_count;
    int no_cleanup = 0;
    Suite *sysdb_suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    tests_set_cwd();

    ret = unlink(TESTS_PATH"/"LOCAL_SYSDB_FILE);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete the test ldb file (%d) (%s)\n",
                errno, strerror(errno));
        return EXIT_FAILURE;
    }

    sysdb_suite = create_sysdb_suite();
    sr = srunner_create(sysdb_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (failure_count == 0 && !no_cleanup) {
        ret = unlink(TESTS_PATH"/"TEST_CONF_FILE);
        if (ret != EOK) {
            fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                    errno, strerror(errno));
            return EXIT_FAILURE;
        }
        ret = unlink(TESTS_PATH"/"LOCAL_SYSDB_FILE);
        if (ret != EOK) {
            fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                    errno, strerror(errno));
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }
    return  EXIT_FAILURE;
}
