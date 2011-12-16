/*
    SSSD

    IPA Common utility code

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

#ifndef _IPA_COMMON_H_
#define _IPA_COMMON_H_

#include "util/util.h"
#include "confdb/confdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/krb5/krb5_common.h"

struct ipa_service {
    struct sdap_service *sdap;
    struct krb5_service *krb5_service;
};

/* the following defines are used to keep track of the options in the ldap
 * module, so that if they change and ipa is not updated correspondingly
 * this will trigger a runtime abort error */
#define IPA_OPTS_BASIC_TEST 56

/* the following define is used to keep track of the options in the krb5
 * module, so that if they change and ipa is not updated correspondingly
 * this will trigger a runtime abort error */
#define IPA_KRB5_OPTS_TEST 15

enum ipa_basic_opt {
    IPA_DOMAIN = 0,
    IPA_SERVER,
    IPA_HOSTNAME,
    IPA_DYNDNS_UPDATE,
    IPA_DYNDNS_IFACE,
    IPA_HBAC_SEARCH_BASE,
    IPA_HOST_SEARCH_BASE,
    IPA_KRB5_REALM,
    IPA_HBAC_REFRESH,
    IPA_HBAC_DENY_METHOD,
    IPA_HBAC_SUPPORT_SRCHOST,

    IPA_OPTS_BASIC /* opts counter */
};

enum ipa_netgroup_attrs {
    IPA_OC_NETGROUP = 0,
    IPA_AT_NETGROUP_NAME,
    IPA_AT_NETGROUP_MEMBER,
    IPA_AT_NETGROUP_MEMBER_OF,
    IPA_AT_NETGROUP_MEMBER_USER,
    IPA_AT_NETGROUP_MEMBER_HOST,
    IPA_AT_NETGROUP_EXTERNAL_HOST,
    IPA_AT_NETGROUP_DOMAIN,
    IPA_AT_NETGROUP_UUID,

    IPA_OPTS_NETGROUP /* attrs counter */
};

enum ipa_host_attrs {
    IPA_OC_HOST = 0,
    IPA_AT_HOST_FQDN,
    IPA_AT_HOST_MEMBER_OF,

    IPA_OPTS_HOST /* attrs counter */
};

struct ipa_auth_ctx {
    struct krb5_ctx *krb5_auth_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_auth_ctx *sdap_auth_ctx;
    struct dp_option *ipa_options;
};

struct ipa_id_ctx {
    struct sdap_id_ctx *sdap_id_ctx;
    struct ipa_options *ipa_options;
};

struct ipa_options {
    struct dp_option *basic;

    struct sdap_search_base **host_search_bases;
    struct ipa_service *service;

    /* id provider */
    struct sdap_options *id;
    struct ipa_id_ctx *id_ctx;
    struct resolv_ctx *resolv;

    /* auth and chpass provider */
    struct dp_option *auth;
    struct ipa_auth_ctx *auth_ctx;
};

int domain_to_basedn(TALLOC_CTX *memctx, const char *domain, char **basedn);

/* options parsers */
int ipa_get_options(TALLOC_CTX *memctx,
                    struct confdb_ctx *cdb,
                    const char *conf_path,
                    struct sss_domain_info *dom,
                    struct ipa_options **_opts);

int ipa_get_id_options(struct ipa_options *ipa_opts,
                       struct confdb_ctx *cdb,
                       const char *conf_path,
                       struct sdap_options **_opts);

int ipa_get_auth_options(struct ipa_options *ipa_opts,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct dp_option **_opts);

int ipa_service_init(TALLOC_CTX *memctx, struct be_ctx *ctx,
                     const char *servers,
                     struct ipa_options *options,
                     struct ipa_service **_service);

#endif /* _IPA_COMMON_H_ */
