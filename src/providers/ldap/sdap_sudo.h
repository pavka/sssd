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

#ifndef _SDAP_SUDO_H_
#define _SDAP_SUDO_H_

struct sdap_sudo_ctx {
    struct be_ctx *be_ctx;
    struct be_req *be_req;
    struct be_sudo_req *req;
    struct sdap_id_ctx *sdap_ctx;
    struct sdap_id_op *sdap_op;
    struct sdap_id_conn_cache *sdap_conn_cache;

    const char *username;
    uint_t uid;
    char **groups;
};

/* (&(objectClass=sudoRole)(|(cn=defaults)(sudoUser=ALL)%s)) */
#define SDAP_SUDO_FILTER_USER "(&(objectClass=%s)(|(%s=%s)(%s=ALL)%s))"
#define SDAP_SUDO_FILTER_ALL  "(objectClass=%s)"
#define SDAP_SUDO_DEFAULTS    "defaults"

#define SDAP_SUDO_FILTER_USERNAME "(%s=%s)"
#define SDAP_SUDO_FILTER_UID "(%s=#%u)"
#define SDAP_SUDO_FILTER_GROUP "(%s=%%%s)"
#define SDAP_SUDO_FILTER_NETGROUP "(%s=+%s)"

#endif /* _SDAP_SUDO_H_ */
