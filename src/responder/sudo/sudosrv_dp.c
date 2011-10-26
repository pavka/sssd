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

#include <dbus/dbus.h>

#include "util/util.h"
#include "sbus/sbus_client.h"
#include "providers/data_provider.h"
#include "responder/common/responder.h"
#include "responder/sudo/sudosrv.h"

static void sudo_dp_process_reply(DBusPendingCall *pending, void *ptr)
{
    DEBUG(0, ("=== received SUDO reply===\n"));
}

int sudo_dp_refresh_send(struct cli_ctx *cctx, const char *domain, int timeout)
{
    struct be_conn *be_conn;
    DBusMessage *msg;
    int ret;

    /* double check dp_ctx has actually been initialized.
     * in some pathological cases it may happen that sudo starts up before
     * dp connection code is actually able to establish a connection.
     */
    ret = sss_dp_get_domain_conn(cctx->rctx,
                                 domain, &be_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("The Data Provider connection for %s is not available! "
               "This maybe a bug, it shouldn't happen!\n",
               domain));
        return EIO;
    }

    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DP_INTERFACE,
                                       DP_METHOD_SUDOHANDLER);
    if (msg == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("Out of memory?!\n"));
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sending SUDOers refresh request\n"));

    ret = sbus_conn_send(be_conn->conn, msg,
                         timeout, sudo_dp_process_reply,
                         cctx, NULL);
    dbus_message_unref(msg);

    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Unable to contact data provider "
                                  "for domain %s", domain));
    }

    return ret;
}
