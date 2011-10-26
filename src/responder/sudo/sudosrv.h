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

#ifndef SUDOSRV_H_
#define SUDOSRV_H_

#define SSS_SUDO_SBUS_SERVICE_VERSION 0x0001
#define SSS_SUDO_SBUS_SERVICE_NAME "sudo"

struct sudo_ctx {
    struct resp_ctx *rctx;
};

int sudo_cmd_execute(struct cli_ctx *cctx);

int sudo_dp_refresh_send(struct cli_ctx *cctx, const char *domain, int timeout);

struct sss_cmd_table *get_sudo_cmds(void);

#endif /* SUDOSRV_H_ */
