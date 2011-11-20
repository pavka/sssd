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


struct cached_resolv_ctx *
cres_init(TALLOC_CTX *mem_ctx, struct resolv_ctx *res);

void
cres_reset(struct cached_resolv_ctx *cctx);

struct tevent_req *
cres_gethostbyname_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
                        struct cached_resolv_ctx *ctx, const char *name,
                        enum restrict_family family_order,
                        enum host_database *db);
int
cres_gethostbyname_recv(struct tevent_req *req,
                        struct resolv_hostent **rhostent);
