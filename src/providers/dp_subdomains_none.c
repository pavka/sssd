/*
    SSSD

    Data Provider - empty subomains provider

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "src/providers/dp_backend.h"

void none_subdomains_handler(struct be_req *be_req)
{
    DEBUG(SSSDBG_CONF_SETTINGS,
          ("The subdomains provider is not configured"));
    be_req->fn(be_req, DP_ERR_OK, EOK, NULL);
}
