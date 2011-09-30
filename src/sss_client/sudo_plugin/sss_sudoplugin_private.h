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

#ifndef SSS_SUDOPLUGIN_PRIVATE_H_
#define SSS_SUDOPLUGIN_PRIVATE_H_

#define SSS_SUDO_SUCCESS 1
#define SSS_SUDO_FAILURE 0
#define SSS_SUDO_GENERAL_ERROR -1
#define SSS_SUDO_USAGE_ERROR -2

#ifndef EOK
    #define EOK 0
#endif

char * get_qualified_command_path(const char *command);

#endif /* SSS_SUDOPLUGIN_PRIVATE_H_ */
