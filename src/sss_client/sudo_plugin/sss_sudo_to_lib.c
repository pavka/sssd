/*
    Authors:
        Pavel BÃ…Â™ezina <pbrezina@redhat.com>

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

/*
 * This file contains functions that would be nice to have in a common
 * plugin library from SUDO upstream.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <sys/stat.h>

#include "sss_client/sudo_plugin/sss_sudoplugin_private.h"

int command_exists(const char* command);

char * get_qualified_command_path(const char *command)
{
    char *path_env = NULL;
    char *path = NULL;
    char *cp = NULL;
    char *qualified = NULL;
    char pathbuf[PATH_MAX];
    int dot_in_path = 0;

    /*
     * If we were given a fully qualified or relative path
     * there is no need to look at $PATH.
     */
    if (strchr(command, '/') != NULL) {
        if (command_exists(command)) {
            return strdup(command);
        }

        return NULL;
    }

    path_env = getenv("PATH");
    path = strdup(path_env);
    if (path == NULL) {
        errno = ENOMEM;
        return NULL;
    }

    if (path == NULL) {
        return NULL;
    }

    do {
        cp = strchr(path, ':');
        if (cp != NULL) {
            *cp = '\0';
        }

        /*
         * Search current dir last if it is in $PATH This will miss sneaky
         * things like using './' or './/'
         */
        if (*path == '\0' || (*path == '.' && *(path + 1) == '\0')) {
            dot_in_path = 1;
        } else {
            snprintf(pathbuf, sizeof(char) * PATH_MAX, "%s/%s", path, command);
            if (command_exists(pathbuf)) {
                qualified = pathbuf;
                break;
            }
        }

        path = cp + 1;
    } while(cp != NULL);

    /*
     * Check current dir if dot was in the PATH
     */
    if (qualified == NULL && dot_in_path) {
        snprintf(pathbuf, sizeof(char) * PATH_MAX, "./%s", command);
        if (command_exists(pathbuf)) {
            qualified = pathbuf;
        }
    }

    /* free(path_env); do not free since it is from getenv() */
    if (qualified == NULL) {
        errno = ENOENT;
        return NULL;
    }

    return strdup(qualified);
}

int command_exists(const char* command)
{
    struct stat sb;

    if (command == NULL || command[0] == '\0') {
        return 0;
    };

    if (stat(command, &sb) == 0) {
        if (S_ISREG(sb.st_mode)
                && (sb.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))) {
            errno = EOK;
            return 1;
        }

        errno = EACCES;
    }

    return 0;
}
