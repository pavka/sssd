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

#include "config.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sudo_plugin.h>

#include "sss_client/sudo_plugin/sss_sudoplugin.h"
#include "sss_client/sudo_plugin/sss_sudoplugin_private.h"
#include "sss_client/sss_cli.h"

struct plugin_state {
    sudo_conv_t conversation;
    sudo_printf_t printf;
    char * const *settings;
    char * const *user_info;
    char * const *user_env;
};

int policy_open(unsigned int version,
                sudo_conv_t sudo_conversation,
                sudo_printf_t sudo_printf,
                char * const settings[],
                char * const user_info[],
                char * const user_env[]);

void policy_close(int exit_status,
                  int error);

int policy_version(int verbose);

int policy_list(int argc,
                char * const argv[],
                int verbose,
                const char *list_user);

int policy_check(int argc,
                 char * const argv[],
                 char *env_add[],
                 char **command_out[],
                 char **argv_out[],
                 char **user_env_out[]);

static errno_t policy_check_create_query(const char *qualified_command_path,
                                         char * const *settings,
                                         char * const *user_info,
                                         char * const *user_env,
                                         char * const *env_add,
                                         int argc,
                                         char * const argv[],
                                         char **query,
                                         int *query_length);

static errno_t policy_check_parse_response(char *response,
                                           int response_length,
                                           int *result,
                                           char ***_command_out,
                                           char ***_argv_out,
                                           char ***_user_env_out);


/* SUDO Plugin structure */
struct policy_plugin sss_sudo_policy = {
    SUDO_POLICY_PLUGIN,
    SUDO_API_VERSION,
    policy_open,
    policy_close,
    policy_version,
    policy_check,
    policy_list,
    NULL, /* validate */
    NULL, /* invalidate */
    NULL /* session init */
};

/* Global plugin state initialized from policy_check with data passed by SUDO */
static struct plugin_state plugin = {NULL, NULL, NULL, NULL, NULL};

int policy_open(unsigned int version,
                sudo_conv_t sudo_conversation,
                sudo_printf_t sudo_printf,
                char * const settings[],
                char * const user_info[],
                char * const user_env[])
{
    if (sudo_conversation == NULL || settings == NULL) {
        return SSS_SUDO_USAGE_ERROR;
    }

    /* check Plugin API version */

    /*
     * TODO: Do we need to check major and minor version or major is enough?
     */
    if (version != SUDO_API_VERSION) {
        sudo_printf(SUDO_CONV_ERROR_MSG, "The SSS SUDO plugin requires "
                                         "API version %d. Your version is %d",
                                         SUDO_API_VERSION, version);

        return SSS_SUDO_GENERAL_ERROR;
    }

    /* save input variables */

    plugin.conversation = sudo_conversation;
    plugin.printf = sudo_printf;
    plugin.settings = settings;
    plugin.user_info = user_info;
    plugin.user_env = user_env;

    return SSS_SUDO_SUCCESS;
}

void policy_close(int exit_status, int error)
{
    if (error) {
        plugin.printf(SUDO_CONV_ERROR_MSG, "Command error: %s\n", strerror(error));
    } else if (WIFEXITED(exit_status)) {
        plugin.printf(SUDO_CONV_INFO_MSG, "Command exited with status %d\n",
                    WEXITSTATUS(exit_status));
    } else if (WIFSIGNALED(exit_status)) {
        plugin.printf(SUDO_CONV_INFO_MSG, "Command was killed by signal %d\n",
                    WTERMSIG(exit_status));
    }

    return;
}

int policy_version(int verbose)
{
    return SSS_SUDO_SUCCESS;
}

int policy_list(int argc,
                char * const argv[],
                int verbose,
                const char *list_user)
{
    return SSS_SUDO_SUCCESS;
}

int policy_check(int argc,
                 char * const argv[],
                 char *env_add[],
                 char **command_out[],
                 char **argv_out[],
                 char **user_env_out[])
{
    char *qualified_command_path = NULL;
    char *query = NULL;
    int query_length = 0;
    int ret = 0;
    int errnop;
    int sudo_result = SSS_SUDO_FAILURE;
    struct sss_cli_req_data request_data;
    uint8_t *reply_buf = NULL;
    size_t reply_len;

    if (argc <= 0) {
        plugin.printf(SUDO_CONV_ERROR_MSG, "sudo: no command specified!\n");
        return SSS_SUDO_USAGE_ERROR;
    }

    /* Does command exists? */
    errno = 0;
    qualified_command_path = get_qualified_command_path(argv[0]);
    if (errno) {
        if (qualified_command_path == NULL) {
            plugin.printf(SUDO_CONV_ERROR_MSG,
                          "sudo: %s: %s\n", argv[0], strerror(errno));
        } else {
            plugin.printf(SUDO_CONV_ERROR_MSG,
                          "sudo: %s: %s\n", qualified_command_path, strerror(errno));
        }
        return SSS_SUDO_GENERAL_ERROR;
    }

    /* create query data */
    ret = policy_check_create_query(qualified_command_path, plugin.settings,
                                    plugin.user_info, plugin.user_env,
                                    env_add, argc, argv,
                                    &query, &query_length);
    if (ret != EOK) {
        plugin.printf(SUDO_CONV_ERROR_MSG,
                      "sudo: unable to create query string: %s\n",
                      strerror(ret));
        ret = SSS_SUDO_GENERAL_ERROR;
        goto done;
    }
    request_data.len = query_length;
    request_data.data = (const void*)query;

    /* send query */
    errnop = 0;
    ret = sss_sudo_make_request(SSS_SUDO_CHECK, &request_data, &reply_buf,
                                &reply_len, &errnop);
    if (errnop != 0) {
        plugin.printf(SUDO_CONV_ERROR_MSG,
                      "Unable contact SSSD responder: %s\n", strerror(errnop));
        ret = SSS_SUDO_GENERAL_ERROR;
        goto done;
    }

    /* process response */
    ret = policy_check_parse_response((char*)reply_buf, reply_len, &sudo_result,
                                      command_out, argv_out, user_env_out);
    if (ret != EOK) {
        plugin.printf(SUDO_CONV_ERROR_MSG,
                      "sudo: unable to parse response: %s\n",
                      strerror(ret));
        ret = SSS_SUDO_GENERAL_ERROR;
        goto done;
    }

    plugin.printf(SUDO_CONV_INFO_MSG, "CMD Return code: %d\n", sudo_result);
    plugin.printf(SUDO_CONV_INFO_MSG, "errnop: %d\n", errnop);

    switch (sudo_result) {
    case SSS_SUDO_RESPONSE_ALLOW:
        ret = SSS_SUDO_SUCCESS;
        break;
    case SSS_SUDO_RESPONSE_AUTHENTICATE:
        /* user can run the command, but must authenticate himself first */
        /* TODO */
        ret = SSS_SUDO_FAILURE;
        break;
    case SSS_SUDO_RESPONSE_DENY:
        ret = SSS_SUDO_FAILURE;
        break;
    case SSS_SUDO_RESPONSE_UNKNOWN:
        /* possibly local user, run sudoers plugin */
        /* TODO */
        ret = SSS_SUDO_GENERAL_ERROR;
        plugin.printf(SUDO_CONV_ERROR_MSG, "sudo: Unknown user.\n");
        break;
    }

done:
    free(query);

    return ret;
}

/*
 * Creates query string in format:
 * qualified_command_path\0argv[0]\0argv[i]\0\0
 * env_add\0\0user_env\0\0settings\0\0user_info\0\0
 *
 * where env_add, user_env, settings and user_info are in the form of
 * NAME=VALUE pairs.
 */
errno_t policy_check_create_query(const char *qualified_command_path,
                                  char * const *settings,
                                  char * const *user_info,
                                  char * const *user_env,
                                  char * const *env_add,
                                  int argc,
                                  char * const argv[],
                                  char **query,
                                  int *query_length)
{
#define APPEND_ELEMENT(element) do { \
    iter_length = strlen(element) + 1; /* with ending \0 */ \
    data = (char*)realloc(data, data_length + iter_length); \
    if (data == NULL) { \
        return ENOMEM; \
    } \
    memcpy(data + data_length, element, iter_length); \
    data_length += iter_length; \
} while(0)

#define APPEND_ZERO() do { \
    data_length++; \
    data = (char*)realloc(data, data_length); \
    data[data_length] = '\0'; \
} while(0)

    char *data = NULL;
    int data_length = 0;
    char * const *iter = NULL;
    int iter_length = 0;
    int i = 0;
    char * const *fields[] = { env_add, user_env, settings, user_info, NULL };
    char * const **field = NULL;

    /* append qualified_command_path */

    APPEND_ELEMENT(qualified_command_path);

    /* append argv */

    for (i = 0; i < argc; i++) {
        APPEND_ELEMENT(argv[i]);
    }
    APPEND_ZERO();

    /* append NAME=VALUE fields */
    for (field = fields; *field != NULL; field++) {
        if (**field == NULL) {
            APPEND_ZERO();
            APPEND_ZERO();
        } else {
            for (iter = *field; *iter != NULL; iter++) {
                APPEND_ELEMENT(*iter);
            }
            APPEND_ZERO();
        }
    }

    *query_length = data_length;
    *query = data;

    return EOK;

#undef APPEND_ELEMENT
#undef APPEND_ZERO
}

errno_t policy_check_parse_response(char *response,
                                    int response_length,
                                    int *result,
                                    char ***_command_out,
                                    char ***_argv_out,
                                    char ***_user_env_out)
{
#define LOAD_ARRAY(element) do { \
    i = 0; \
    while (*current_position != '\0') { \
        i++; \
        element = (char**)realloc(element, i * sizeof(char*)); \
        element[i - 1] = current_position; \
        current_position = strchr(current_position, '\0'); \
        if (current_position == NULL) { \
            ret = ESPIPE; \
            goto done; \
        } \
        current_position++; \
    } \
    i++; \
    element = (char**)realloc(element, i * sizeof(char*)); \
    element[i - 1] = NULL; \
    current_position++; \
} while(0)

    char *current_position = NULL;
    char **command_out = NULL;
    char **argv_out = NULL;
    char **user_env_out = NULL;
    int i = 0;
    int ret;

    if (response_length <= 0 || response == NULL) {
        return EINVAL;
    }

    /* get responder result */
    memcpy(result, response, sizeof(int));
    current_position = response + sizeof(int);

    /* get argv_out */
    LOAD_ARRAY(argv_out);

    /* get command_out */
    LOAD_ARRAY(command_out);

    /* get user_env_out */
    LOAD_ARRAY(user_env_out);

    /* copy output */
    *_command_out = command_out;
    *_argv_out = argv_out;
    *_user_env_out = user_env_out;

    ret = EOK;

done:
    return ret;

#undef LOAD_ARRAY
}
