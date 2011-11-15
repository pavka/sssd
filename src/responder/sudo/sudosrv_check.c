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

#include <talloc.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/sudo/sudosrv.h"
#include "responder/sudo/sudosrv_private.h"
#include "sss_client/sudo_plugin/sss_sudoplugin.h"

struct sudo_check_output * sudosrv_check(TALLOC_CTX *mem_ctx,
                                         struct cli_ctx *cli_ctx,
                                         struct sudo_check_input *input)
{
    struct sudo_command_info command_info;
    struct sudo_check_output *output = NULL;
    TALLOC_CTX *tmp_ctx;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    output = talloc_zero(tmp_ctx, struct sudo_check_output);
    if (output == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    /*
     * there is no logic yet
     * allow everything
     */

    /* set return code */
    output->return_code = SSS_SUDO_RESPONSE_ALLOW;

    /* build argv */
    ret = sudosrv_copy_string_array(output, input->argc,
                                    input->argv, &(output->argv));
    if (ret != EOK) {
        goto fail;
    }

    /* build command info */
    command_info.command = input->command_name;
    ret = sudosrv_check_build_command_info(output, &command_info,
                                           &(output->command_info));
    if (ret != EOK) {
        goto fail;
    }

    /* build env out */
    ret = sudosrv_copy_string_array(output, input->user_env_count,
                                    input->user_env, &(output->user_env));

    /* contact DP */
    ret = sudo_dp_refresh_send(cli_ctx, cli_ctx->rctx->domains->name,
                               SSS_CLI_SOCKET_TIMEOUT / 2);

    talloc_steal(mem_ctx, output);
    talloc_free(tmp_ctx);

    return output;

fail:
    talloc_free(tmp_ctx);
    errno = ret;

    return NULL;
}

/*
 * This may not be needed in final version.
 */
int sudosrv_copy_string_array(TALLOC_CTX *mem_ctx,
                              int count,
                              char **array,
                              char ***_array_out)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **array_out = NULL;
    int ret = EOK;
    int i = 0;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    array_out = talloc_array(tmp_ctx, char*, count + 1);
    if (array_out == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_array() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    for (i = 0; i < count; i++) {
        array_out[i] = talloc_strdup(array, array[i]);
        if (array_out[i] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf() failed\n"));
            ret = ENOMEM;
            goto done;
        }
    }
    array_out[count] = NULL;

    *_array_out = talloc_steal(mem_ctx, array_out);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * Currently only "command" is supported.
 */
int sudosrv_check_build_command_info(TALLOC_CTX *mem_ctx,
                                     struct sudo_command_info *command_info,
                                     char ***_command_info_array)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **array = NULL;
    int count = 0;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    /* command */
    if (command_info->command != NULL) {
        count++;
        array = talloc_realloc(tmp_ctx, array, char*, count);
        if (array == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
            ret = ENOMEM;
            goto done;
        }
        array[count - 1] = talloc_asprintf(array, "command=%s",
                                           command_info->command);
        if (array[count - 1] == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf() failed\n"));
            ret = ENOMEM;
            goto done;
        }
    }

    /* terminate with NULL */
    count++;
    array = talloc_realloc(tmp_ctx, array, char*, count);
    if (array == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
        ret = ENOMEM;
        goto done;
    }
    array[count - 1] = NULL;

    *_command_info_array = talloc_steal(mem_ctx, array);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct sudo_check_input * sudosrv_check_parse_query(TALLOC_CTX *mem_ctx,
                                                    char *query,
                                                    int query_length)
{
    struct sudo_check_input *input = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    int next_pos = 0;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    input = talloc_zero(tmp_ctx, struct sudo_check_input);
    if (input == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero() failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    /* command name */
    ret = sudosrv_query_parse_string(input, query, query_length,
                                     next_pos, &next_pos,
                                     &(input->command_name));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query - command name\n"));
        goto fail;
    }

    /* argv */
    ret = sudosrv_query_parse_array(input, query, query_length,
                                    next_pos, &next_pos,
                                    &(input->argc),
                                    &(input->argv));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query - argv\n"));
        goto fail;
    }

    /* env_add */
    ret = sudosrv_query_parse_array(input, query, query_length,
                                    next_pos, &next_pos,
                                    &(input->env_add_count),
                                    &(input->env_add));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query - env_add \n"));
        goto fail;
    }


    /* user_env */
    ret = sudosrv_query_parse_array(input, query, query_length,
                                    next_pos, &next_pos,
                                    &(input->user_env_count),
                                    &(input->user_env));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query - user_env\n"));
        goto fail;
    }

    /* settings */
    ret = sudosrv_query_parse_array(input, query, query_length,
                                    next_pos, &next_pos,
                                    &(input->settings_count),
                                    &(input->settings));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query - settings\n"));
        goto fail;
    }

    /* user_info */
    ret = sudosrv_query_parse_array(input, query, query_length,
                                    next_pos, &next_pos,
                                    &(input->user_info_count),
                                    &(input->user_info));
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Invalid query - user_info\n"));
        goto fail;
    }

    talloc_steal(mem_ctx, input);
    talloc_free(tmp_ctx);

    return input;

fail:
    talloc_free(tmp_ctx);
    errno = ret;

    return NULL;
}

int sudosrv_check_build_response(TALLOC_CTX *mem_ctx,
                                 struct sudo_check_output *output,
                                 uint8_t **_response_body,
                                 size_t *_response_length)
{
    uint8_t *response_body = NULL;
    size_t response_length = 0;
    TALLOC_CTX *tmp_ctx = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    /* return code */
    ret = sudosrv_response_append_int(tmp_ctx, output->return_code,
                                      &response_body, &response_length);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to build response - return code\n"));
        goto done;
    }

    /* argv */
    ret = sudosrv_response_append_array(tmp_ctx, output->argv,
                                        &response_body, &response_length);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to build response - argv\n"));
        goto done;
    }

    /* command info */
    ret = sudosrv_response_append_array(tmp_ctx, output->command_info,
                                        &response_body, &response_length);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to build response - command_info\n"));
        goto done;
    }

    /* user env */
    ret = sudosrv_response_append_array(tmp_ctx, output->user_env,
                                        &response_body, &response_length);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to build response - user_env\n"));
        goto done;
    }

    *_response_body = talloc_steal(mem_ctx, response_body);
    *_response_length = response_length;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}
