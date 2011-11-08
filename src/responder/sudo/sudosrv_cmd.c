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

#include <errno.h>
#include <talloc.h>
#include <sudo_plugin.h>

#include "util/util.h"
#include "confdb/confdb.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/sudo/sudosrv.h"
#include "sss_client/sudo_plugin/sss_sudoplugin.h"
#include "sss_client/sss_cli.h"

static int sudo_cmd_check_response(struct cli_ctx *cctx,
                                   int return_code,
                                   int argc,
                                   char **argv,
                                   char *command_info,
                                   int command_info_length,
                                   char **user_env)
{
#define APPEND_ELEMENT(element, length) do { \
    iter_length = length; \
    sss_packet_grow(packet_out, iter_length * sizeof(char)); \
    sss_packet_get_body(packet_out, &body, &blen); \
    memcpy(body + packet_offset, element, iter_length); \
    packet_offset += iter_length; \
} while(0)

#define APPEND_ZERO() do { \
    sss_packet_grow(packet_out, 1 * sizeof(char)); \
    sss_packet_get_body(packet_out, &body, &blen); \
    body[packet_offset] = '\0'; \
    packet_offset++; \
} while(0)

    int i;
    int ret;
    int iter_length;
    uint8_t *body;
    size_t blen;
    size_t packet_offset = 0;
    struct sss_packet *packet_out = NULL;

    ret = sss_packet_new(cctx->creq, 0,
                         sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    packet_out = cctx->creq->out;

    sss_packet_set_error(packet_out, EOK);

    /* fill data */

    /* result */
    ret = sss_packet_grow(packet_out, sizeof(int));
    if (ret != EOK) {
        return ret;
    }
    sss_packet_get_body(packet_out, &body, &blen);
    SAFEALIGN_SET_VALUE(&body[packet_offset], return_code, int, &packet_offset);

    if (return_code == SSS_SUDO_RESPONSE_ALLOW) {
        /* argv */
        for (i = 0; i < argc; i++) {
            APPEND_ELEMENT(argv[i], strlen(argv[i]) + 1);
        }
        APPEND_ZERO();

        /* command_info */
        APPEND_ELEMENT(command_info, command_info_length);
        APPEND_ZERO();

        /* user_env */
        APPEND_ZERO();
        APPEND_ZERO();
    }

    return EOK;

#undef APPEND_ELEMENT
#undef APPEND_ZERO
}

static int sudo_cmd_check_parse_query(TALLOC_CTX *mem_ctx,
                                      char *query,
                                      int query_length,
                                      char **_command_out,
                                      char ***_argv_out,
                                      int *_argc_out)
{
    TALLOC_CTX *tmp_ctx;
    char *current_position = query;
    char **argv_out;
    int argc_out = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed"));
        ret = ENOMEM;
        goto done;
    }

    /* get command */
    *_command_out = current_position;
    current_position = strchr(current_position, '\0');
    if (current_position == NULL) {
        ret = ESPIPE;
        goto done;
    }
    current_position++;

    /* get argv */
    while (*current_position != '\0') {
        argc_out++;
        argv_out = talloc_realloc(tmp_ctx, argv_out, char*, argc_out);
        argv_out[argc_out - 1] = current_position;

        current_position = strchr(current_position, '\0');
        if (current_position == NULL) {
            ret = ESPIPE;
            goto done;
        }
        current_position++;
    }
    current_position++;

    /* TODO get env_add */

    /* TODO get user_env */

    /* TODO get settings */

    /* TODO get user_info */


    *_argc_out = argc_out;
    *_argv_out = talloc_steal(mem_ctx, argv_out);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int sudo_cmd_check_create_command_info(TALLOC_CTX *mem_ctx,
                                                char *command,
                                                char **command_info_out,
                                                int *command_info_length_out)
{
    TALLOC_CTX *tmp_ctx;
    char *command_info;
    int command_info_length = 0;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed"));
        ret = ENOMEM;
        goto done;
    }

    command_info = talloc_asprintf(tmp_ctx, "command=%s", command);
    if (command_info == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_asprintf() failed"));
        ret = ENOMEM;
        goto done;
    }
    command_info_length += strlen(command_info) + 1; /* with \0 */

    /* TODO support other fields */

    *command_info_length_out = command_info_length;
    *command_info_out = talloc_steal(mem_ctx, command_info);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static int sudo_cmd_check(struct cli_ctx *cctx) {
    TALLOC_CTX *mem_ctx;
    uint8_t *body;
    size_t blen;
    char *query = NULL;
    char *command_in = NULL;
    char **argv_in = NULL;
    char *command_info_out = NULL;
    int command_info_out_length = 0;
    int argc_in = 0;
    int ret;
    int sudo_result;

    mem_ctx = talloc_new(NULL);
    if (mem_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed"));
        return ENOMEM;
    }

    /* get query string */
    sss_packet_get_body(cctx->creq->in, &body, &blen);
    if (blen <= 0 || body == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Query string is empty"));
        ret = EINVAL;
        goto done;
    }
    query = (char*)body;

    /* parse query string */
    ret = sudo_cmd_check_parse_query(mem_ctx, query, blen, &command_in,
                                     &argv_in, &argc_in);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Unable to parse query string"));
        goto done;
    }

    /* TODO can user run this command? */

    sudo_result = SSS_SUDO_RESPONSE_ALLOW;

    /* create command info */
    if (sudo_result == SSS_SUDO_RESPONSE_ALLOW) {
        ret = sudo_cmd_check_create_command_info(mem_ctx, command_in,
                                                 &command_info_out,
                                                 &command_info_out_length);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to create command info string"));
            return ENOMEM;
        }
    }

    /* contact DP */
    ret = sudo_dp_refresh_send(cctx, cctx->rctx->domains->name,
                               SSS_CLI_SOCKET_TIMEOUT/2);

    /* send response */
    sudo_cmd_check_response(cctx, sudo_result, argc_in, argv_in,
                            command_info_out, command_info_out_length, NULL);

    ret = EOK;

done:
    sss_cmd_done(cctx, NULL);
    talloc_free(mem_ctx);

    return ret;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version sudo_cli_protocol_version[] = {
        {0, NULL, NULL}
    };

    return sudo_cli_protocol_version;
}

struct sss_cmd_table *get_sudo_cmds(void) {
    static struct sss_cmd_table sudo_cmds[] = {
        {SSS_GET_VERSION, sss_cmd_get_version},
        {SSS_SUDO_CHECK, sudo_cmd_check},
        {SSS_CLI_NULL, NULL}
    };

    return sudo_cmds;
}
