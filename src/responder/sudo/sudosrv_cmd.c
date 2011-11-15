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
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/sudo/sudosrv.h"
#include "responder/sudo/sudosrv_private.h"

static int sudo_cmd_check(struct cli_ctx *cli_ctx)
{
    struct sudo_check_output *output = NULL;
    struct sudo_check_input *input = NULL;
    struct sss_packet *packet = NULL;
    uint8_t *packet_body = NULL;
    size_t packet_length = 0;
    TALLOC_CTX *mem_ctx = NULL;
    uint8_t *response_body = NULL;
    size_t response_length = 0;
    uint8_t *query_body = NULL;
    size_t query_length = 0;
    int ret = EOK;

    mem_ctx = talloc_new(NULL);
    if (mem_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        return ENOMEM;
    }

    /* get query */
    sss_packet_get_body(cli_ctx->creq->in, &query_body, &query_length);
    if (query_length <= 0 || query_body == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is empty\n"));
        ret = EINVAL;
        goto done;
    }

    /* parse query */
    input = sudosrv_check_parse_query(mem_ctx, (char*)query_body, query_length);
    if (input == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to parse query: %s\n", strerror(ret)));
        goto done;
    }

    /* evaluate sudo rules */
    output = sudosrv_check(mem_ctx, cli_ctx, input);
    if (output == NULL) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to evaluate sudo rules: %s\n", strerror(ret)));
        goto done;
    }

    /* create response message */
    ret = sudosrv_check_build_response(mem_ctx, output,
                                       &response_body, &response_length);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to create response message: %s\n", strerror(ret)));
        goto done;
    }

    /* set response */
    ret = sss_packet_new(cli_ctx->creq, 0,
                         sss_packet_get_cmd(cli_ctx->creq->in),
                         &cli_ctx->creq->out);
    if (ret != EOK) {
        return ret;
    }
    packet = cli_ctx->creq->out;

    sss_packet_set_error(packet, EOK);

    ret = sss_packet_grow(packet, response_length);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              ("Unable to create response: %s\n", strerror(ret)));
        return ret;
    }
    sss_packet_get_body(packet, &packet_body, &packet_length);
    memcpy(packet_body, response_body, response_length);

    ret = EOK;

done:
    sss_cmd_done(cli_ctx, NULL);
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
