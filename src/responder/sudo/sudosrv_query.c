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

#include <string.h>
#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "responder/sudo/sudosrv.h"
#include "responder/sudo/sudosrv_private.h"

/*
 * Reads null-terminated string.
 */
int sudosrv_query_parse_string(TALLOC_CTX *mem_ctx,
                               char *query,
                               int query_length,
                               int start_pos,
                               int *_end_pos,
                               char **_string)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *current_pos = query + start_pos;
    char *string = NULL;
    int ret = EOK;

    if (start_pos > query_length) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is too short\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    if (*current_pos != '\0') {
        string = talloc_strdup(tmp_ctx, current_pos);
        if (string == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
            return ENOMEM;
        }

        current_pos = strchr(current_pos, '\0');
        if (current_pos == NULL) {
            ret = ESPIPE;
            goto done;
        }
    }

    /* go one char past \0 */
    current_pos++;

    *_end_pos = current_pos - query;
    *_string = talloc_steal(mem_ctx, string);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * Reads array in format:
 * value1\0value2\0...\0\0
 */
int sudosrv_query_parse_array(TALLOC_CTX *mem_ctx,
                              char *query,
                              int query_length,
                              int start_pos,
                              int *_end_pos,
                              int *_count,
                              char ***_array)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *current_pos = query + start_pos;
    char **array = NULL;
    int count = 0;
    int ret = EOK;

    if (start_pos > query_length) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Query is too short\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed\n"));
        ret = ENOMEM;
        goto done;
    }

    if (*current_pos != '\0') {
        /* array with at least one element */
        do {
            count++;

            array = talloc_realloc(tmp_ctx, array, char*, count);
            if (array == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
                ret = ENOMEM;
                goto done;
            }

            array[count - 1] = talloc_strdup(array, current_pos);
            if (array[count - 1] == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_strdup() failed\n"));
                return ENOMEM;
            }

            /* find end of this element */
            current_pos = strchr(current_pos, '\0');
            if (current_pos == NULL) {
                ret = ESPIPE;
                goto done;
            }

            /* go to the start of the next element (one char past \0) */
            current_pos++;
        } while (*current_pos != '\0');
    } else {
        /* special case for empty arrays - go one char past \0 */
        current_pos++;
    }

    /* go to the next array */
    current_pos++;

    if (_count != NULL) {
        *_count = count;
    }
    *_array = talloc_steal(mem_ctx, array);
    *_end_pos = current_pos - query;

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/*
 * Appends null-terminated string array.
 */
int sudosrv_response_append_array(TALLOC_CTX *mem_ctx,
                                  char **array,
                                  uint8_t **_response,
                                  size_t *_response_length)
{
    size_t response_length = *_response_length;
    uint8_t *response = *_response;
    TALLOC_CTX *tmp_ctx = NULL;
    char **iter = NULL;
    int ret = EOK;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_new() failed"));
        ret = ENOMEM;
        goto done;
    }

    if (array == NULL || *array == NULL) {
        /* empty array - append two \0 */
        ret = sudosrv_response_append_string(tmp_ctx, "\0\0", 2,
                                             &response, &response_length);
        if (ret != EOK) {
            goto done;
        }
    } else {
        for (iter = array; *iter != NULL; iter++) {
            /* append element with ending \0 */
            ret = sudosrv_response_append_string(tmp_ctx, *iter,
                                                 strlen(*iter) + 1,
                                                 &response, &response_length);
            if (ret != EOK) {
                goto done;
            }
        }

        /* append \0 to mark end of this array */
        ret = sudosrv_response_append_string(tmp_ctx, "\0", 1,
                                             &response, &response_length);
        if (ret != EOK) {
            goto done;
        }
    }

    *_response_length = response_length;
    *_response = talloc_steal(mem_ctx, response);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

int sudosrv_response_append_string(TALLOC_CTX *mem_ctx,
                                   const char *str,
                                   size_t str_length,
                                   uint8_t **_response,
                                   size_t *_response_length)
{
    size_t response_length = *_response_length;
    uint8_t *response = *_response;

    response = talloc_realloc(mem_ctx, response, uint8_t,
                              response_length + (str_length * sizeof(char)));
    if (response == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
        return ENOMEM;
    }
    memcpy(response + response_length, str, str_length);
    response_length += str_length;

    *_response = response;
    *_response_length = response_length;

    return EOK;
}

int sudosrv_response_append_int(TALLOC_CTX *mem_ctx,
                                int number,
                                uint8_t **_response,
                                size_t *_response_length)
{
    size_t response_length = *_response_length;
    uint8_t *response = *_response;

    response = talloc_realloc(mem_ctx, response, uint8_t,
                              response_length + sizeof(int));
    if (response == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_realloc() failed\n"));
        return ENOMEM;
    }
    SAFEALIGN_SET_VALUE(response + response_length,
                        number, int, &response_length);

    *_response = response;
    *_response_length = response_length;

    return EOK;
}
