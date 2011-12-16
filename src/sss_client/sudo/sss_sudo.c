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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sss_client/sss_cli.h"
#include "sss_client/sudo/sss_sudo.h"
#include "sss_client/sudo/sss_sudo_private.h"

static int sss_sudo_create_query(const char *username,
                                 char **_query,
                                 int *_query_len);

static void sss_sudo_free_rules(unsigned int num_rules,
                                struct sss_rule *rules);

static void sss_sudo_free_attrs(unsigned int num_attrs,
                                struct sss_attr *attrs);

int sss_sudo_get_result(const char *username,
                        uint32_t *_error,
                        struct sss_result **_result)
{
    struct sss_result *result = NULL;
    struct sss_cli_req_data request;
    char *query = NULL;
    int query_len = 0;
    uint8_t *reply_buf = NULL;
    size_t reply_len = 0;
    uint32_t responder_error = 0;
    int errnop = 0;
    int ret = 0;

    /* create query */

    ret = sss_sudo_create_query(username, &query, &query_len);
    if (ret != EOK) {
        goto done;
    }

    request.len = query_len;
    request.data = (const void*)query;

    /* send query and recieve response */

    errnop = 0;
    ret = sss_sudo_make_request(SSS_SUDO_GET_SUDORULES, &request,
                                &reply_buf, &reply_len, &errnop);
    if (errnop != EOK) {
        ret = errnop;
        goto done;
    }

    /* parse and print structure */

    ret = sss_sudo_parse_response((const char*)reply_buf, reply_len,
                                  &result, &responder_error);
    if (ret != EOK) {
        goto done;
    }

    *_error = responder_error;
    *_result = result;

    ret = EOK;

done:
    free(query);

    return ret;
}

int sss_sudo_create_query(const char *username, char **_query, int *_query_len)
{
    char *data = NULL;
    int data_len = strlen(username) + 1;

    if (data_len <= 1) {
        return EINVAL;
    }

    data = (char*)malloc(data_len * sizeof(char));
    if (data == NULL) {
        return ENOMEM;
    }

    memcpy(data, username, data_len);

    *_query = data;
    *_query_len = data_len;

    return EOK;
}

int sss_sudo_get_values(struct sss_rule *e,
                        const char *attrname, char ***_values)
{
    struct sss_attr *attr = NULL;
    char **values = NULL;
    int i, j;

    for (i = 0; i < e->num_attrs; i++) {
        attr = e->attrs + i;
        if (strcasecmp(attr->name, attrname) == 0) {
            values = calloc(attr->num_values + 1, sizeof(char*));
            if (values == NULL) {
                return ENOMEM;
            }

            for (j = 0; j < attr->num_values; j++) {
                values[j] = strdup(attr->values[j]);
                if (values[j] == NULL) {
                    return ENOMEM;
                }
            }

            values[attr->num_values] = NULL;
        }
    }

    if (values == 0) {
        return ENOENT;
    }

    *_values = values;

    return EOK;
}

void sss_sudo_free_values(char **values)
{
    char **value = NULL;

    if (values == NULL) {
        return;
    }

    for (value = values; *value != NULL; value++) {
        free(*value);
    }

    free(values);
}

void sss_sudo_free_result(struct sss_result *result)
{
    if (result == NULL) {
        return;
    }

    sss_sudo_free_rules(result->num_rules, result->rules);
    free(result);
}

void sss_sudo_free_rules(unsigned int num_rules, struct sss_rule *rules)
{
    struct sss_rule *rule = NULL;
    int i;

    if (rules == NULL) {
        return;
    }

    for (i = 0; i < num_rules; i++) {
        rule = rules + i;

        if (rule == NULL) {
            continue;
        }

        sss_sudo_free_attrs(rule->num_attrs, rule->attrs);
        rule->attrs = NULL;
    }

    free(rules);
}

void sss_sudo_free_attrs(unsigned int num_attrs, struct sss_attr *attrs)
{
    struct sss_attr *attr = NULL;;
    int i, j;

    if (attrs == NULL) {
        return;
    }

    for (i = 0; i < num_attrs; i++) {
        attr = attrs + i;

        if (attr == NULL) {
            continue;
        }

        free(attr->name);
        attr->name = NULL;

        for (j = 0; j < attr->num_values; j++) {
            free(attr->values[j]);
            attr->values[j] = NULL;
        }

        free(attr->values);
    }

    free(attrs);
}
