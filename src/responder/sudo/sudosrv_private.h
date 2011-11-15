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

#ifndef SUDOSRV_PRIVATE_H_
#define SUDOSRV_PRIVATE_H_

struct sudo_check_input {
    char *command_name;

    int argc;
    char **argv;

    int env_add_count;
    char **env_add;

    int user_env_count;
    char **user_env;

    int settings_count;
    char **settings;

    int user_info_count;
    char **user_info;
};

struct sudo_check_output {
    int return_code;
    char **argv;
    char **command_info;
    char **user_env;
};

struct sudo_command_info {
    char *command;
};

struct sudo_check_output * sudosrv_check(TALLOC_CTX *mem_ctx,
                                         struct cli_ctx *cli_ctx,
                                         struct sudo_check_input *input);

int sudosrv_copy_string_array(TALLOC_CTX *mem_ctx,
                              int argc,
                              char **argv,
                              char ***_argv_out);

int sudosrv_check_build_command_info(TALLOC_CTX *mem_ctx,
                                     struct sudo_command_info *command_info,
                                     char ***_command_info);

struct sudo_check_input * sudosrv_check_parse_query(TALLOC_CTX *mem_ctx,
                                                    char *query,
                                                    int query_length);

int sudosrv_check_build_response(TALLOC_CTX *mem_ctx,
                                 struct sudo_check_output *output,
                                 uint8_t **_response_body,
                                 size_t *_response_length);

int sudosrv_query_parse_array(TALLOC_CTX *mem_ctx,
                              char *query,
                              int query_length,
                              int start_pos,
                              int *_end_pos,
                              int *_count,
                              char ***_array);

int sudosrv_query_parse_string(TALLOC_CTX *mem_ctx,
                               char *query,
                               int query_length,
                               int start_pos,
                               int *_end_pos,
                               char **_string);

int sudosrv_response_append_array(TALLOC_CTX *mem_ctx,
                                  char **array,
                                  uint8_t **_response,
                                  size_t *_response_length);

int sudosrv_response_append_string(TALLOC_CTX *mem_ctx,
                                   const char *str,
                                   size_t str_length,
                                   uint8_t **_response,
                                   size_t *_response_length);

int sudosrv_response_append_int(TALLOC_CTX *mem_ctx,
                                int number,
                                uint8_t **_response,
                                size_t *_response_length);

#endif /* SUDOSRV_PRIVATE_H_ */
