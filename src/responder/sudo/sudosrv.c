/*
   SSSD

   SUDO Responder

   Copyright (C)  Arun Scaria <arunscaria91@gmail.com> (2011)

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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <fnmatch.h>
#include <netdb.h>


#include <popt.h>
#include "dhash.h"
#include "util/util.h"
#include "util/dlinklist.h"
#include "db/sysdb.h"
#include "db/sysdb_private.h"
#include "sbus/sbus_client.h"
#include "sbus/sssd_dbus_messages_helpers.h"
#include "responder/common/responder.h"
#include "responder/common/negcache.h"
#include "responder/common/responder_packet.h"

#include "responder/sudo/sudosrv.h"
#include "sss_client/sudo_plugin/sss_sudo_cli.h"
#include "sbus/sbus_client.h"
#include "responder/common/responder_packet.h"
#include "providers/data_provider.h"
#include "monitor/monitor_interfaces.h"

#define FILTER_APPEND_CHECK(filter_in,filter_out, append_str, str_arg)          \
        do {                                                                    \
            filter_out = talloc_asprintf_append(filter_in,append_str, str_arg); \
            if (!filter_out) {                                                  \
                DEBUG(0, ("Failed to build filter\n"));                         \
                ret = ENOMEM;                                                   \
                goto done;                                                      \
            }                                                                   \
        }while(0);



static int sudo_client_destructor(void *ctx)
{
    struct sudo_client *sudocli = talloc_get_type(ctx, struct sudo_client);
    if (sudocli) {
        talloc_zfree(sudocli);
        DEBUG(4, ("Removed Sudo client\n"));
    }
    return 0;
}

char * get_host_name(TALLOC_CTX* mem_ctx){

    struct addrinfo hints, *info;
    int gai_result;

    char *hostname = talloc_size(mem_ctx,1024);
    hostname[1024]='\0';
    gethostname(hostname, 1023);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; /*either IPV4 or IPV6*/
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    if ((gai_result = getaddrinfo(hostname, "http", &hints, &info)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(gai_result));
        exit(1);
    }


    return talloc_strdup(mem_ctx, info->ai_canonname);

}

errno_t prepare_filter( TALLOC_CTX * mem_ctx,
                        const char * username,
                        uid_t user_id,
                        char * host,
                        struct ldb_result *groups_res,
                        char ** filter_out)   {

    int i,ret=EOK;
    char *filter;
    const char * group_name;

    filter = talloc_asprintf(mem_ctx,"&(|("SYSDB_SUDO_USER_ATTR"=%s)",username);
    if (!filter) {
        DEBUG(0, ("Failed to build filter \n"));
        ret = ENOMEM;
        goto done;
    }

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_USER_ATTR"=#%d)",user_id);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_USER_ATTR"=+*)",NULL);

    for(i=0;i< groups_res->count;i++){
        group_name = ldb_msg_find_attr_as_string(groups_res->msgs[i], SYSDB_NAME, NULL);
        if( !group_name){
            DEBUG(0,("Failed to get group name from group search result"));
            ret = ENOENT;
            goto done;
        }
        FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_USER_ATTR"=%%%s)",group_name);
    }
    FILTER_APPEND_CHECK(filter,filter,")(|("SYSDB_SUDO_HOST_ATTR"=+*)",NULL);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_HOST_ATTR"=ALL)",NULL);

    FILTER_APPEND_CHECK(filter,filter,"("SYSDB_SUDO_HOST_ATTR"=%s))",host);


    done:
    *filter_out = filter;
    return ret;

}


int compare_sudo_order(const struct ldb_message **msg1, const struct ldb_message **msg2)
{
    int ret;
    double order_msg1 = ldb_msg_find_attr_as_double(*msg1, SYSDB_SUDO_ORDER_ATTR, 0.0);
    double order_msg2 = ldb_msg_find_attr_as_double(*msg2, SYSDB_SUDO_ORDER_ATTR, 0.0);
    /*
     * No need to consider errors since zero is assumed by default
     *
     **/
    ret = (order_msg1 < order_msg2)?  1: ((order_msg1 == order_msg1) ?  0 :  -1);
    return ret;
}

errno_t eliminate_sudorules_by_sudocmd(TALLOC_CTX * mem_ctx,
                                       struct sss_sudorule_list ** head,
                                       const char * fq_command) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0;
    char * tmpcmd, *space;
    struct sudo_cmd_ctx * sudo_cmnd;

    sudo_cmnd = talloc_zero(mem_ctx,struct sudo_cmd_ctx);
    if(!sudo_cmnd){
        DEBUG(0,("Failed to allocate command structure."));
        return ENOMEM;
    }
    current_node = list_head;
    while(current_node != NULL) {

        DEBUG(0, ("--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double(current_node->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(current_node->data->dn)));

        el = ldb_msg_find_element(current_node->data,
                                  SYSDB_SUDO_COMMAND_ATTR);
        if (!el) {
            DEBUG(0, ("Failed to get sudo commands for sudorule [%s]\n",
                    ldb_dn_get_linearized(current_node->data->dn)));
            tmp_node = current_node->next;
            DLIST_REMOVE(list_head,current_node);
            current_node =  tmp_node;
            continue;
        }
        flag = 0;
        /* check each command with wild cards */
        for (i = 0; i < el->num_values; i++) {
            DEBUG(0, ("sudoCommand: %s\n" ,(const char *) (el->values[i].data)));
            /* Do command elimination here */
            tmpcmd = talloc_asprintf(mem_ctx,
                                     "%s",
                                     (const char *) (el->values[i].data));
            if (!tmpcmd) {
                DEBUG(0, ("Failed to build commands string - dn: %s\n",
                        ldb_dn_get_linearized(current_node->data->dn)));
                return ENOMEM;
            }

            if(strcmp(tmpcmd,"ALL") == 0){
                current_node=current_node->next;
                flag=1;
                break;
            }
            space = strchr(tmpcmd,' ');
            if(space != NULL) {
                *space = '\0';
                sudo_cmnd->arg= (space +1);
            }
            else
                sudo_cmnd->arg= NULL;

            if(tmpcmd[0]=='!') {
                sudo_cmnd->fqcomnd=tmpcmd+1;
            }
            else {
                sudo_cmnd->fqcomnd=tmpcmd;
            }

            if(fnmatch(sudo_cmnd->fqcomnd,fq_command,FNM_PATHNAME) == 0){
                current_node=current_node->next;
                flag=1;
                break;
            }
        }

        if(flag==1) {
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    return EOK;
}


errno_t eliminate_sudorules_by_sudohosts(TALLOC_CTX * mem_ctx,
                                         struct sss_sudorule_list ** head,
                                         const char * host_name,
                                         const char * domain_name) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0;
    char * tmphost;

    current_node = list_head;
    while(current_node != NULL) {

        DEBUG(0, ("\n\n\n\n--sudoOrder: %f\n",
                ldb_msg_find_attr_as_double((struct ldb_message *)current_node->data,
                                            SYSDB_SUDO_ORDER_ATTR,
                                            0.0)));
        DEBUG(0, ("--dn: %s----\n",
                ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));

        el = ldb_msg_find_element((struct ldb_message *)current_node->data,
                                  SYSDB_SUDO_HOST_ATTR);

        if (!el) {
            DEBUG(0, ("Failed to get sudo hosts for sudorule [%s]\n",
                    ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
            current_node = current_node->next;
            continue;
        }
        flag = 0;

        for (i = 0; i < el->num_values; i++) {

            DEBUG(0, ("sudoHost: %s\n" ,(const char *) (el->values[i].data)));
            tmphost = ( char *) (el->values[i].data);
            if(strcmp(tmphost,"ALL")==0){
                current_node=current_node->next;
                flag=1;
                break;
            }
            else if(tmphost[0] == '+'){
                ++tmphost;
                if(innetgr(tmphost,host_name,NULL,domain_name) == 1){
                    current_node=current_node->next;
                    flag=1;
                    break;

                }
            }
            else {
                if(strcmp(tmphost,host_name)==0){
                    current_node=current_node->next;
                    flag=1;
                    break;
                }
            }

        }
        if(flag==1) {
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    return EOK;
}

errno_t eliminate_sudorules_by_sudouser_netgroups(TALLOC_CTX * mem_ctx,
                                                  struct sss_sudorule_list ** head,
                                                  const char * user_name,
                                                  const char * domain_name) {


    struct sss_sudorule_list * list_head = *head , *current_node, *tmp_node;
    struct ldb_message_element *el;
    int flag =0;
    int i=0, valid_user_count = 0;
    char * tmpuser;


    current_node = list_head;
    while(current_node != NULL) {
        el = ldb_msg_find_element((struct ldb_message *)current_node->data,
                                  SYSDB_SUDO_USER_ATTR);

        if (!el) {
            DEBUG(0, ("Failed to get sudo hosts for sudorule [%s]\n",
                    ldb_dn_get_linearized(((struct ldb_message *)current_node->data)->dn)));
            DLIST_REMOVE(list_head,current_node);
            continue;
        }
        flag = 0;

        for (i = 0; i < el->num_values; i++) {

            DEBUG(0, ("sudoUser: %s\n" ,(const char *) (el->values[i].data)));
            tmpuser = ( char *) (el->values[i].data);
            if(tmpuser[0] == '+'){
                tmpuser++;
                if(innetgr(tmpuser,NULL,user_name,domain_name) == 1){
                    flag = 1;
                }
            }
            else{
                valid_user_count++;
                break;
            }
        }

        if(flag == 1 || valid_user_count > 0){
            current_node = current_node -> next;
            continue;
        }
        tmp_node = current_node->next;
        DLIST_REMOVE(list_head,current_node);
        current_node =  tmp_node;
    }
    *head = list_head;
    return EOK;
}


errno_t search_sudo_rules(struct sudo_client *sudocli,
                          struct sysdb_ctx *sysdb,
                          struct sss_domain_info * domain,
                          const char * user_name,
                          uid_t user_id,
                          struct sss_sudo_msg_contents *sudo_msg,
                          struct sss_sudorule_list **sudorule_list) {
    TALLOC_CTX *tmp_mem_ctx;
    const char *attrs[] = { SYSDB_SUDO_CONTAINER_ATTR,
                            SYSDB_SUDO_USER_ATTR,
                            SYSDB_SUDO_HOST_ATTR,
                            SYSDB_SUDO_OPTION_ATTR,
                            SYSDB_SUDO_COMMAND_ATTR,
                            SYSDB_SUDO_RUNAS_USER_ATTR,
                            SYSDB_SUDO_RUNAS_GROUP_ATTR,
                            SYSDB_SUDO_NOT_BEFORE_ATTR,
                            SYSDB_SUDO_NOT_AFTER_ATTR,
                            SYSDB_SUDO_ORDER_ATTR,
                            NULL };
    char *filter = NULL, *host = NULL;
    struct ldb_message **sudo_rules_msgs;
    struct ldb_result *res;
    int ret;
    size_t count;
    int i = 0;
    TALLOC_CTX *listctx;
    struct sss_sudorule_list *list_head =NULL, *tmp_node;

    DEBUG(0,("in Sudo rule elimination\n"));
    tmp_mem_ctx = talloc_new(NULL);
    if (!tmp_mem_ctx) {
        return ENOMEM;
    }

    ret  = sysdb_get_groups_by_user(tmp_mem_ctx,
                                    sysdb,
                                    domain,
                                    user_name,
                                    &res);
    if (ret) {
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    host = get_host_name(tmp_mem_ctx);
    if (!host) {
        DEBUG(0, ("Failed to build hostname \n"));
        return ENOMEM;
    }
    DEBUG(0, ("Host - %s\n",host));

    ret = prepare_filter(tmp_mem_ctx,user_name,user_id,host,res,&filter);
    if (ret!=EOK) {
        DEBUG(0, ("Failed to build filter - %s\n",filter));
        goto done;
    }
    DEBUG(0,("Filter - %s\n",filter));

    ret = sysdb_search_sudo_rules(tmp_mem_ctx,
                                  sysdb,
                                  domain,
                                  filter,
                                  attrs,
                                  &count,
                                  &sudo_rules_msgs);
    if (ret) {
        if (ret == ENOENT) {
            ret = EOK;
        }
        goto done;
    }

    DEBUG(0, ("Found %d sudo rule entries!\n\n", count));

    if (count == 0) {
        ret = EOK;
        goto done;
    }

    qsort(sudo_rules_msgs,count,sizeof(struct ldb_message *), (__compar_fn_t)compare_sudo_order);

    listctx = talloc_new(tmp_mem_ctx);
    if (!listctx) {
        return ENOMEM;
    }

    for(i=0; i < count ; i++) {
        tmp_node =  talloc_zero(listctx,struct sss_sudorule_list);
        tmp_node->data = sudo_rules_msgs[i];
        tmp_node->next = NULL;
        tmp_node->prev = NULL;
        DLIST_ADD_END( list_head, tmp_node, struct sss_sudorule_list *);

    }


    ret = eliminate_sudorules_by_sudocmd(tmp_mem_ctx,
                                         &list_head,
                                         sudo_msg->fq_command);
    if (ret != EOK) {
        DEBUG(0, ("Failed to eliminate sudo rules based on sudo commands\n"));
        ret = EIO;
        goto done;
    }

    ret = unsetenv("_SSS_LOOPS");
    if (ret != EOK) {
        DEBUG(0, ("Failed to unset _SSS_LOOPS, "
                "sudo rule elimination might not work as expected.\n"));
    }

    ret = eliminate_sudorules_by_sudohosts(tmp_mem_ctx,
                                           &list_head,
                                           host,
                                           sysdb->domain->name);
    if (ret != EOK) {
        DEBUG(0, ("Failed to eliminate sudo rules based on sudo Hosts\n"));
        ret = EIO;
        goto done;
    }

    ret = eliminate_sudorules_by_sudouser_netgroups(tmp_mem_ctx,
                                                    &list_head,
                                                    user_name,
                                                    sysdb->domain->name);
    if (ret != EOK) {
        DEBUG(0, ("Failed to eliminate sudo rules based on sudo user net groups\n"));
        ret = EIO;
        goto done;
    }

    setenv("_SSS_LOOPS", "NO", 0);

    done:
    talloc_steal(sudocli,listctx);
    *sudorule_list = list_head;

    talloc_zfree(tmp_mem_ctx);
    return ret;
}

errno_t find_sudorules_for_user_in_db_list(TALLOC_CTX * ctx,
                                           struct sudo_client *sudocli,
                                           struct sss_sudo_msg_contents * sudo_msg) {
    struct sysdb_ctx **sysdblist;
    struct ldb_message *ldb_msg;
    size_t no_ldbs = 0;
    const char *attrs[] = { SYSDB_NAME, SYSDB_UIDNUM, NULL};
    uid_t user_id;
    int i = 0,ret;
    const char * user_name;
    struct sss_sudorule_list * res_sudorule_list;

    sysdblist = sudocli->sudoctx->rctx->db_list->dbs;
    no_ldbs = sudocli->sudoctx->rctx->db_list->num_dbs;


    while(i < no_ldbs) {

        ret = sysdb_search_user_by_uid(ctx,
                                       sysdblist[i],
                                       sysdblist[i]->domain,
                                       sudo_msg->userid,
                                       attrs,
                                       &ldb_msg);
        if (ret != EOK) {
            i++;
            DEBUG(0, ("No User matched\n"));
            if (ret == ENOENT) {
                continue;
            }
            DEBUG(0, ("sysdb_search_user_by_uid Returned something other that ENOENT\n"));
            return ENOMEM;
        }
        break;

    }
    if(ldb_msg == NULL) {
        DEBUG(0, ("NoUserEntryFound Error. Exit with error message.\n"));
        return ENOENT;
    }

    user_name = ldb_msg_find_attr_as_string(ldb_msg, SYSDB_NAME, NULL);
    user_id = ldb_msg_find_attr_as_uint64(ldb_msg, SYSDB_UIDNUM, 0);
    if ( user_name == NULL || user_id == 0){
        DEBUG(0, ("Error in getting user_name and user id. fatal error"));
        return ENOENT;
    }
    ret =  search_sudo_rules(sudocli,
                             sysdblist[i],
                             sysdblist[i]->domain,
                             "tom"/*user_name*/,
                             user_id,
                             sudo_msg,
                             &res_sudorule_list);
    if(ret != EOK){
        DEBUG(0, ("Error in rule"));
    }

    return ret;

}

errno_t sudo_query_parse(TALLOC_CTX *mem_ctx,
                         struct DBusMessage *message,
                         struct sss_sudo_msg_contents **sudo_msg_packet){
    DBusMessageIter msg_iter;
    DBusMessageIter subItem;
    hash_table_t *settings_table;
    hash_table_t *env_table;
    char **ui;
    char **command_array;
    int count = 0;
    struct sss_sudo_msg_contents *contents;

    contents = talloc_zero(mem_ctx,struct sss_sudo_msg_contents);
    if(!contents){
        DEBUG(0,("Failed to allocate sudo msg structure."));
        return SSS_SUDO_RESPONDER_MEMORY_ERR;
    }

    if (!dbus_message_iter_init(message, &msg_iter)) {
        DEBUG(0,( "Message received as empty!\n"));
        return SSS_SUDO_RESPONDER_MESSAGE_ERR;
    }

        if(DBUS_TYPE_STRUCT != dbus_message_iter_get_arg_type(&msg_iter)) {
            DEBUG(0,( "Argument is not struct!\n"));
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }
        else{
            dbus_message_iter_recurse(&msg_iter,&subItem);
        }

            if(DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("UID failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->userid);
                dbus_message_iter_next (&subItem);
            }

            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("CWD failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->cwd);
                dbus_message_iter_next (&subItem);
            }

            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("TTY failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->tty);
                dbus_message_iter_next (&subItem);
            }
            if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                DEBUG(0,("FQ Command failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&subItem, &contents->fq_command);
            }

            DEBUG(0,("-----------Message---------\n"
                    "uid : %d\ncwd : %s\ntty : %s\nFQ Command: %s\n",contents->userid,contents->cwd,contents->tty,contents->fq_command));

            dbus_message_iter_next (&msg_iter);

            if(DBUS_TYPE_UINT32 != dbus_message_iter_get_arg_type(&msg_iter)) {
                DEBUG(0,("array size failed"));
                return SSS_SUDO_RESPONDER_MESSAGE_ERR;
            }
            else {
                dbus_message_iter_get_basic(&msg_iter, &contents->command_count);
                DEBUG(0,("Command array size: %d\n",contents->command_count));
            }
            dbus_message_iter_next (&msg_iter);

        command_array = (char**)malloc(contents->command_count*sizeof(char *));
        DEBUG(0,("command : "));

        if( DBUS_TYPE_ARRAY != dbus_message_iter_get_arg_type(&msg_iter)) {
            DEBUG(0,("Command array failed!\n"));
            return SSS_SUDO_RESPONDER_MESSAGE_ERR;
        }
        else{
            dbus_message_iter_recurse(&msg_iter,&subItem);
        }

            for(ui = command_array,count = contents->command_count; count--; ui++) {
                if(DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&subItem)) {
                    DEBUG(0,("string array content failed"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;

                }
                else {
                    dbus_message_iter_get_basic(&subItem, ui);
                    DEBUG(0,("%s ",*ui));
                    if(!dbus_message_iter_next (&subItem)) {
                        /*"Array ended. */
                        break;
                    }
                }
            }
            DEBUG(0,("\n"));

        contents->command = command_array;
        dbus_message_iter_next(&msg_iter);

                if( dbus_msg_iter_to_dhash(&msg_iter, &settings_table)!= SSS_SBUS_CONV_SUCCESS){
                    DEBUG(0,("settings table corrupted!\n"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;
                }
    contents->settings_table = settings_table;

                dbus_message_iter_next(&msg_iter);

                if( dbus_msg_iter_to_dhash(&msg_iter, &env_table)!= SSS_SBUS_CONV_SUCCESS){
                    DEBUG(0,("environment table corrupted!\n"));
                    return SSS_SUDO_RESPONDER_MESSAGE_ERR;
                }
    contents->env_table = env_table;
    *sudo_msg_packet = contents;

    DEBUG(0, ("-----------Message END---------\n"));
    return SSS_SUDO_RESPONDER_SUCCESS;

}

errno_t format_sudo_result_reply(TALLOC_CTX * mem_ctx,
                                 DBusMessage **reply_msg,
                                 struct sss_sudo_msg_contents *sudo_msg_packet,
                                 const char * result){

    dbus_uint32_t header = SSS_SUDO_RESPONDER_HEADER,command_size;
    DBusMessage *reply;
    DBusMessageIter msg_iter;
    DBusMessageIter subItem;
    char ** command_array;
    dbus_bool_t dbret;

    reply = *reply_msg;

    command_size = sudo_msg_packet->command_count;
    dbret = dbus_message_append_args(reply,
                                     DBUS_TYPE_UINT32, &header,
                                     DBUS_TYPE_STRING,&result,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(0, ("Failed to build sudo dbus reply\n"));
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    dbus_message_iter_init_append(reply, &msg_iter);

        if(!dbus_message_iter_open_container(&msg_iter,
                                             DBUS_TYPE_ARRAY,
                                             "s",
                                             &subItem)) {
            DEBUG(0, ("Out Of Memory!\n"));
            return SSS_SUDO_RESPONDER_REPLY_ERR;
        }

                for(command_array = sudo_msg_packet->command ; command_size-- ; command_array++) {

                    if (!dbus_message_iter_append_basic(&subItem,
                                                        DBUS_TYPE_STRING,
                                                        command_array)) {
                        DEBUG(0, ( "Out Of Memory!\n"));
                        return SSS_SUDO_RESPONDER_REPLY_ERR;
                    }
                }

        if (!dbus_message_iter_close_container(&msg_iter,&subItem)) {
            DEBUG(0, ( "Out Of Memory!\n"));
            return SSS_SUDO_RESPONDER_REPLY_ERR;
        }

    if(dbus_dhash_to_msg_iter(&sudo_msg_packet->env_table,&msg_iter) != SSS_SBUS_CONV_SUCCESS){
        DEBUG(0,("fatal: env message framing failed."));
        return SSS_SUDO_RESPONDER_DHASH_ERR;
    }

    *reply_msg = reply;

    return SSS_SUDO_RESPONDER_SUCCESS;

}

static int sudo_query_validation(DBusMessage *message, struct sbus_connection *conn)
{
    struct sudo_client *sudocli;
    DBusMessage *reply;
    DBusError dbus_error;
    int ret = -1;
    void *data;

    char * result;
    struct sss_sudo_msg_contents * msg;

    TALLOC_CTX * tmpctx;


    data = sbus_conn_get_private_data(conn);
    sudocli = talloc_get_type(data, struct sudo_client);
    if (!sudocli) {
        DEBUG(0, ("Connection holds no valid init data exists \n",
                SSS_SUDO_RESPONDER_CONNECTION_ERR));
        return SSS_SUDO_RESPONDER_CONNECTION_ERR;
    }
    result = talloc_strdup(sudocli,"PASS");

    /* First thing, cancel the timeout */
    DEBUG(4, ("Cancel SUDO client timeout [%p]\n", sudocli->timeout));
    talloc_zfree(sudocli->timeout);

    dbus_error_init(&dbus_error);

    ret = sudo_query_parse(sudocli,
                           message,
                           &msg);
    if(ret != SSS_SUDO_RESPONDER_SUCCESS){
        DEBUG(0,( "message parser for sudo returned &d\n",ret));
        /* TODO: Do the error recovery method */

    }
    DEBUG(0, ("-----------Message successfully Parsed---------\n"));
    talloc_set_destructor(sudocli, sudo_client_destructor);

    tmpctx = talloc_new(NULL);
    if (!tmpctx) {
        return ENOMEM;
    }


    ret = find_sudorules_for_user_in_db_list(tmpctx,sudocli,msg);
    if(ret != EOK ){
        DEBUG(0, ("sysdb_search_user_by_uid() failed - No sudo commands found with given criterion\n"));
    }
    talloc_zfree(tmpctx);

    /*
     * TODO: Evaluate the list of non eliminated sudo rules and make necessary
     * changed in command array and env table with result
     *
     *
     *reply that everything is ok
     */
    reply = dbus_message_new_method_return(message);
    if (!reply) {
        DEBUG(0, ("Dbus Out of memory!\n"));
        return SSS_SUDO_RESPONDER_REPLY_ERR;
    }

    ret = format_sudo_result_reply(sudocli,
                                   &reply,
                                   msg,
                                   result);
    if (ret != SSS_SUDO_RESPONDER_SUCCESS) {
        DEBUG(0, ("Dbus reply failed with error state %d\n",ret));
        /* TODO: Do the error recovery method
         * dbus_message_unref(reply);
         * sbus_disconnect(conn);
         *
         * */
    }



    /* send reply back */
    sbus_conn_send_reply(conn, reply);
    dbus_message_unref(reply);

    sudocli->initialized = true;
    return EOK;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct sudo_client *sudocli;

    DEBUG(2, ("Client timed out  [%p]!\n", te));

    sudocli = talloc_get_type(ptr, struct sudo_client);

    sbus_disconnect(sudocli->conn);
    talloc_zfree(sudocli);
}

static int sudo_client_init(struct sbus_connection *conn, void *data)
{
    struct sudo_ctx *sudoctx;
    struct sudo_client *sudocli;
    struct timeval tv;

    sudoctx = talloc_get_type(data, struct sudo_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    sudocli = talloc_zero(conn, struct sudo_client);
    if (!sudocli) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    sudocli->sudoctx = sudoctx;
    sudocli->conn = conn;
    sudocli->initialized = false;

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    sudocli->timeout = tevent_add_timer(sudoctx->rctx->ev, sudocli, tv, init_timeout, sudocli);
    if (!sudocli->timeout) {
        DEBUG(0,("Out of memory?!\n"));
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(4, ("Set-up Sudo client timeout [%p]\n", sudocli->timeout));

    /* Attach the client context to the connection context, so that it is
     * always available when we need to manage the connection. */
    sbus_conn_set_private_data(conn, sudocli);
    return EOK;
}
static void sudo_dp_reconnect_init(struct sbus_connection *conn, int status, void *pvt)
{
    struct be_conn *be_conn = talloc_get_type(pvt, struct be_conn);
    int ret;

    /* Did we reconnect successfully? */
    if (status == SBUS_RECONNECT_SUCCESS) {
        DEBUG(1, ("Reconnected to the Data Provider.\n"));

        /* Identify ourselves to the data provider */
        ret = dp_common_send_id(be_conn->conn,
                                DATA_PROVIDER_VERSION,
                                "PAM");
        /* all fine */
        if (ret == EOK) return;
    }

    /* Handle failure */
    DEBUG(0, ("Could not reconnect to %s provider.\n",
            be_conn->domain->name));


}

int sudo_server_init(TALLOC_CTX *mem_ctx,
                     struct sudo_ctx *_ctx)
{

    int ret;
    struct sbus_connection *serv;


    DEBUG(1, ("Setting up the sudo server.\n"));



    ret = sbus_new_server(mem_ctx,
                          _ctx->rctx->ev,
                          SSS_SUDO_SERVICE_PIPE,
                          &sudo_monitor_interface,
                          &serv,
                          sudo_client_init,
                          _ctx);
    if (ret != EOK) {
        DEBUG(0, ("Could not set up sudo sbus server.\n"));
        return ret;
    }

    return EOK;

}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version sudo_cli_protocol_version[] = {
                                                                      {0, NULL, NULL}
    };

    return sudo_cli_protocol_version;
}

struct sss_cmd_table *get_sudo_cmds(void)
{
    static struct sss_cmd_table sss_cmds[] = {
                                              {SSS_SUDO_AUTHENTICATE, NULL},
                                              {SSS_SUDO_INVALIDATE, NULL},
                                              {SSS_SUDO_VALIDATE, NULL},
                                              {SSS_SUDO_LIST, NULL},
                                              {SSS_CLI_NULL, NULL}
    };

    return sss_cmds;
}

int sudo_process_init(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct confdb_ctx *cdb)
{
    struct sss_cmd_table *sudo_cmds;
    struct be_conn *iter;
    struct sudo_ctx *ctx;
    int ret, max_retries;
    int id_timeout;


    ctx = talloc_zero(mem_ctx, struct sudo_ctx);
    if (!ctx) {
        DEBUG(0, ("fatal error initializing sudo_ctx\n"));
        return ENOMEM;
    }
    sudo_cmds = get_sudo_cmds();
    ret = sss_process_init(ctx,
                           ev,
                           cdb,
                           sudo_cmds,
                           SSS_SUDO_SOCKET_NAME,
                           SSS_SUDO_PRIV_SOCKET_NAME,
                           CONFDB_SUDO_CONF_ENTRY,
                           SSS_SUDO_SBUS_SERVICE_NAME,
                           SSS_SUDO_SBUS_SERVICE_VERSION,
                           &sudo_monitor_interface,
                           "SUDO", &sudo_dp_interface,
                           &ctx->rctx);
    if (ret != EOK) {
        goto done;
    }


    ctx->rctx->pvt_ctx = ctx;



    ret = confdb_get_int(ctx->rctx->cdb, ctx->rctx, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SERVICE_RECON_RETRIES, 3, &max_retries);
    if (ret != EOK) {
        DEBUG(0, ("Failed to set up automatic reconnection\n"));
        goto done;
    }

    for (iter = ctx->rctx->be_conns; iter; iter = iter->next) {
        sbus_reconnect_init(iter->conn, max_retries,
                            sudo_dp_reconnect_init, iter);
    }

    /* Set up the negative cache */
    ret = confdb_get_int(cdb, ctx, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SUDO_ENTRY_NEG_TIMEOUT, 15,
                         &ctx->neg_timeout);
    if (ret != EOK) goto done;

    /* Set up the PAM identity timeout */
    ret = confdb_get_int(cdb, ctx, CONFDB_SUDO_CONF_ENTRY,
                         CONFDB_SUDO_ID_TIMEOUT, 5,
                         &id_timeout);
    if (ret != EOK) goto done;

    ctx->id_timeout = (size_t)id_timeout;

    ret = sss_ncache_init(ctx, &ctx->ncache);
    if (ret != EOK) {
        DEBUG(0, ("fatal error initializing negative cache\n"));
        goto done;
    }

    ret = sss_ncache_prepopulate(ctx->ncache, cdb, ctx->rctx->names,
                                 ctx->rctx->domains);
    if (ret != EOK) {
        goto done;
    }

    ret = sudo_server_init(mem_ctx, ctx);
    DEBUG(0, ("sudo server returned %d.\n",ret));

    return EOK;
    done:
    if (ret != EOK) {
        talloc_free(ctx);
    }
    return ret;
}

int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    struct main_context *main_ctx;
    int ret;

    struct poptOption long_options[] = {
                                        POPT_AUTOHELP
                                        SSSD_MAIN_OPTS
                                        POPT_TABLEEND
    };

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    poptFreeContext(pc);

    /* set up things like debug, signals, daemonization, etc... */
    debug_log_file = "sssd_sudo";

    ret = server_setup("sssd[sudo]", 0, CONFDB_SUDO_CONF_ENTRY, &main_ctx);
    if (ret != EOK) return 2;

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(2, ("Could not set up to exit when parent process does\n"));
    }

    ret = sudo_process_init(main_ctx,
                            main_ctx->event_ctx,
                            main_ctx->confdb_ctx);
    if (ret != EOK) return 3;

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}

