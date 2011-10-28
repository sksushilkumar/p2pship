/*
  p2pship - A peer-to-peer framework for various applications
  Copyright (C) 2007-2010  Helsinki Institute for Information Technology
  
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <pthread.h>

#include "ship_utils.h"
#include "ship_debug.h"
#include "ol_broadcast.h"
#include "ident.h"
#include "netio.h"
#include "processor.h"
#include "conn.h"

/* the list of entries */
static ship_obj_list_t *requests = NULL;

/* the target addr */
static struct sockaddr_in mc_sin;
static ship_list_t *bc_sockets = 0;

/* special strings */
#define OLBC_STR_REQ "req"
#define OLBC_STR_RESP "resp"

#define OLBROADCAST_TO 3000

/* 
   framework things 
*/

/* the name of this module */
static struct olclient_module ol_broadcast_module;

static void
ol_broadcast_get_to(void *data, int code)
{
	/* ol_broadcast_get_t* g = data; */
	olclient_get_task_t *task = data;
	ship_lock(requests);
	if (requests) {
		ship_obj_ref(task);
		ship_obj_list_remove(requests, task);
		ship_unlock(requests);

		if (task->callback) {
			task->callback(NULL, 0, task);
			task->callback = NULL;
		}		
		ship_obj_unref(task);
	}
}

static int
ol_broadcast_send(char *req, struct sockaddr* sa, socklen_t salen)
{
	/* send on all interfaces */
	if (bc_sockets) {
		void *ptr = 0;
		int *s = 0;
		while ((s = ship_list_next(bc_sockets, &ptr))) {
			netio_packet_send((*s), req, strlen(req), sa, salen);
		}
	}
	return 0;
}
	    
/* async function for returning the data currently present in the cache */
/* static int */
/* ol_broadcast_return_cache(void* data, processor_task_t **wait, int wait_for_code) */
/* { */
/* 	ol_broadcast_get_t *g = (ol_broadcast_get_t *)data; */
/* 	ship_list_t *resps = 0; */
/* 	if (resps = ship_list_new()) { */
/* 		olclient_storage_entry_t* e = NULL; */
		
/* 		/\* find the resource(s), submit *\/ */
/* 		LOG_DEBUG("returning async for '%s'\n", g->key); */
/* 		olclient_storage_find_entries(g->key, resps); */
/* 		while (e = ship_list_pop(resps)) { */
/* 			g->callback(e->data, 1, g->lookup, g->mod); */
/* 			e->data = 0; */
/* 			olclient_storage_entry_free(e); */
/* 		} */
/* 		ship_list_free(resps); */
/* 	} */
/* 	return 0; */
/* } */

static int 
ol_broadcast_get(char *key, olclient_get_task_t *task)
{
	char *req = NULL;
	int ret = -1;
	char *k2 = 0;
	ship_list_t *resps = 0;

	ASSERT_TRUE(k2 = ship_hash_sha1_base64(key, strlen(key)), err);
	
	/* create packet */
	ASSERT_TRUE(req = mallocz(strlen(k2) + 10), err);
	strcpy(req, "req:");
	strcat(req, k2);
	strcat(req, "\n");
	
	if ((resps = ship_list_new())) {
		olclient_storage_entry_t* e = NULL;

		olclient_storage_find_entries(k2, resps);
		while ((e = ship_list_pop(resps))) {
			if (task->callback)
				task->callback(e->data, 1, task);
			e->data = 0;
			olclient_storage_entry_free(e);
		}
		ship_list_free(resps);
	}

	LOG_DEBUG("Sending request '%s'\n", req);
	if (ol_broadcast_send(req, (struct sockaddr*)&mc_sin, sizeof(mc_sin)) > -1) {
		ret = 0;
		ship_obj_list_add(requests, task);
		processor_tasks_add_timed(NULL, task, ol_broadcast_get_to, OLBROADCAST_TO);
	}
 err:
	freez(k2);
	freez(req);
	return ret;
}

static int
ol_broadcast_find_gets(char *key, ship_obj_list_t *list)
{
	/* ol_broadcast_get_t* e = NULL; */
	olclient_get_task_t *task = NULL;
	void *ptr = 0;
	int ret = 0;
	char *k2 = 0;

	ship_lock(requests);
	while ((task = ship_list_next(requests, &ptr))) {
		if ((k2 = ship_hash_sha1_base64(task->lookup->key, strlen(task->lookup->key)))) {
			if (!strcmp(k2, key)) {
				ship_obj_list_add(list, task);
				ret++;
			}
			freez(k2);
		}
	}
	ship_unlock(requests);
	
	return ret;
}

static int 
ol_broadcast_remove(char *key, char* secret, struct olclient_module* mod)
{
	char *k2 = 0;
	int ret = -1;

	ASSERT_TRUE(k2 = ship_hash_sha1_base64(key, strlen(key)), err);
	ret = olclient_storage_remove(k2, secret);
 err:
	freez(k2);
	return ret;
}

static int 
ol_broadcast_put(char *key, char *data, int timeout, char *secret, int cached, struct olclient_module* mod)
{
	char *k2 = 0;
	int ret = -1;

	ASSERT_TRUE(k2 = ship_hash_sha1_base64(key, strlen(key)), err);
	/* lets remove first .. */
	olclient_storage_remove(k2, secret);
	ret = olclient_storage_put(k2, data, strlen(data), timeout, secret);
 err:
	freez(k2);
	return ret;
}

static void 
ol_broadcast_packet_cb(int s, char *data, size_t len,
		       struct sockaddr *sa, socklen_t addrlen)
{
	ship_list_t *resps = NULL;
	void *ptr = 0;
	char *pkgdata = NULL;
	char *key = NULL;
	addr_t addr;
	int len2 = len;

	if (data && len2 > 0) {
		LOG_VDEBUG("Got a broadcast packet on socket %d, len %d: '%s'\n",
			   s, len, data);
		pkgdata = strchr(data, '\n');
		key = strchr(data, ':');
	} else {
		if (len < 0)
			netio_close_socket(s);
		return;
	}
	
	ASSERT_ZERO(ident_addr_sa_to_addr(sa, len, &addr), err);
	LOG_VDEBUG("from %s:%d\n", addr.addr, addr.port);
	
	/* find header */
	ASSERT_TRUE(key && pkgdata && (pkgdata > key), err);
	pkgdata[0] = 0; /* now key can be used as a normal string */
	key++; pkgdata++;

	/* message format: 	   
	req:[request key]\n

	resp:[request key]\n
	<data until end of packet>
	*/

	/* parse the message */
	if (!memcmp(data, OLBC_STR_REQ, strlen(OLBC_STR_REQ))) {
		resps = ship_list_new();
		if (resps) {
			olclient_storage_entry_t* e = NULL;
			
			/* find the resource(s), submit */
			LOG_VDEBUG("got request for '%s'\n", key);
			olclient_storage_find_entries(key, resps);
			while ((e = ship_list_pop(resps))) {
				/* create response */
				char *resp = mallocz(e->data_len + strlen(key) + 12);
				if (resp) {
					int strl;
					sprintf(resp, "%s:%s\n", OLBC_STR_RESP, key);
					strl = strlen(resp);
					memcpy(resp + strl, e->data, e->data_len);
					resp[strl + e->data_len] = 0;
					LOG_DEBUG("sending response for key %s\n", key);
					LOG_VDEBUG("the response: '%s'\n", resp);
					netio_packet_send(s, resp, strl+e->data_len, sa, addrlen);
					free(resp);
				}
				olclient_storage_entry_free(e);
			}
		}
	} else if (!memcmp(data, OLBC_STR_RESP, strlen(OLBC_STR_RESP))) {
		/* find the right request, call on callback */
		resps = ship_list_new();
		if (resps) {
			olclient_get_task_t *task;
			
			/* find the resource(s), submit */
			LOG_DEBUG("got response for %s\n", key);
			ship_lock(requests);
			ol_broadcast_find_gets(key, resps);
			ptr = 0;
			while ((task = ship_list_next(resps, &ptr))) {
				char *data = NULL;

				/* call callback! */
				if (task->callback) {
					data = strdup(pkgdata);
					if (data) 
						task->callback(data, 1, task);
				}
			}
			ship_unlock(requests);
			ship_obj_list_clear(resps);
		}
	}
 err:
	ship_list_free(resps);
}


static int
ol_broadcast_init_sockets(processor_config_t *config)
{
	char *host = 0, *portstr, *tmp = 0;
	int port = 0, ret = -1;
	char *bc_addr = 0, *bc2 = 0;
	char **ifs = 0;
	int ifs_c = 0;
	ship_list_t *list = 0;
	addr_t *addr = 0;

	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_BC_ADDR, &bc2), err);
	ASSERT_TRUE(bc_addr = strdup(bc2), err);
	
	if ((portstr = strchr(bc_addr, ':')))
		port = atoi(portstr+1);
	
	if (portstr != bc_addr) {
		if (portstr) 
			portstr[0] = 0;
		host = bc_addr;
	}

	LOG_DEBUG("Using addr %s:%d for broadcast\n", host, port);
	
	/* create sockets on all interfaces */
	ASSERT_TRUE(tmp = processor_config_string(config, P2PSHIP_CONF_BC_IFACES), err);
	ASSERT_ZERO(ship_tokenize_trim(tmp, strlen(tmp), &ifs, &ifs_c, ','), err);
	ASSERT_ZERO(conn_validate_ifaces(ifs, ifs_c), err);
	ASSERT_TRUE(list = ship_list_new(), err);
	conn_getips_af(list, ifs, ifs_c, port, AF_INET);
	
	/* if we should have some interfaces, but dont, then complain! */
	ret = 0;
	while (!ret && (addr = ship_list_pop(list))) {
		struct sockaddr *sa = 0;
		socklen_t salen = 0;
		int *bc_socket = 0;
		
		LOG_DEBUG("\tbroadcast on %s (port %d)\n", addr->addr, addr->port);
		if ((bc_socket = mallocz(sizeof(int))) &&
		    !ident_addr_addr_to_sa(addr, &sa, &salen) &&
		    ((*bc_socket) = netio_new_multicast_reader(host, sa, salen, 
							       ol_broadcast_packet_cb)) != -1) {
			ship_list_add(bc_sockets, bc_socket);
		} else {
			freez(bc_socket);
			ret = -1;
		}
		freez(addr);
		freez(sa);			
	}
	ship_tokens_free(ifs, ifs_c);
	ship_list_empty_free(list);
	ship_list_free(list);

	if (!ret) {
		inet_aton(host, &mc_sin.sin_addr);
		mc_sin.sin_port = htons(port);
	}
 err:
	freez(bc_addr);
	if (ret) {
		LOG_WARN("ol broadcast module socket init failed\n");
	}
	return ret;
}

/* closes the sockets */
static void
ol_broadcast_close_sockets()
{
	if (bc_sockets) {
		int *s = 0;
		while ((s = ship_list_pop(bc_sockets))) {
			netio_close_socket(*s);
			free(s);
		}
	}
}

/* the event interface */
static void
ol_broadcast_events(char *event, void *data, ship_pack_t *eventdata)
{
	/* whatna, re-init the sockets completely */
	LOG_DEBUG("got event %s\n", event);
	ol_broadcast_close_sockets();
	ol_broadcast_init_sockets(processor_get_config());
}


int 
ol_broadcast_init(processor_config_t *config)
{
#ifdef CONFIG_BROADCAST_ENABLED
	int ret = -1;
	
	ASSERT_TRUE(requests = ship_obj_list_new(), err);
	ASSERT_TRUE(bc_sockets = ship_list_new(), err);
	ASSERT_ZERO(ret = ol_broadcast_init_sockets(config), err);
	ASSERT_ZERO(processor_event_receive("net_*", 0, ol_broadcast_events), err);
	ret = olclient_register_module(&ol_broadcast_module /*, ol_broadcast_name_str, NULL */);
 err:
	if (ret) {
		LOG_WARN("ol broadcast module init failed\n");
	}
#endif
	return ret;
}


static void 
ol_broadcast_close(struct olclient_module* mod)
{
	olclient_unregister_module(&ol_broadcast_module /*ol_broadcast_name_str, NULL*/);

	/* close all sockets! */
	ol_broadcast_close_sockets();
	ship_list_free(bc_sockets);
	bc_sockets = 0;
		
	ship_obj_list_free(requests);
	requests = NULL;
	/* if (requests) { */
	/* 	ol_broadcast_get_t *e; */
	/* 	while (e = ship_list_pop(requests)) { */
	/* 		ol_broadcast_get_free(e); */
	/* 	} */
	/* 	ship_list_free(requests); */
	/* 	requests = NULL; */
	/* } */
}

/* the struct, things needed for the interface */
static struct olclient_module ol_broadcast_module = {
		.put = ol_broadcast_put,
		.get = ol_broadcast_get,
		.remove = ol_broadcast_remove,
		.put_signed = 0,
		.get_signed = 0,
		.close = ol_broadcast_close,
		.name = "broadcast",
		.module_data = NULL,
};
