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
#include "libhipopendht.h"
#include "libhipopendhtxml.h"
#include "ol_opendht.h"
#include "ident.h"

/* the name of this module */
static struct olclient_module ol_opendht_module;
static char* ol_opendht_server_str = 0;
static int ol_opendht_check_conn();
/*
typedef struct ol_opendht_get_s {
	void (*callback) (char *val, int status, olclient_lookup_t *lookup, struct olclient_module* mod);
	olclient_lookup_t *lookup;
	struct olclient_module* mod;
} ol_opendht_get_t;
*/

/* entries */
typedef struct ol_opendht_entry_s {

	char *key;
	char *secret;
	char *hash;
} ol_opendht_entry_t;

static ship_list_t *ol_opendht_entries = 0;

static void 
ol_opendht_get_cb(char *key, char *value, void *param, int status)
{
	olclient_get_task_t *task = param;
	task->callback(value, status, task); //->lookup, task->mod);
	if (status != 1)
		ship_obj_unref(task);
}

static int 
ol_opendht_get(char *key, olclient_get_task_t *task)
{
	//ol_opendht_get_t *g = NULL;
	if (!ol_opendht_check_conn())
		return -1;

	/*
	if (g = (ol_opendht_get_t *)mallocz(sizeof(ol_opendht_get_t))) {
		g->callback = callback;
		g->lookup = lookup;
		g->mod = mod;
	*/
	ship_obj_ref(task);
	if (opendht_get((unsigned char*)key, ol_opendht_get_cb, task)) {
		ship_obj_unref(task);
		return -1;
	}
	return 0;
}

static void
ol_opendht_entry_free(ol_opendht_entry_t* entry)
{
	if (entry) {
		freez(entry->key);
		freez(entry->secret);
		freez(entry->hash);
		freez(entry);
	}
}

static ol_opendht_entry_t*
ol_opendht_entry_new(char *key, char *secret)
{
	ol_opendht_entry_t* ret = NULL;
	ASSERT_TRUE(ret = mallocz(sizeof(ol_opendht_entry_t)), err);
	ASSERT_TRUE(ret->key = strdup(key), err);
	ASSERT_TRUE(ret->secret = strdup(secret), err);
	return ret;
 err:
	ol_opendht_entry_free(ret);
	return NULL;
}

static int 
ol_opendht_remove(char *key, char* secret, struct olclient_module* mod)
{	
	ol_opendht_entry_t *e;
	void *ptr = 0, *last = 0;

	if (!ol_opendht_check_conn())
		return -1;

	if (!secret)
		secret = "";

	/* fetch the hash from somewhere, use it! */
	ship_lock(ol_opendht_entries);
	while ((e = ship_list_next(ol_opendht_entries, &ptr))) {
		if (!strcmp(e->key, key) && !strcmp(secret, e->secret)) {
			opendht_rm(key, e->hash, secret);
			ship_list_remove(ol_opendht_entries, e);
			ol_opendht_entry_free(e);
				ptr = last;
		} else {
			last = ptr;
		}
	}
	ship_unlock(ol_opendht_entries);
	return 0;
}

static void 
ol_opendht_put_cb(char *key, char *value, void *param, int status)
{
}

static void 
ol_opendht_put_part_cb(char *key, char *value, void *param, int status)
{
	char value_hash[21];
	ol_opendht_entry_t *e;
	void *ptr = 0;
	
	/* find an entry with the same key-secret & store the hash there (of value) */
	ship_lock(ol_opendht_entries);
	while ((e = ship_list_next(ol_opendht_entries, &ptr))) {
		if (!strcmp(e->key, key) && param == e->secret) {
			freez(e->hash);
			memset(value_hash, '\0', sizeof(value_hash));
			if (!SHA1((unsigned char*)value, strlen(value), (unsigned char *)value_hash)) {
				LOG_ERROR("SHA1 error when creating hash of the value for rm msg\n");
			} else {
				e->hash = (char *)base64_encode((unsigned char *)value_hash, 20);
				LOG_DEBUG("Storing hash %s for key %s / %s\n", e->hash, e->key, e->secret);
			}
		}
	}
	ship_unlock(ol_opendht_entries);
}

static int 
ol_opendht_put(char *key, char *data, int timeout, char *secret, int cached, struct olclient_module* mod)
{
	int ret = -1;
	ol_opendht_entry_t *e;
	
	/* cached we ignore */
	if (cached)
		return 0;

	if (!ol_opendht_check_conn())
		return -1;

	if (!secret)
		secret = "";

	e = ol_opendht_entry_new(key, secret);
	if (!e) return -1;
	
	ship_lock(ol_opendht_entries);
	/* remove any other entries with the same
	   key-secret */
	ol_opendht_remove(key, secret, mod);
	
	/* store the key-secret somewhere, use that secret as
	   the secret here.. */
	ship_list_add(ol_opendht_entries, e);
	ship_unlock(ol_opendht_entries);
	ret = opendht_put((unsigned char *)key, (unsigned char *)data, secret, timeout, ol_opendht_put_cb, e->secret, ol_opendht_put_part_cb);
	return ret;
}

static void 
ol_opendht_statecb(char *gateway, int port, int status)
{
	char *buf;
	buf = mallocz(strlen(gateway) + 20);
	if (buf) {
		sprintf(buf, "%s:%d", gateway, port);
	}
	olclient_cb_state_change(NULL, status, buf);
	free(buf);
}

static int
ol_opendht_check_conn()
{
	if (!ol_opendht_entries) {
		ASSERT_ZERO(opendht_init(ol_opendht_server_str, ol_opendht_statecb), err);
		ASSERT_TRUE(ol_opendht_entries = ship_list_new(), err);
	}
	
	return 1;
 err:
	return 0;
}


int 
ol_opendht_init(processor_config_t *config)
{
	char *od = 0;
	
#ifdef CONFIG_OPENDHT_ENABLED
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_OPENDHT_PROXY, &od), err);
	ASSERT_TRUE(ol_opendht_server_str = strdup(od), err);
	ol_opendht_check_conn();
	return olclient_register_module(&ol_opendht_module /*, ol_opendht_name_str, NULL */);
 err:
#endif
	return -1;
}

void 
static ol_opendht_close(struct olclient_module* mod)
{
	olclient_unregister_module(&ol_opendht_module /*name_str, NULL*/);
	opendht_close();
	
	if (ol_opendht_entries) {
		while (ship_list_first(ol_opendht_entries))
			ol_opendht_entry_free(ship_list_pop(ol_opendht_entries));
	}
	ship_list_free(ol_opendht_entries);
	ol_opendht_entries = NULL;
	freez(ol_opendht_server_str);
}


/* the struct, things needed for the interface */
static struct olclient_module ol_opendht_module = {
		.put = ol_opendht_put,		
		.get = ol_opendht_get,
		.remove = ol_opendht_remove,
		.put_signed = 0,
		.get_signed = 0,
		.close = ol_opendht_close,
		.name = "opendht",
		.module_data = NULL,
};
