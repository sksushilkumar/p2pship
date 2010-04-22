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
/* opendht_xml_interface.c supports put/get XML RPC interface */
/* NOTE: you must use port 5851 because openDHT accepts XML RPC only on that port */
/* TODO: support for put_removable and rm */

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
#include <linux/socket.h>

#include "ship_utils.h"
#include "ship_debug.h"
#include "libhipopendht.h"
#include "libhipopendhtxml.h"
#include "netio.h"
#include "ident.h"

static char *gw_name = NULL;
static int gw_port = 0;
static ship_list_t *opendht_tasks = NULL;

static struct sockaddr *gw_sa = NULL;
static socklen_t gw_len = 0;

static void (*state_callback) (char *gateway, int port, int status) = NULL;

/* prototypes */
static void opendht_socket_opened(int s, struct sockaddr *sa, socklen_t addrlen);

/* free: only free */
static void
opendht_task_free(opendht_task_t *task)
{
        if (task) {
		ship_list_remove(opendht_tasks, task);

		/* check all sub-tasks, got through on-by-one, close
		   each (=call each's callback) */
		if (task->subs) {
			opendht_task_t *child;
			while (child = ship_list_pop(task->subs)) {
				child->parent = NULL;
				opendht_task_free(child);
			}
			ship_list_free(task->subs);
			task->subs = 0;
		}
				
		freez(task->key);
		freez(task->value);
		freez(task->secret);
		/* close socket if such */
		if (task->socket != -1) {
			netio_close_socket(task->socket);
			task->socket = -1;
		}

		freez(task->read_buf);
		
		/* free from parent? */
		if (!task->parent) {
			free(task);
		}
        }
}

/* close: free & handle callbacks & childs & parents */
static void
opendht_task_close(opendht_task_t *task)
{
        if (task) {
		opendht_task_t *peer;
		void *ptr = 0;

		/* interrupted */
		if (task->status > 0)
			task->status = -1;

		/* call own callback. If we got subtasks, use error
		   from them. */
		if (task->callback) {
			task->callback(task->key, task->value, task->param, task->status);
			task->callback = NULL;
			freez(task->value);
			task->value = NULL;
		}
		
		/* check if parent has any more pending childs. if so,
		   then call the parent's callback */
		
		if (task->parent) {
			/* todo: sync this around the parent! */
			task->closed = 1;
			task->parent->status = 0;
			while (peer = ship_list_next(task->parent->subs, &ptr)) {
				if (peer->status == 1 || !peer->closed) {
					task->parent->status = 1;
					break;
				} else if (peer->status < 0)
					task->parent->status = peer->status;
			}
			
			/* done. call parent close */
			if (task->parent->status < 1) {
				opendht_task_close(task->parent);
			}
		} else {
			opendht_task_free(task);
		}
        }
}

static opendht_task_t *
opendht_task_new(int type, void (*callback) (char *, char *, void * , int ), void *param,
		 char *key, char *value, int value_len, char *secret, int timeout,
		 opendht_task_t *parent)
{
        opendht_task_t *task;
        ASSERT_TRUE(task = (opendht_task_t *)mallocz(sizeof(opendht_task_t)), err);
	task->socket = -1;
        task->type = type;
        task->timeout = timeout;
	task->value_len = value_len;
	task->status = -1;
	task->param = param;
	if (secret) {
		ASSERT_TRUE(task->secret = strdup(secret), err);
	}
        if (key) {
                ASSERT_TRUE(task->key = strdup(key), err);
        }
	
        if (value) {
		ASSERT_TRUE(task->value = mallocz(value_len+1), err);
                memcpy(task->value, value, value_len);
        }

	if (parent) {
		ASSERT_TRUE(parent->subs || (parent->subs = ship_list_new()), err);
		ship_list_add(parent->subs, task);
	}

        task->callback = callback;
	task->parent = parent;
        return task;
 err:
        opendht_task_free(task);
        return NULL;
}

static int
opendht_task_init(int type, void (*callback) (char *, char *, void * , int ), void *param,
		  char *key, char *value, int value_len, char *secret, int timeout,
		  opendht_task_t *parent)
{
	opendht_task_t *task;
	
        if (!gw_sa)
		return -1;
	
        if (!(task = opendht_task_new(type, callback, param, 
				      key, value, value_len, secret, timeout, parent)))
                return -4;
	
	ship_lock(opendht_tasks);
		task->socket = netio_connto(gw_sa, gw_len, opendht_socket_opened);
		if (task->socket != -1) {
			ship_list_add(opendht_tasks, task);
			task->status = 1;
		} else {
			opendht_task_free(task);
			task = NULL;
		}
	ship_unlock(opendht_tasks);
	
	if (task)
		return 0;
	else
		return -1;
}


/**
 * inits & connects to the given gateway
 */
int opendht_init(char *addrstr, void (*callback) (char *gw, int p, int status))
{
	int error = -1;
	addr_t addr;
	
	LOG_INFO("initing opendht to %s\n", addrstr);

	ASSERT_ZERO(ident_addr_str_to_addr_lookup(addrstr, &addr), err);
	srand(time(0));
	state_callback = callback;
           
	ASSERT_ZERO(ident_addr_addr_to_sa(&addr, &gw_sa, &gw_len), err);

	ASSERT_ZERO(ident_addr_str_to_addr(addrstr, &addr), err);
	ASSERT_TRUE(gw_name = strdup(addr.addr), err);    
	ASSERT_TRUE(opendht_tasks = ship_list_new(), err);
	error = 0;
	goto end;
 err:
	opendht_close();
 end:
	return error;
}

/**
 * closes the opendht connection
 */
void
opendht_close()
{
        LOG_INFO("closing opendht\n");

	freez(gw_name);
	freez(gw_sa);
	gw_sa = NULL;

        if (opendht_tasks) {
                while (ship_list_length(opendht_tasks)) {
                        opendht_task_close((opendht_task_t*)ship_list_pop(opendht_tasks));
		}
                ship_list_free(opendht_tasks);
        }
	opendht_tasks = NULL;
}

static opendht_task_t *
opendht_find_by_socket(int s)
{
        opendht_task_t *task = NULL;
	void *ptr = NULL;
	ship_lock(opendht_tasks);
		while (!task && (task = ship_list_next(opendht_tasks, &ptr))) {
			if (task->socket != s)
				task = NULL;
		}
	ship_unlock(opendht_tasks);

	if (!task) {
		LOG_WARN("No opendht task found for socket %d\n", s);
	}
	return task;
}	


static void
opendht_subget_cb(char *key, char *value, void *param, int status)
{
        opendht_task_t *task = (opendht_task_t *)param;
	void *ptr = 0;
	opendht_task_t *child;
	int msg_len = 0;

	if (status == 0) {
		/* construct our message, deliver to the callback! */
		while (child = ship_list_next(task->subs, &ptr))
			msg_len += child->value_len;
		
		task->value = mallocz(msg_len+1);
		task->value_len = msg_len;
		if (task->value) {
			ptr = 0;
			msg_len = 0;
			while (child = ship_list_next(task->subs, &ptr)) {
				memcpy(task->value+msg_len, child->value, child->value_len);
				msg_len += child->value_len;
			}
		}

		if (task->parent && task->parent->callback) {
			task->parent->callback(task->key, task->value, task->parent->param, 1);
			task->value = NULL;
		}
	}
}


static void 
opendht_socket_read(int s, char *data, ssize_t datalen)
{
        opendht_task_t *task = NULL;
	int ret = -1;
	char **resps = NULL;
	int resp_count = 0;
	char *ans = NULL;
	
	/* stray signal? */
	ship_lock(opendht_tasks);
	if (!(task = opendht_find_by_socket(s))) {
		netio_close_socket(s);
		goto err;
	}

	if (task->status != 1)
		goto err;

	/* collect all response data before continuing */
	if (!task->read_buf) {
		task->read_buf_size = 2048; /* initial size */
		ASSERT_TRUE(task->read_buf = (char*)mallocz(task->read_buf_size), err);
	}

	if (data && datalen > 0) {
		if ((task->read_buf_size - task->read_buf_read) < datalen+1) {
			char *tmp;
			ASSERT_TRUE(tmp = (char*)mallocz(task->read_buf_size+datalen), err);
			memcpy(tmp, task->read_buf, task->read_buf_size);
			free(task->read_buf);
			task->read_buf = tmp;
		}
		memcpy(task->read_buf+task->read_buf_read, data, datalen);
		task->read_buf_read += datalen;
	}

	if (datalen > 0) {
		task = NULL;
		goto err;
	} else {
		netio_close_socket(task->socket);
	}
	
	/* Parse answer */
	task->read_buf[task->read_buf_read] = 0;
	resp_count = read_packet_content2(task->read_buf, &resps);
	
	/* handle */
	switch (task->type) {
	case OPENDHT_TASK_SUBSUBGET: {
		/* store data, set status, close (=call callback) */
		LOG_VDEBUG("Got subpart %s (code %d)\n", task->key, resp_count);
		if (resp_count > 0) {
			task->value = resps[resp_count-1]; /* use the last (hopefully newest..) */
			task->value_len = strlen(task->value);
			resps[resp_count-1] = 0;
			task->status = 0;
		} else {
			task->status = -1;
		}
		break;
	}

	case OPENDHT_TASK_GET: {
		int i, j, key_count, val_count;
		opendht_task_t *sub_task = NULL, *subsub_task = NULL;

		/* for each entry, create a new task-tree */
		task->status = -1;
		val_count = 0;
		for (j = 0; j < resp_count; j++) {
			char *val = resps[j];
				
			LOG_VDEBUG("Processing response %d/%d\n", j+1, resp_count);

			/* count the number of keys */
			key_count = 0; i = 0;
			for (i=0; val[i]; i++) if (val[i] == '\n') key_count++;
			if (!key_count)
				continue;
			
			/* create new sub-task (dont init as we don't
			   want a socket for this one) */
			ASSERT_TRUE(sub_task = opendht_task_new(OPENDHT_TASK_SUBGET, opendht_subget_cb, NULL,
								task->key, NULL, 0, NULL, 0, task), subget_err);
			sub_task->param = sub_task; /* hack.. */
			ship_list_add(opendht_tasks, task);
			key_count = 0;
			for (i=0; val[i]; i++) 
				if (val[i] == '\n') {
					val[i] = 0;
					LOG_VDEBUG("Requesting part..%d / %s\n", j+1, &val[key_count]);
					
					/* create new sub-sub tasks */
					ASSERT_ZERO(opendht_task_init(OPENDHT_TASK_SUBSUBGET, 
								      NULL, NULL,
								      &val[key_count], NULL, 0, NULL, 0, sub_task), subget_err);
					key_count = i+1;
				}

			/* yeah, at least one valis subtask */
			task->status = 1;
			sub_task->status = 1;
			val_count++;
			sub_task = 0;
		subget_err:
			if (sub_task)
				opendht_task_close(sub_task);
		}
		
	get_err:
		if (task->status == 1) {
			LOG_DEBUG("Requested %d entries for key '%s'\n", val_count, task->key);
		} else {
			LOG_WARN("Error getting value for key '%s'\n", task->key);
			task->status = -1;
		}		       		
		break;
	}

	case OPENDHT_TASK_PUT_PART:
	case OPENDHT_TASK_RM: {
		/* just close the task if everything was ok */
		ASSERT_ZERO(task->status = read_packet_content(task->read_buf, ans), err);
		break;
	}
	}	

	/* what to do now? just close if we aren't waiting anymore. */
	if (task->status < 1) {
		opendht_task_close(task);
	}
	task = NULL;
 err:
	if (task) {
		task->status = -1;
		opendht_task_close(task);
		task = NULL;
	}

	/* free up the strings we got */
	if (resps) {
		int i = 0;
		while (resps[i]) { freez(resps[i]); i++; }
		free(resps);
	}
	freez(ans);
	ship_unlock(opendht_tasks);
}

/* callback for netio when a socket connection has been established */
static void 
opendht_socket_opened(int s, struct sockaddr *sa, socklen_t addrlen)
{
        opendht_task_t *task = NULL;
	int key_len = 0;
	char packet[2048];
	char tmp_key[21];
	int pkgstatus = -1;
	int remove_task = 0;

	/* stray signal? */
	ship_lock(opendht_tasks);
	ASSERT_TRUE(task = opendht_find_by_socket(s), err);
	if (netio_read(task->socket, opendht_socket_read)) {
		opendht_task_close(task);
		ASSERT_TRUE(0, err);
	}

	/* md5 the key */
	memset(tmp_key, 0, sizeof(tmp_key));
	MD5(task->key, strlen(task->key), tmp_key);
	key_len = 16;
	memset(packet, '\0', sizeof(packet));

	switch (task->type) {
	case OPENDHT_TASK_SUBSUBGET: /* get a part of a key */
	case OPENDHT_TASK_GET: { /* get */
		LOG_VDEBUG("Req for key '%s'\n", task->key);
		pkgstatus = build_packet_get((unsigned char *)tmp_key,
					     key_len,
					     gw_port,
					     (unsigned char *)gw_name,
					     packet);
		
		break;
	}
	case OPENDHT_TASK_PUT_PART: { /* put a single part */
		LOG_VDEBUG("Send %d bytes under key '%s'\n", strlen(task->value), task->key);
		/* .. if we have a secret .. */
		if ((task->secret && 
		     build_packet_put_rm((unsigned char *)tmp_key,
					 key_len,
					 (unsigned char *)task->value,
					 strlen(task->value),
					 (unsigned char *)task->secret,
					 strlen((char *)task->secret),
					 gw_port,
					 (unsigned char *)gw_name,
					 packet, task->timeout) == 0) ||
		    (!task->secret && 
		     build_packet_put((unsigned char *)tmp_key,
				      key_len,
				      (unsigned char *)task->value,
				      strlen(task->value),
				      gw_port,
				      (unsigned char *)gw_name,
				      packet, task->timeout) == 0)) {
			pkgstatus = 0;
		}
		break;
	}
	case OPENDHT_TASK_RM: { /* remove something */
		LOG_DEBUG("Removing key '%s', hash %s, secret '%s'\n", task->key, task->value, task->secret);
		pkgstatus = build_packet_rm((unsigned char *)tmp_key,
					    key_len,
					    (unsigned char *)task->value,
					    (unsigned char *)task->secret,
					    strlen((char *)task->secret),
					    gw_port,
					    (unsigned char *)gw_name,
					    packet, task->timeout);
		break;
	}
	}
	
	/* send the packet if everything went ok */
	task->status = -1;
	if (pkgstatus == 0 && (netio_send(task->socket, packet, strlen(packet)) > 0)) {
		task->status = 1;
	} else {
		remove_task = 1;
		ship_list_remove(opendht_tasks, task);
	}
 err:
	ship_unlock(opendht_tasks);
	if (remove_task) {
		opendht_task_close(task);
	}
}

/* removes something from the DHT. This doesn't actually remove all
 * the parts, but rather only the index entry */
int 
opendht_rm(char *key,
	   char *hash,
	   char *secret)
{
	if (!key || !hash || !secret)
		return -1;
	return opendht_task_init(OPENDHT_TASK_RM, NULL, NULL, key, hash, strlen(hash), secret, 0, NULL);
}

static int 
opendht_put_part(unsigned char * key,
		 unsigned char * value,
		 int value_len,
		 char *secret,
		 int opendht_ttl,
		 opendht_task_t *parent,
		 void (*callback) (char *key, char *value, void *param, int status),
		 void *param)
{
	return opendht_task_init(OPENDHT_TASK_PUT_PART, callback, param, key, value, value_len, secret, opendht_ttl, parent);
}

#define key_rand_len 20
#define rand_chars "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define OPENDHT_LIMIT 1024
#define PACKET_SIZE 1000

int 
opendht_put(unsigned char * key,
            unsigned char * value,
	    char *secret,
            int opendht_ttl,
            void (*callback) (char *key, char *value, void *param, int status),
	    void *param,
	    void (*part_callback) (char *key, char *value, void *param, int status))
{
	int ret = -1;
	char *tmpkey = NULL, *index = NULL;
	int key_len = strlen(key) + key_rand_len +1, pkglen, parts = 0;
        opendht_task_t *task = NULL;
	
	/* new protocol: put the data under n number of x sized blocks
	   with randomly generated keys, and under the real key an index
	   of all of those */

	/* create parent task for this! */
	ship_lock(opendht_tasks);
	ASSERT_TRUE(task = opendht_task_new(OPENDHT_TASK_PUT, callback, param, 
					    key, value, strlen(value), secret, opendht_ttl, NULL),
		    put_err);
	ship_list_add(opendht_tasks, task);
	
	ASSERT_TRUE(tmpkey = (char*)mallocz(key_len + 1), put_err);
	ASSERT_TRUE(index = (char*)mallocz(((strlen(value) / PACKET_SIZE) + 1) * (key_len + 1)), put_err);
	while (pkglen = strlen(value)) {
		if (pkglen > PACKET_SIZE)
			pkglen = PACKET_SIZE;
		
		strcpy(tmpkey, key);
		for (key_len = 0; key_len < key_rand_len; key_len++) {
			tmpkey[strlen(key)+key_len] = rand_chars[rand() % strlen(rand_chars)];
		}
		tmpkey[strlen(key)+key_len] = 0;
					
		strcat(index, tmpkey);
		strcat(index, "\n");

		LOG_VDEBUG("Putting %d bytes under key '%s'\n", pkglen, tmpkey);
		ASSERT_ZERO(ret = opendht_put_part(tmpkey, value, pkglen, secret, opendht_ttl, task,
						   part_callback, param), put_err);
		value += pkglen;
		parts++;
	}
	
	/* put the index also */
	LOG_VDEBUG("Putting index %d bytes under key '%s'\n", strlen(index), key);
	ASSERT_ZERO(ret = opendht_put_part(key, index, strlen(index), secret, opendht_ttl, task,
					   part_callback, param), put_err);
	task->status = 1; /* waiting.. */
	ret = 0;
 put_err:
	freez(tmpkey);
	freez(index);
		
	if (!ret) {
		LOG_DEBUG("Put %d bytes as %d parts under key '%s'\n", 
			  strlen(task->value), parts, task->key);
	} else {
		LOG_WARN("Error putting %d bytes under key '%s'\n", 
			 strlen(task->value), task->key);

		task->status = -1;
		opendht_task_close(task);
	}

	ship_unlock(opendht_tasks);
	return ret;
}

int 
opendht_get(unsigned char * key,
            void (*callback) (char *key, char *value, void* param, int status),
	    void *param)
{
	return opendht_task_init(OPENDHT_TASK_GET, callback, param, key, NULL, 0, NULL, 0, NULL);
}
