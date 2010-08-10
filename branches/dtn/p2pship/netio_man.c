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
#include <stdlib.h>
#include "netio.h"
#include "ship_utils.h"
#include "processor.h"

/* entry structure for the conn management */
typedef struct netio_man_conn_s {

	int socket;
	void *conn_obj;
	void (*data_cb) (int s, void *obj, char *data, int datalen);
	void (*conn_cb) (int s, void *obj);
     
} netio_man_conn_t;

/* the array in which to store the netio managed connections */
static ship_ht_t *netio_man_conns = 0;

/* inits the netio_man funcs */
int
netio_man_init(processor_config_t *config)
{
	if ((netio_man_conns = ship_ht_new()))
		return 0;
	return -1;
}

/* .. and closes */
void
netio_man_close()
{
	netio_man_conn_t *conn = 0;
	ship_lock(netio_man_conns);	

	/* signal close to all! */
	while ((conn = ship_ht_pop(netio_man_conns))) {
		conn->data_cb(conn->socket, conn->conn_obj, NULL, -1);
		free(conn);
	}
	ship_unlock(netio_man_conns);	
	ship_ht_free(netio_man_conns);
	netio_man_conns = NULL;
}

/* removes a managed connection from the netio stack. Returns the data
   object, if one was found! */
void * 
netio_man_close_socket(int socket)
{
	netio_man_conn_t *conn;
	void *ret = NULL;
	ship_lock(netio_man_conns);
	conn = ship_ht_remove_int(netio_man_conns, socket);
	if (conn) {
		ret = conn->conn_obj;
		freez(conn);
	}
	netio_close_socket(socket);
	ship_unlock(netio_man_conns);	
	return ret;
}

static void
netio_man_read_cb(int s, char *data, ssize_t datalen)
{
	netio_man_conn_t *conn = NULL;
	ship_lock(netio_man_conns);
	conn = ship_ht_get_int(netio_man_conns, s);
	if (!conn) {
		netio_close_socket(s);
		ship_unlock(netio_man_conns);
	} else {
		if (datalen < 1) {
			ship_ht_remove_int(netio_man_conns, s);
			netio_remove_read(s);
		}
		ship_unlock(netio_man_conns);
		conn->data_cb(conn->socket, conn->conn_obj, data, datalen);
		if (datalen < 1) {
			freez(conn);
		}
	}
}

static void 
netio_man_connto_cb(int s, struct sockaddr *sa, socklen_t addrlen)
{
	netio_man_conn_t *conn = 0;

	ship_lock(netio_man_conns);
	conn = ship_ht_get_int(netio_man_conns, s);
	if (!conn) {
		netio_close_socket(s);
		ship_unlock(netio_man_conns);
	} else {
		ship_unlock(netio_man_conns);
		conn->conn_cb(conn->socket, conn->conn_obj);
		ship_lock(netio_man_conns);
		if (netio_read(s, netio_man_read_cb)) {
			ship_ht_remove_int(netio_man_conns, s);
			ship_unlock(netio_man_conns);
			conn->data_cb(conn->socket, conn->conn_obj, NULL, -1);
		} else {
			ship_unlock(netio_man_conns);
		}
	}
}

/* connects TCP to & creates a managed connection */
int 
netio_man_connto(struct sockaddr *sa, socklen_t sa_len,
		 void *conn_obj,
		 void (*conn_cb) (int s, void *obj),
		 void (*data_cb) (int s, void *obj, char *data, int datalen))
{
	int ret = -1;
	netio_man_conn_t *conn = mallocz(sizeof(netio_man_conn_t));

	if (!conn)
		return -1;

	conn->data_cb = data_cb;
	conn->conn_cb = conn_cb;
	conn->conn_obj = conn_obj;

	ship_lock(netio_man_conns);
	conn->socket = netio_connto(sa, sa_len, netio_man_connto_cb);
	if (conn->socket != -1) {
		ship_ht_put_int(netio_man_conns, conn->socket, conn);
		ret = conn->socket;
	} else
		freez(conn);
	ship_unlock(netio_man_conns);
	return ret;
}


/* retrieves a managed connection object for the given socket */
void * 
netio_man_get(int socket)
{
	return ship_ht_get_int(netio_man_conns, socket);
}


/* the netio_man register */
static struct processor_module_s processor_module = 
{
	.init = netio_man_init,
	.close = netio_man_close,
	.name = "netio_man",
	.depends = "netio",
};

/* register func */
void
netio_man_register() {
	processor_register(&processor_module);
}
