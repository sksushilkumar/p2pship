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
/**
 * conn.c
 *
 * The peer-to-peer connection-related stuff. This contains the
 * functions and data structures needed to establish and maintian the
 * p2p connections for signalling traffic.
 *
 * @author joakim.koskela@hiit.fi
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <asm/types.h> 
#include <sys/types.h> 
#include <sys/socket.h> 
#include <linux/netlink.h> 
#include <linux/rtnetlink.h>
#include <net/if.h>

#include "hipapi.h"
#include "ship_debug.h"
#include "processor.h"
#include "ident.h"
#include "conn.h"
#include "netio.h"
#include "sipp_mp.h"
#include "trustman.h"
#include "ship_utils.h"


#define ship_lock_conn(conn) { ship_lock(conn); ship_restrict_locks(conn, identities); ship_restrict_locks(conn, conn_all_conn); }

#ifndef NEW_CONNS
static int conn_open_connection_to(char *sip_aor, ident_t *ident, processor_task_t **wait, int flags);
#endif
static int conn_resend_reg_pkg(ident_t *ident);
static void conn_connection_free(conn_connection_t *conn);
static int conn_connection_init(conn_connection_t *conn, void *param);
extern ship_obj_list_t *identities;

SHIP_DEFINE_TYPE(conn_connection);

static ship_obj_list_t *conn_all_conn;
static ship_list_t *conn_lis_sockets = 0;
static ship_list_t *conn_lis_socket_addrs = 0;
static int conn_ship_port_range;
static int original_conn_ship_port;

#ifdef CONFIG_HIP_ENABLED
static int conn_allow_nonhip = 0;
#endif

/* this is the holder for the 'unique' split-part numbers */
//static int splitcounter = 0;

/* the keepalive counter / time */
static int keepalive_sent = 0;
static int conn_keepalive = 0;

static char** conn_ifaces = 0;
static int conn_ifaces_count = 0;
static struct sockaddr* ka_sa = 0;
static socklen_t ka_salen = 0;

/* dtn: unique packet id */
static unsigned char conn_instance_id[32];

/* dtn: ! this should be per to-from ! */
static int packet_count = 0;

static void conn_cb_socket_got(int s, struct sockaddr *sa, socklen_t addrlen, int ss);
static int conn_send_conn(conn_connection_t *conn, char *buf, int len, int type);
static int conn_sendto(char *sip_aor, char *from, char *buf, size_t len, int type);
static void conn_process_data_done(void *rdata, int code);
static int conn_process_data_do(void *data, processor_task_t **wait, int wait_for_code);
static int conn_periodic();
#ifndef NEW_CONNS
static int conn_has_connection_to(char *sip_aor, ident_t *ident, int flags);
static int conn_open_connection_to_do(void *data, processor_task_t **wait, int wait_for_code);
static void conn_open_connection_to_done(void *data, int code);
static void conn_cb_conn_opened(int s, struct sockaddr *sa, socklen_t addrlen);
#endif
static void conn_send_done(void *data, int code);
static int conn_send_do(void *data, processor_task_t **wait, 
			int wait_for_code);


/* timeout which to wait for an ack / nack */
#define PACKET_ACK_TIMEOUT (1*30)

#ifdef NEW_CONNS
static ship_ht_t *conn_transports = 0;

typedef struct conn_transport_handler_s  conn_transport_handler_t;
typedef void (*conn_transport_handler_cb) (int success, conn_packet_t *p, conn_transport_handler_t *conn);

struct conn_transport_handler_s {
	
	char *name;

	/* 'static methods' */
	int (*init) ();
	void (*close) ();

	conn_transport_handler_t* (*new_instance) (ident_t *ident);

	/* 'instance methods' */
	int (*connect) (conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback);
	int (*is_connected) (conn_transport_handler_t *self, const char *sip_aor);
	int (*disconnect) (conn_transport_handler_t *self, const char *sip_aor);
	
	int (*is_fast) (conn_transport_handler_t *self, const char *sip_aor);
	int (*is_slow) (conn_transport_handler_t *self, const char *sip_aor);
	
	/* returns 0 - ok, -1 - error, 1 - not sure, awaiting.. */
	int (*send) (conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback);
	
	/* closes a connection. NULL for all. */
	void (*close_instance) (conn_transport_handler_t *self);

	char* (*get_transport_address) (conn_transport_handler_t *self);
};
#endif


#ifndef NEW_CONNS
static int conn_send_service_package_to(conn_packet_t *p);
#endif
static char *conn_create_pkgid(const char *from, const char *to);
static void conn_packet_free(conn_packet_t *obj);
static int conn_packet_init(conn_packet_t *obj, void *param);
static int conn_packet_process_data(char *payload, int pkglen, conn_connection_t *conn);
static int conn_send_ack(conn_packet_t *p, int code, const char *data, const int data_len);
static conn_packet_t *conn_packet_new_service(const char *to, const char *from,
					      service_type_t service,
					      char *data, int data_len,
					      int flags,
					      void *ptr, conn_packet_callback callback);

SHIP_DEFINE_TYPE(conn_packet);
static ship_obj_ht_t *conn_waiting_packets = 0;

/* @sync none
 * frees & closes the given connection. 
 * should not be called directly, but rather through conn_conn_close!
 * 
 */
static void
conn_connection_free(conn_connection_t *conn)
{
	/* close the connection */
	netio_close_socket(conn->socket);
	conn->socket = -1;
	processor_signal_wait(conn->wait, -1);
	conn->wait = NULL;

	freez(conn->sip_aor);
	freez(conn->local_aor);
	freez(conn->sa);
	if (conn->in_queue) {
		ship_list_empty_with(conn->in_queue, ship_lenbuf_free);
		ship_list_free(conn->in_queue);
		conn->in_queue = NULL;
	}
		
	if (conn->fragments) {
		ship_ht_t *parts = 0;
		while ((parts = ship_ht_pop(conn->fragments))) {
			void **arr;
			while ((arr = ship_ht_pop(parts)))
				freez_arr(arr, 2);
			ship_ht_free(parts);
		}
	}
	ship_ht_free(conn->fragments);
	ship_list_free(conn->processing);
}

/* @sync none
 * creates a new, empty connection struct, state CLOSED, no socket. */
static int
conn_connection_init(conn_connection_t *ret, void *param)
{
        conn_connection_t *c = (conn_connection_t *)param;
	ret->socket = -1;
        ret->state = STATE_CLOSED;
        if (c->sip_aor) {
                ASSERT_TRUE(ret->sip_aor = strdup(c->sip_aor), err);
        }

        if (c->ident) {
                ASSERT_TRUE(ret->local_aor = strdup(c->ident->sip_aor), err);
        }

        ASSERT_TRUE(ret->fragments = ship_list_new(), err);
        ASSERT_TRUE(ret->processing = ship_list_new(), err);
        ASSERT_TRUE(ret->in_queue = ship_list_new(), err);
        if (c->sa) {
                ASSERT_TRUE(ret->sa = (struct sockaddr *)mallocz(c->addrlen), err);
                memcpy(ret->sa, c->sa, c->addrlen);
                ret->addrlen = c->addrlen;
        }
        return 0;
 err:
        return -1;
}

/* @sync ok
 *
 * todo: check that we always have a ref to this when closing!
 * check that we have a lock?
 */
static void
conn_conn_close(conn_connection_t *conn) 
{
        if (conn) {
		conn->state = STATE_CLOSING;
		processor_signal_wait(conn->wait, -1);
		conn->wait = NULL;
		
		ship_unlock(conn);
		ship_obj_list_remove(conn_all_conn, conn);
		ship_lock_conn(conn);
        }        
}


/* @sync ok 
 * finds a certain connection. syncs around the list of
 * conns, if a suitable connection is found, the lock for it is
 * acquired before returning it */
static conn_connection_t *
conn_find_connection_by_aor(char *sip_aor, char *local_aor)
{
        int i;
        conn_connection_t *ret = NULL;

        if (!conn_all_conn)
                return NULL;

        ship_lock(conn_all_conn);
	for (i=0; !ret && i < ship_list_length(conn_all_conn); i++) {
		conn_connection_t *c = (conn_connection_t *)ship_list_get(conn_all_conn, i);
		if (c->sip_aor && !strcmp(sip_aor, c->sip_aor) &&
		    c->local_aor && !strcmp(local_aor, c->local_aor) &&
		    c->state != STATE_CLOSING) {
			ret = c;
			ship_obj_lockref(ret);
			ship_restrict_locks(ret, identities); 
			ship_restrict_locks(ret, conn_all_conn); 
		}
	}
        ship_unlock(conn_all_conn);

        return ret;
}

/* @sync ok
 * finds a conn by the socket */
static conn_connection_t *
conn_find_connection_by_socket(int socket)
{
        int i;
        conn_connection_t *ret = NULL;

        if (!conn_all_conn)
                return NULL;

        ship_lock(conn_all_conn);
	for (i=0; !ret && i < ship_list_length(conn_all_conn); i++) {
		conn_connection_t *c = (conn_connection_t *)ship_list_get(conn_all_conn, i);
		if (c->socket == socket &&
		    c->state != STATE_CLOSING) {
			ret = c;
			ship_obj_lockref(ret);
		}
	}
        ship_unlock(conn_all_conn);

        return ret;
}


#ifdef CONFIG_HIP_ENABLED
/* returns true / false whether the connection uses hip (hit
   endpoints) */
int 
conn_connection_uses_hip(char *remote_aor, char *local_aor)
{
	int ret = 0;
	addr_t addr;
	conn_connection_t *conn = conn_find_connection_by_aor(remote_aor, local_aor);	
	if (conn && conn->sa && !ident_addr_sa_to_addr(conn->sa, conn->addrlen, &addr)) {
		if (hipapi_addr_is_hit(&addr))
			ret = 1;
	}
	ship_obj_unlockref(conn);
	return ret;
}
#endif

/* closes all open server socket listeners */
static void
conn_close_bindings()
{
        /* listener */
        if (conn_lis_sockets) {                
		int *s = 0;
		ship_lock(conn_lis_sockets);
			
		while ((s = ship_list_pop(conn_lis_sockets))) {
			netio_close_socket(*s);
			freez(s);
		}
		ship_list_empty_free(conn_lis_socket_addrs);
		ship_unlock(conn_lis_sockets);
	}
}

/* binds to conn listener to the listening port. this should be
   called when interfaces (HIPD) goes up & down */
static int
conn_rebind()
{
	struct sockaddr *sa = 0;
        socklen_t slen;
	int *s = 0;
	int bind_to_nonhip = 1;
	int ret = -1;
	ship_list_t *ips = 0;
	addr_t *addr = 0;
	int conn_ship_port = original_conn_ship_port;
		
	conn_close_bindings();
	
	if (!conn_lis_sockets)
		return -1;
	
	ASSERT_TRUE(ips = ship_list_new(), err);
#ifdef CONFIG_HIP_ENABLED
	{
		ASSERT_TRUE(addr = mallocz(sizeof(addr_t)), err);
		if (!hipapi_gethit(addr)) {
			ship_list_add(ips, addr);
			addr = 0;
		} else {
			freez(addr);
			if (!conn_allow_nonhip) {
				ASSERT_ZERO(-1, err);
			}
		}
		if (!conn_allow_nonhip) 
			bind_to_nonhip = 0;
	}
#endif
	
	if (bind_to_nonhip) {
		/* we should actually only bind to the ips of
		   conn_ifaces! */
		conn_getips(ips, conn_ifaces, conn_ifaces_count, 0);
	}
	
	/* start loop.. try always first the original port */
	while ((addr = ship_list_pop(ips))) {
		char *str = 0;
		int pos = 0;
		
		conn_ship_port = original_conn_ship_port;
		ASSERT_TRUE(s = mallocz(sizeof(int*)), err);
		
		do {
			addr->port = conn_ship_port;
			ASSERT_ZERO(ident_addr_addr_to_sa(addr, &sa, &slen), err);			
			
			(*s) = netio_new_listener(sa, slen, conn_cb_socket_got);
			if ((*s) == -1) {
				if (pos < conn_ship_port_range) {
					pos++;
					conn_ship_port++;
				} else {
					ASSERT_TRUE(0, err);
				}
			} else {
				ident_addr_sa_to_addr(sa, slen, addr);
				
				ident_addr_addr_to_str(addr, &str);
				LOG_DEBUG("Bound p2pship listener to %s..\n", str);
				freez(str);

				ship_list_add(conn_lis_socket_addrs, addr);
				ship_list_add(conn_lis_sockets, s);
				s = 0;
				addr = 0;
			}

			freez(sa);
			sa = 0;
		} while (s);
	}

	ret = 0;
 err:
	freez(sa);
	freez(s);
	freez(addr);
	if (ret) {
		USER_ERROR("Could not create p2pship listener on port %d\n", conn_ship_port);
	}
	if (ips) {
		ship_list_empty_free(ips);
		ship_list_free(ips);
	}
	
	processor_event_generate("conn_new_listener", NULL, NULL);
        return ret;
}

/* @sync none
 * closes the conn module. closes all conns. 
 */
void
conn_close()
{
        LOG_INFO("closing the conn module..\n");
#ifdef NEW_CONNS
	if (conn_transports) {
		conn_transport_handler_t *h = 0;
		while ((h = ship_ht_pop(conn_transports)))
			h->close();
		ship_ht_free(conn_transports);
	}
#else
	ship_list_t *conns = conn_all_conn;
	conn_all_conn = NULL;
	
        ship_obj_list_free(conns);
	conn_close_bindings();
	ship_list_free(conn_lis_sockets);
	conn_lis_sockets = 0;
	ship_list_free(conn_lis_socket_addrs);
	conn_lis_socket_addrs = 0;
	ship_tokens_free(conn_ifaces, conn_ifaces_count);
	freez(ka_sa);
#endif

	trustman_close();
	ship_obj_ht_free(conn_waiting_packets);
	conn_waiting_packets = NULL;
}

static void
conn_cb_events(char *event, void *data, void *eventdata)
{
	if (str_startswith(event, "net_"))
		conn_rebind();
	else if (str_startswith(event, "ident_"))
		conn_resend_reg_pkg((ident_t *)eventdata);
}

static void
conn_cb_config_update(processor_config_t *config, char *k, char *v)
{
#ifdef CONFIG_HIP_ENABLED	
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_ALLOW_NONHIP,
					      &conn_allow_nonhip), err);
#endif
	ASSERT_ZERO(processor_config_get_int(config, P2PSHIP_CONF_CONN_KEEPALIVE,
					     &conn_keepalive), err);
	return;
 err:
	PANIC("Error getting configuration values");
}

/* @sync none
 * inits the conn module. creates list of conns etc.. */
int
conn_init(processor_config_t *config)
{
	char *inifs;

        LOG_INFO("initing the conn module\n");

	ASSERT_ZERO(ship_get_random(conn_instance_id, sizeof(conn_instance_id)), err);

#ifdef CONFIG_HIP_ENABLED	
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_ALLOW_NONHIP, conn_cb_config_update);
#endif
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_CONN_KEEPALIVE, conn_cb_config_update);
	conn_cb_config_update(config, NULL, NULL);

	/* capture net events so we can rebind to hits as hipd goes up & down */
	ASSERT_ZERO(processor_event_receive("net_*", 0, conn_cb_events), err);
	
	/* capture the ident_status events */
	ASSERT_ZERO(processor_event_receive("ident_*", 0, conn_cb_events), err);

	/* init trust manager */
	ASSERT_ZERO(trustman_init(config), err);

        /* check that ifaces are valid */
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_IFACES, &inifs), err);
	ASSERT_ZERO(ship_tokenize_trim(inifs, strlen(inifs), &conn_ifaces, &conn_ifaces_count, ','), err);
	ASSERT_ZERO(conn_validate_ifaces(conn_ifaces, conn_ifaces_count), err);
	
        ASSERT_TRUE(conn_all_conn = ship_obj_list_new(), err);
        ASSERT_ZERO(processor_config_get_int(config, P2PSHIP_CONF_SHIP_PORT, &original_conn_ship_port), err);
        ASSERT_ZERO(processor_config_get_int(config, P2PSHIP_CONF_SHIP_PORT_RANGE, &conn_ship_port_range), err);

	ASSERT_TRUE(conn_lis_sockets = ship_list_new(), err);
	ASSERT_TRUE(conn_lis_socket_addrs = ship_list_new(), err);
	ASSERT_ZERO(conn_rebind(), err);

	ASSERT_TRUE(conn_waiting_packets = ship_obj_ht_new(), err);

	ASSERT_ZERO(processor_tasks_add_periodic(conn_periodic, 5000), err);

#ifdef NEW_CONNS
	ASSERT_TRUE(conn_transports = ship_ht_new(), err);

	/* init the various transports */
	ASSERT_ZERO(trans_tcp_register(), err);
#endif

        LOG_INFO("Started ship listener\n");
        return 0;
 err:
        conn_close();
        return -1;
}

/* @sync ok
 *  called when data has arrived. */
static void
conn_cb_data_got(int s, char *data, ssize_t datalen)
{
        conn_connection_t *conn = NULL;
        ship_lenbuf_t *tmparr = NULL;

        /* find which peer this was & process data */

	// can it be that the socket hasn't been put into the socket
	// stack yet when this might be called? got a 'between unknowns!!'
        conn = conn_find_connection_by_socket(s);
        if (datalen < 1 || !conn) {
                if (conn) {
			LOG_DEBUG("socket %d from %s => %s closed\n", s, conn->local_aor, conn->sip_aor);
			conn_conn_close(conn);
                } else {
			LOG_DEBUG("socket %d between unknowns closed\n", s);
                        netio_close_socket(s);
                }
        } else if (datalen > 0) {
		/* record.. */
		conn->rec_data += datalen;
		
                /* if data buffered > some_limit, then take the socket
                   from the select list! */
                ASSERT_TRUE(tmparr = ship_lenbuf_create_copy(data, datalen), err);

                ship_list_add(conn->in_queue, tmparr);
                if (ship_list_length(conn->in_queue) > CONN_IN_QUEUE_LIMIT) {
                        netio_set_active(conn->socket, 0);
			LOG_WARN("limiting the rate at which the socket is read\n");
                }
                tmparr = NULL;

		/* leave a ref to conn */
                processor_tasks_add(conn_process_data_do, (void*)conn, 
				    conn_process_data_done);
		ship_unlock(conn);
		conn = NULL;
        }
 err:
	ship_lenbuf_free(tmparr);
        ship_obj_unlockref(conn);
}


static int conn_process_pkg_reg(char *payload, int pkglen, conn_connection_t *conn);
static int conn_process_pkg_target(char *payload, int pkglen, conn_connection_t *conn);
static int conn_process_pkg_mp(char *payload, int pkglen, conn_connection_t *conn);
static int conn_process_pkg_service(char *payload, int pkglen, service_type_t service, conn_connection_t *conn);


/* @sync none
 * callback when data has been processes. does not need to do anything as
 * the actual data is owned by the connection's data stack */
static void
conn_process_data_done(void *rdata, int code)
{
	ship_obj_unref((conn_connection_t *)rdata);
}


/* @sync almost ok
 * processes the data */
static int
conn_process_data_do(void *data, processor_task_t **wait, int wait_for_code)
{
        ship_lenbuf_t *lenbuf = NULL;
        void *ptr = 0;
	int datalen, ret = -1;
        char *buf = 0;
        int type, pkglen = 0;
        conn_connection_t *conn;
	
	conn = (conn_connection_t *)data;
	ship_lock_conn(conn);
	
	conn->ident = NULL;
	ASSERT_TRUE(conn->state != STATE_CLOSING, err);
        do {
		char *payload;
		int got_useful = 1;

		/* we cannot lock an ident while holding a conn
		   (deadlock), but the other way's ok */
		if (!conn->ident) {
			ident_t *ident = 0;
			if (conn->local_aor)
				buf = strdup(conn->local_aor);
			ship_unlock(conn);
			ident = ident_find_by_aor(buf);
			freez(buf);
			ship_lock_conn(conn);
			conn->ident = ident;
		}

		/* update last-seen timestamp */
		time(&conn->last_heard);
		ret = -1;
		
                /* combine buffers to one large */
                datalen = 0;
		ptr = 0;
		while ((lenbuf = ship_list_next(conn->in_queue, &ptr)))
			datalen += lenbuf->len;
		
		if (datalen < (CONN_PKG_LEN_LEN+1)) {
			ret = 0;
			break;
		}

		freez(buf);
		ASSERT_TRUE(buf = mallocz(datalen+1), err);
		datalen = 0;
		while ((lenbuf = ship_list_pop(conn->in_queue))) {
			memcpy(buf+datalen, lenbuf->data, lenbuf->len);
			datalen += lenbuf->len;
			ship_lenbuf_free(lenbuf);
		}
		
		/* read size (16 bit) & type (8b) */
		pkglen = 0;
		ship_unroll(pkglen, buf, CONN_PKG_LEN_LEN);
		type = (uint8_t)buf[CONN_PKG_LEN_LEN];
		LOG_VDEBUG("got a %d bytes (%d available), pkg %d\n", pkglen, datalen, type);		
		ASSERT_TRUE(pkglen > 2 && pkglen <= CONN_MAX_PKG_LEN, err);

		/* store the rest.. or if we don't have enought yet */
		if (pkglen > datalen) {
			ASSERT_TRUE(lenbuf = ship_lenbuf_create_ref(buf, datalen), err);
			buf = NULL;
			ship_list_add(conn->in_queue, lenbuf);
			ret = 0;
			break;
		} else if (pkglen < datalen) {
			ASSERT_TRUE(lenbuf = ship_lenbuf_create_copy(buf+pkglen, datalen-pkglen), err);
			ship_list_add(conn->in_queue, lenbuf);
		}
		
                /* buf - the current packet, pkglen = the packets total len */	
		payload = buf+CONN_PKG_LEN_LEN+1;
		pkglen -= (CONN_PKG_LEN_LEN+1);
		ret = -3;
		LOG_VDEBUG("processing packet type %d\n", type);

		// todo: check here already that we either have an ident or the pkg type is target (+we have no ident)
		switch (type) {
		case PKG_REG:
			ret = conn_process_pkg_reg(payload, pkglen, conn);
			break;
		case PKG_TARGET:
			ret = conn_process_pkg_target(payload, pkglen, conn);
			break;
		case PKG_MP:
			ret = conn_process_pkg_mp(payload, pkglen, conn);
			break;
		case PKG_PING:
			ret = 0;
			got_useful = 0;
			break;
		case PKG_SERVICE:
			ret = conn_packet_process_data(payload, pkglen, conn);
			break;
		default:
			/* ignore */
			LOG_WARN("unknown packet type: %d\n", type);
			got_useful = 0;
			ret = 0;
			break;
                        
			if (ret) {
                                LOG_WARN("processing of message type %d failed (code %d)!\n", type, ret);
                        } else {
				LOG_VDEBUG("processing of message type %d ok!\n", type);
				if (got_useful)
					time(&conn->last_content);
                        }
                }
        } while (!ret);
	
 err:
	freez(buf);

	ship_obj_unlockref(conn->ident);
	conn->ident = NULL;
        if (!ret) {
                netio_set_active(conn->socket, 1);
        } else {
                conn_conn_close(conn);
	}
	ship_unlock(conn); // unreffing is in _done!
        return ret;
}

/* ensure that we are the only one for this aor pair. The conn should be locked
   when entering and will be so when exiting.
   @return -1 when things didn't go well - the connection should be dropped. Otherwise, */
/* todo: why lock beforehand?? */
/* todo: why do we need to test for unique connections? .. because the
   other host might go down, re-create a connection with us which we should use. and ipsec
   doesn't report tcp timeouts etc that well.. ?

   .. if it's just for loopback, well that should be ok anyway, right?

   .. and 'dead' connections will get collected by the GC, right?

   .. would the same be possible just by using always the *latest* connection for an aor pair?
*/
static int
conn_ensure_unique_conn_lock(conn_connection_t *conn)
{
	conn_connection_t *rc = NULL;
	void *ptr = 0, *last = 0;
	int ret = -1;
	
	/* if quitting or a loopback connection */
        if (!conn_all_conn || !strcmp(conn->local_aor, conn->sip_aor))
                return 0;

	/* releasing this lock might mean that *this* connection will
	   not be the active one. someone might close it. */
	ship_obj_unlockref(conn->ident);
	conn->ident = NULL;
	
	ship_unlock(conn);
        ship_lock(conn_all_conn);
	/* ensure that this conn is still valid */
	if (conn->state != STATE_CLOSING) {
		ret = 0;
		while ((rc = ship_list_next(conn_all_conn, &ptr))) {
			if (rc != conn && 
			    rc->sip_aor && !strcmp(conn->sip_aor, rc->sip_aor) &&
			    rc->local_aor && !strcmp(conn->local_aor, rc->local_aor)) {
				ship_obj_lockref(rc);
				conn_conn_close(rc);
				ship_obj_unlockref(rc);
				ptr = last;
			}
			last = ptr;
		}
	}
	ship_lock_conn(conn);
        ship_unlock(conn_all_conn);
	return ret;
}

/* handles incoming pkg_reg's (ident registration packages */
static int
conn_process_pkg_reg(char *payload, int pkglen, conn_connection_t *conn)
{
        reg_package_t *reg = NULL;
        int ret = -3;
	char *tmp_aor = NULL;

	ident_reg_xml_to_struct(&reg, payload);

#ifndef NEW_CONNS
	/* dtn: move this to the hip module.. */
#ifdef CONFIG_HIP_ENABLED
	/* verify that the hit in the reg belongs to the end-point for
	   this connection! */
	if (reg) {
		void *ptr = NULL;
		addr_t *addr;
		addr_t remote;

		/* if we are dealing with hit, ensure that it belongs
		   to the end-point. if not a hit, then allow if
		   config says so .. */
		if (conn->sa->sa_family == AF_INET6) {
			ident_addr_in6_to_addr(&((struct sockaddr_in6*)conn->sa)->sin6_addr, &remote);
			if (hipapi_addr_is_hit(&remote)) {
				while (ret && (addr = (addr_t*)ship_list_next(reg->hit_addr_list, &ptr))) {
					LOG_DEBUG("Is HIT? %s -> %s?\n", addr->addr, remote.addr);
					if (!strcmp(addr->addr, remote.addr))
						ret = 0;
				}
			} else if (conn_allow_nonhip) {
				ret = 0;
			}
		} else if (conn_allow_nonhip) {
			ret = 0;
		}
		
		/* if no match, skip the reg package and connection */
		if (ret) {
			LOG_WARN("HIT from which connection was got doesn't match the remote user\n");
			ident_reg_free(reg);
			reg = NULL;
		}
		ret = -3;
	}
#endif
#endif
        if (reg && (tmp_aor = strdup(reg->sip_aor)) && !ident_import_foreign_reg(reg)) {
                
                if (!conn->sip_aor) {
                        conn->sip_aor = tmp_aor;
			tmp_aor = NULL;
		}
		
                /* allow only updates for the same sip aor on a connection,
                 * and mark connection as connected if we get a reg package where we haven't
                 * before.
                 */
                if (conn->sip_aor && (!tmp_aor || !strcmp(conn->sip_aor, tmp_aor))) {
                        if (conn->local_aor && conn->state != STATE_CONNECTED) {
				/* here we close any existing sockets
				   for the same aor-pair. */                                
				STATS_LOG("conn handshake done\n");
				if (!conn_ensure_unique_conn_lock(conn)) {
                                        conn->state = STATE_CONNECTED;
					processor_signal_wait(conn->wait, 0);
					conn->wait = NULL;
				}
                        }
			ret = 0;
                }
        }
	freez(tmp_aor);
        return ret;
}

static void
conn_event_cb(char *event, void *eventdata)
{
	ship_obj_unref((conn_connection_t*)eventdata);
}

/* handles a target-package */
static int
conn_process_pkg_target(char *payload, int pkglen, conn_connection_t *conn)
{
        int ret = -3;

	/* we *should* have received a reg package before this target
	   one!  here we ensure that this is the only aor conn and that
	   we really have the aor that the target indicates */
        ASSERT_TRUE(conn->state == STATE_INIT, err);
	ASSERT_TRUE(conn->sip_aor && !conn->local_aor, err);
	ASSERT_TRUE(conn->local_aor = strndup(payload, pkglen), err);
	if (!conn_ensure_unique_conn_lock(conn)) {	
		char *reg_str = NULL;
		ident_t *ident = 0;
		
		/* this will ref the ident, which is unref'd when returning */
		ship_unlock(conn);
		ident = ident_find_by_aor(conn->local_aor); // crash twice
		ship_lock_conn(conn);
		ASSERT_TRUE(conn->ident = ident, err);
		ASSERT_TRUE(reg_str = ident_get_regxml(conn->ident), err);
		
		conn_send_conn(conn, (char*)reg_str, strlen(reg_str), PKG_REG);
		conn->state = STATE_CONNECTED;
		ret = 0;
		
		/* ok, we are connected */
		STATS_LOG("incoming conn handshake done\n");
		ship_obj_ref(conn);
		processor_event_generate("conn_got", conn, conn_event_cb);
		freez(reg_str);
	}
err:
        return ret;
}


/* re-sends the registration packet to all conns for the given
   ident */
static int
conn_resend_reg_pkg(ident_t *ident)
{
        conn_connection_t *c = NULL;
	void *ptr = 0;
	char *data = NULL;
	int ret = -1;
	
	LOG_INFO("resending new registration packet on all open connections for %s\n", ident->sip_aor);
	ASSERT_TRUE(data = ident_get_regxml(ident), err);
        if (conn_all_conn) {
		ship_lock(conn_all_conn);
		while ((c = ship_list_next(conn_all_conn, &ptr))) {
			ship_lock_conn(c);
			if (c->local_aor && !strcmp(ident->sip_aor, c->local_aor))
				conn_send_conn(c, (char*)data, strlen(data), PKG_REG);
			ship_unlock(c);
		}
		ship_unlock(conn_all_conn);
	}
	ret = 0;
 err:
	freez(data);
	return ret;
}


/* handles a generic service package. return codes:
 * @return -1 service error, -2 service not found/registered, -3 .. err */
static int
conn_process_pkg_service(char *payload, int pkglen, service_type_t service_type, conn_connection_t *conn)
{
        int ret = -3;

	// todo: this might have to be separated from the conn lock .. (as a processor task, that is .. )
	// -> the s->data_received function to be exact.

	LOG_VDEBUG("Processing service 0x%x packet, %d bytes ..\n", service_type, pkglen);
        if (conn->state == STATE_CONNECTED) {
                if (conn->ident) {
			service_t *s = ident_get_service(conn->ident, service_type);

			/* reject messages that are for idents no longer registered */
			if (!s || (!ident_get_default_service(service_type) &&
				   !ident_registration_is_valid(conn->ident, service_type))) {
				LOG_WARN("Got service %d packet for ident %s that is not valid anymore!\n", 
					 service_type, (conn->ident? conn->ident->sip_aor : "<nil>"));
				s = 0;
				ret = -2;
			} else {
				/* parse the packet, process split packets */
				/*
				if (pkglen >= CONN_SERVICE_NORMAL_HEADER_LEN) {
					int v;
					ship_unroll(v, payload, 1);
					if (v == 0) {
				*/
				if (s->data_received(payload /*+CONN_SERVICE_NORMAL_HEADER_LEN*/, 
						     pkglen /*-CONN_SERVICE_NORMAL_HEADER_LEN*/, 
						     conn->ident, conn->sip_aor, service_type))
					ret = -1;
				else
					ret = 0;

				/*
					} else if (v == 1 && pkglen >= CONN_SERVICE_SPLIT_HEADER_LEN) {
						int id, p, tot;
						ship_ht_t *parts = 0;

						ship_unroll(id, payload+1, 4);
						ship_unroll(p, payload+5, 4);
						ship_unroll(tot, payload+9, 4);

						/ * store into the conn these .. * /
						parts = ship_ht_get_int(conn->fragments, id);
						if (!parts && (parts = ship_ht_new())) {
							ship_ht_put_int(conn->fragments, id, parts);
						}
						
						if (parts) {
							void **arr = 0;
							
							// todo: lenbuf's

							/ * sanity check * / 
							if (p > -1 && p < tot)
								arr = mallocz(sizeof(void*) * 2);
							payload += CONN_SERVICE_SPLIT_HEADER_LEN;
							pkglen -= CONN_SERVICE_SPLIT_HEADER_LEN;
							if (arr) {
								arr[0] = mallocz(sizeof(pkglen));
								arr[1] = mallocz(pkglen);
								if (arr[0] && arr[1]) {
									memcpy(arr[0], &pkglen, sizeof(pkglen));
									memcpy(arr[1], payload, pkglen);

									LOG_VDEBUG("Got part %d / %d for id %d\n", p, tot, id);
									ship_ht_put_int(parts, p, arr);
									arr = 0;
									ret = 0;
								}
							}
							freez_arr(arr, 2);
							
							if (ret) {
								/ * something went wrong, cancel all parts! * /
							} else if (ship_list_length(parts) == tot) {
								/ * combine these parts into one * /
								void *ptr = 0;
								char *totbuf = 0;
								int totlen = 0;
								
								while ((arr = ship_ht_next(parts, &ptr))) {
									totlen += *((int*)arr[0]);
								}
								LOG_VDEBUG("Got all parts: for id %d: %d, total length %d\n", id, tot, totlen);
								
								if ((totbuf = mallocz(totlen + 1))) {
									int i;
									ptr = 0;
									totlen = 0;
									
									/ * go through the parts in order * /
									for (i=0; i < tot; i++) {
										if ((arr = ship_ht_get_int(parts, i))) {
											memcpy(totbuf + totlen, arr[1], *((int*)arr[0]));
											totlen += *((int*)arr[0]);
										}
									}
									ret = s->data_received(totbuf, totlen, 
											       conn->ident, conn->sip_aor, service_type);
									freez(totbuf);
								}
							} else {
								parts = 0;
							}

							if (parts) {
								ship_ht_remove_int(conn->fragments, id);
								while ((arr = ship_ht_pop(parts)))
									freez_arr(arr, 2);
								ship_ht_free(parts);
							}
						}
						}
						} else {
					ret = s->data_received(payload, pkglen, conn->ident, conn->sip_aor, service_type);
				*/
			}
		} else {
                        LOG_ERROR("FAILING as no ident!\n");
                }
        } else {
                LOG_ERROR("FAILING as not connected!\n");
        }
        return ret;
}

/* handles a mp package */
static int
conn_process_pkg_mp(char *payload, int pkglen, conn_connection_t *conn)
{
        int ret = -3;
#ifdef CONFIG_SIP_ENABLED
        
        if (conn->state == STATE_CONNECTED) {
                char *target_addr;
                int target_port;
                char *source_addr;
                int source_port;
                char *data, *callid, *from, *to;
                
		from = strdup(conn->sip_aor);
		to = strdup(conn->local_aor);

/* 		conn_release_processing(conn); */
/* 		conn = NULL; */
                data = payload;

                /* parse the source & target addresses, create pointer to the data */
                callid = data;
                while (*data && data < (payload + pkglen)) data++;

                if (data >= (payload + pkglen-1))
                        return -1;

                data++;
                target_addr = data;
                while (*data && data < (payload + pkglen)) data++;

                if ((data+4) >= (payload + pkglen))
                        return -1;
                
                data++;
                ship_unroll(target_port, data, 4);
                data += 4;
                source_addr = data;
                while (*data && data < (payload + pkglen)) data++;
                if ((data+4) >= (payload + pkglen))
                        return -1;

                data++;
                ship_unroll(source_port, data, 4);
                data += 4;

		if (from && to)
			ret = sipp_mp_route(from, to,
					    source_addr, source_port,
					    target_addr, target_port,
					    callid,
					    data, (pkglen + payload) - data);
                
                /* ignore any error that may have happened while
                   routing the mediaproxy packet-might be that it just
                   closed, and we do not want to loose this connection
                   just because of a stray / late packet! */

		freez(from);
		freez(to);
                ret = 0;
        } 
#endif
        return ret; 
}

/* @sync ok
 * called when a new socket has been got. creates a new conn object */
static void
conn_cb_socket_got(int s, struct sockaddr *sa, socklen_t addrlen, int ss)
{
        conn_connection_t *conn = NULL;
	addr_t addr;

	if (!ident_addr_sa_to_addr(sa, addrlen, &addr)) {
		LOG_INFO("got socket %d from %s:%d\n", s, addr.addr, addr.port);
	}

        /* create an empty one */
        if (conn_all_conn) {
		conn_connection_t c;
		bzero(&c, sizeof(c));
		c.sa = sa;
		c.addrlen = addrlen;
                if ((conn = (conn_connection_t *)ship_obj_new(TYPE_conn_connection, &c))) {
			conn->socket = s;
			conn->state = STATE_INIT;
			time(&conn->last_content);
			ship_obj_list_add(conn_all_conn, conn);
			ship_lock_conn(conn);
			if (netio_read(s, conn_cb_data_got)) {
				LOG_ERROR("could not start receiving data\n");
				conn_conn_close(conn);
			}
			ship_obj_unlockref(conn);
			s = -1;
		}
        } 
	
	if (s != -1)
        	netio_close_socket(s);
}

/*
 * conn packet handling 
 */
static void 
conn_packet_free(conn_packet_t *obj)
{
	if (obj->callback) {
		obj->callback(obj->to, obj->from, obj->service, obj->code, obj->return_data, obj->return_data_len, obj->ptr);
	}
	freez(obj->to);
	ship_obj_unref(obj->ident);
	freez(obj->data);
	freez(obj->pkg_id);
	freez(obj->return_data);
}

static int 
conn_packet_init(conn_packet_t *obj, void *param) 
{
	obj->code = -1;
	/*
 	ASSERT_TRUE(obj->ident = ident_find_by_aor(param), err);
 	ship_unlock(obj->ident);
	return 0;
 err:
 return -1;*/
	return 0;
}

static conn_packet_t *
conn_packet_new_service(const char *to, const char *from,
			service_type_t service,
			char *data, int data_len,
			int flags,
			void *ptr, conn_packet_callback callback)
{
	conn_packet_t *p = NULL;
	
	ASSERT_TRUE(p = (conn_packet_t*)ship_obj_new(TYPE_conn_packet, (void*)from), err);
	ASSERT_TRUE(p->to = strdup(to), err);
	ASSERT_TRUE(p->from = strdup(from), err);
	ASSERT_TRUE(p->pkg_id = conn_create_pkgid(to, from), err);
	p->service = service;
	p->flags = flags;
	if (data) {
		ASSERT_TRUE(p->data = mallocz(data_len), err);
		memcpy(p->data, data, data_len);
		p->data_len = data_len;
	}
	p->type = PKG_SERVICE;
	p->callback = callback;
	p->ptr = ptr;
	
	return p;
 err:
	ship_obj_unref(p);
	return 0;
}

static conn_packet_t *
conn_packet_new_service_received(conn_connection_t *conn,
				 const char *pkg_id,
				 service_type_t service,
				 char *data, int data_len)
{
	conn_packet_t *p = NULL;
	
	ASSERT_TRUE(p = (conn_packet_t*)ship_obj_new(TYPE_conn_packet, conn->local_aor), err);
	ASSERT_TRUE(p->to = strdup(conn->local_aor), err);
	ASSERT_TRUE(p->from = strdup(conn->sip_aor), err);
	ASSERT_TRUE(p->pkg_id = strdup(pkg_id), err);
	p->service = service;
	if (data) {
		ASSERT_TRUE(p->data = mallocz(data_len), err);
		memcpy(p->data, data, data_len);
		p->data_len = data_len;
	}
	p->type = PKG_SERVICE;
	return p;
 err:
	ship_obj_unref(p);
	return 0;
}

static conn_packet_t *
conn_packet_new_ack(conn_packet_t *orig, int code, const char *data, const int data_len)
{
	conn_packet_t *p = NULL;
	
	ASSERT_TRUE(p = (conn_packet_t*)ship_obj_new(TYPE_conn_packet, (void*)orig->to), err);
	ASSERT_TRUE(p->to = strdup(orig->from), err);
	ASSERT_TRUE(p->from = strdup(orig->to), err);
	ASSERT_TRUE(p->pkg_id = strdup(orig->pkg_id), err);
	if (data) {
		ASSERT_TRUE(p->data = mallocz(data_len), err);
		memcpy(p->data, data, data_len);
		p->data_len = data_len;
	}
	p->type = PKG_SERVICE;
	if (code < 0)
		p->is_ack = -1;
	else
		p->is_ack = 1;
	return p;
 err:
	ship_obj_unref(p);
	return 0;
}

/* accepts a data block that is supposedly a data packet serialized */
static int
conn_packet_process_data(char *payload, int pkglen, conn_connection_t *conn)
{
	conn_packet_t *p = 0;
	service_type_t service;
	void *ptr = 0;
	int ret = -1;
	
	ASSERT_TRUE(ptr = memmem(payload, pkglen, "\0", 1), err);
	ptr++;
	pkglen -= ((int)ptr - (int)payload);

	if (str_startswith(payload, "NCK:") || str_startswith(payload, "ACK:")) {
		LOG_DEBUG("got ack/nack: %s\n", payload);

		/* just remove, dont dereffit yet! */
		if ((p = ship_ht_remove_string(conn_waiting_packets, payload+4))) {
			if (pkglen && !p->return_data && (p->return_data = mallocz(pkglen))) {
				memcpy(p->return_data, ptr, pkglen);
				p->return_data_len = pkglen;
			}
			p->code = (str_startswith(payload, "ACK:")? 0: -2);
			ship_obj_unref(p);
			p = 0;
		}
		ret = 0;
	} else if (str_startswith(payload, "PKG:") && (pkglen) >= sizeof(service)) {
		payload += 4;
		
		/* dtn: here, we should introduce the magic of packet
		   fragmentation. re-piece the pieces. stuff like that */
		
		/* specifically: keep an hashtable of the pkgid -> packets.
		   add to the packet the data .. */

		memcpy(&service, ptr, sizeof(service));
		ASSERT_TRUE(p = conn_packet_new_service_received(conn, payload, service,
								 ptr + sizeof(service), pkglen - sizeof(service)), err);
		
		LOG_DEBUG("We got packet id %s\n", p->pkg_id);
		ret = conn_process_pkg_service(p->data, p->data_len,
					       p->service, conn);
		LOG_DEBUG("processed it with %d\n", ret);
		if (ret < 1)
			conn_send_ack(p, ret, "he23o", 6);
	} else {
		LOG_WARN("invalid packet!\n");
	}
 err:
	ship_obj_unref(p);
	return ret;
}

int
conn_packet_serialize(conn_packet_t *p, char **retv, int *len)
{
	char *ret = 0;
	int tot = 0;

	if (!p)
		return -2;

	tot = strlen(p->pkg_id) + 1 + 4;
	*len = p->data_len + tot;
	if (!p->is_ack)
		*len += sizeof(p->service);
	ASSERT_TRUE(ret = mallocz(*len), err);
	
	if (p->is_ack > 0)
		strcpy(ret, "ACK:");
	else if (p->is_ack < 0)
		strcpy(ret, "NCK:");
	else
		strcpy(ret, "PKG:");

	strcat(ret, p->pkg_id);
	if (!p->is_ack) {
		memcpy(ret+tot, &(p->service), sizeof(p->service));
		tot += sizeof(p->service);
	}
	memcpy(ret+tot, p->data, p->data_len);
	*retv = ret;
	return 0;
 err:
	freez(ret);
	return -1;
}

#ifndef NEW_CONNS
/* @sync none
 * sends a message to the given aor

 -4 on memory error

 * returns 0 if ok, < 0 if error */
static int
conn_send_service_package_to(conn_packet_t *p)
{
	int ret = -1, len = 0;
	char *d2 = 0;
	
	LOG_VDEBUG("Sending %d bytes from %s to %s for service %d\n", p->data_len, p->from, p->to, p->service);
	
#ifdef CONFIG_SIP_ENABLED
#ifdef DO_STATS
	if (service == SERVICE_TYPE_SIP) {
		STATS_LOG("sip message from %s to %s\n", p->from, p->to);
		ac_packetfilter_stats_event(p->from, p->to, "sip_sent");
	}
#endif
#endif

	/* packet encoding .. */
	ASSERT_ZERO(conn_packet_serialize(p, &d2, &len), err);
	STATS_LOG("sendto;%s;%s;%d;%d;%d;%d\n",
		  p->to, p->from, p->service, p->data_len, p->data_len+sizeof(p->service), 0);
	ASSERT_ZERO(ret = conn_sendto(p->to, p->from, d2, len, PKG_SERVICE), err);
	
	/* dtn: here we should go through loops of connection
	   handlers, calling each one's 'send' */

	if (p->callback) {
		/* dtn: add this to some sort of waiting list. */
		p->sent = time(NULL);
		ship_obj_ht_put_string(conn_waiting_packets, p->pkg_id, p);
	}
 err:
	return ret;
}

#endif


/* @sync none
 * sends a media-proxy packet */
int
conn_send_mp_to(char *sip_aor, ident_t *ident,
                char *source_addr, int source_port,
                char *target_addr, int target_port,
                char *callid,
                char *buf, size_t len)
{
        char *fullpkg;
        int pos = 0, i = 0, totlen;

        /* this is really slow, should be replaced with some udp-scheme .. */
        totlen = strlen(callid) + 1 +
                strlen(target_addr) + 5 + 
                strlen(source_addr) + 5 + 
                len;
        if (!(fullpkg = (char*)malloc(totlen)))
                return -1;

        pos = 0; 
        i = 0;
        do {
                fullpkg[pos++] = callid[i];
        } while (callid[i++]);

        i = 0;
        do {
                fullpkg[pos++] = target_addr[i];
        } while (target_addr[i++]);
        
        ship_inroll(target_port, (fullpkg+pos), 4);
        pos += 4;

        i = 0;
        do {
                fullpkg[pos++] = source_addr[i];
        } while (source_addr[i++]);
        
        ship_inroll(source_port, (fullpkg+pos), 4);
        pos += 4;

        i = 0;
        while (i < len) {
                fullpkg[pos++] = buf[i++];
        }

        if ((i = conn_sendto(sip_aor, ident->sip_aor, fullpkg, totlen, PKG_MP))) {
		freez(fullpkg);
	}
        return i;
}

/* sends something on a connection. should be sync'd around conn
   before calling this! */
static int
conn_send_conn(conn_connection_t *conn,
               char *buf, int len, int type)
{
#define HEAD_SIZE (CONN_PKG_LEN_LEN+1)

        /* create packet header */
	char *head = 0;
	int ret = -1;
	
	ASSERT_TRUE(head = malloc(len+HEAD_SIZE), err);
        ship_inroll(len+HEAD_SIZE, head, CONN_PKG_LEN_LEN);
        head[CONN_PKG_LEN_LEN] = (uint8_t)(type & 0xff);

	/* combine into one packet! */
	if (len)
		memcpy(head+HEAD_SIZE, buf, len);
        if (netio_send(conn->socket, head, HEAD_SIZE+len) == (HEAD_SIZE+len) ){
		STATS_LOG("sendto_wire;%s;%s;%d;%d;%d;%d\n",
			  conn->sip_aor, conn->local_aor, 0, len, len+HEAD_SIZE, 0);
		conn->sent_data += HEAD_SIZE + len;
		time(&conn->last_sent);
		ret = 0;
        }
 err:
	freez(head);
	return ret;
}

/* @sync ok
 * sends a package to a recipient */
static int
conn_sendto_raw(char *sip_aor, char *local_aor, char *buf, size_t len, int type)
{
        int ret = -1;
        conn_connection_t *conn;        
        
	LOG_DEBUG("sending %d bytes to %s from %s over HIP\n", len, sip_aor, local_aor);
        conn = conn_find_connection_by_aor(sip_aor, local_aor);
        if (conn && conn->state == STATE_CONNECTED) {
                if ((ret = conn_send_conn(conn, buf, len, type))) {
                        conn_conn_close(conn);
                }
        }
	ship_obj_unlockref(conn);
        return ret;
}

/** callback from trustman when parameters have been got */
static int
conn_trustman_cb(char *local_aor, char *target_aor, 
		 char *params, int param_len,
		 void *data)
{
	int ret = -1;
	void **d = data;

	// todo: lenbuf-ize
	
	/* send some trust parameters */
	if (params && param_len) {
		ASSERT_ZERO(ret = conn_send_slow(target_aor, local_aor,
						 SERVICE_TYPE_TRUST,
						 params, param_len,
						 NULL, NULL), err);
		trustman_mark_current_trust_sent(local_aor, target_aor);
	}
	
	/* we might sometimes get just the callback for sending
	   trustparams, without any app-data associated */

	if (data) {
		ret = conn_sendto_raw(target_aor, local_aor, 
				      (char*)d[0], (int)d[1], (int)d[2]);
	}
 err:
	if (data) {
		freez(d[0]);
		freez(data);
	}
	return ret;
}

/* @sync ok
 * sends a package to a recipient. The ownership of the data is taken! */
static int
conn_sendto(char *sip_aor, char *from, char *buf, size_t len, int type)
{
	void **data;

	/* fetch trust parameters */
	data = mallocz(3*sizeof(void*));
	if (data) {
		data[0] = buf;
		data[1] = (void*)len;
		data[2] = (void*)type;
		trustman_check_trustparams(from, sip_aor,
					   conn_trustman_cb, data);
		return 0;
	}
	return -4;
}

/* periodic update of the connection */
static int
conn_periodic()
{
	time_t now;
        conn_connection_t *conn;
	void *ptr = 0, *last = 0;
	conn_packet_t *p;
	
	LOG_VDEBUG("checking connections.. \n");
	if (!conn_all_conn)
		return 0;
	
        ship_lock(conn_all_conn);
	while ((conn = ship_list_next(conn_all_conn, &ptr))) {
		int close = 0;
		int useful, heard, sent;
		
		ship_obj_lockref(conn);
		time(&now);
		useful = now - conn->last_content;
		heard = now - conn->last_heard;
		sent = now - conn->last_sent;
		
		switch (conn->state) {
		case STATE_ERROR:
		case STATE_CLOSED:
			/* already closed, no need to do anything */
			break;
		case STATE_INIT:
			/* init: we have received a socket, but not target. have a
			   timeout for anything useful of xx secs (15?) */
			if (useful > 15)
				close = 1;
			break;
		case STATE_CONNECTED:
			/* check timestamps, check last_heard < 10s ? and last_content < 5*60? */
			if (useful > (5*60) || heard > 20)
				close = 1;
			else if (sent > 10) {
				/* send ping! */
				conn_send_conn(conn, 0, 0, PKG_PING);
			}
			break;
		case STATE_CONNECTING:
			/* check timestamps, last_content < 30s? */
			if (useful > 30)
				close = 1;
			break;
		default:
			close = 1;
			break;
		}
		
		if (close) {
			LOG_WARN("Closing socket as some sort of timeout has expired\n");
			conn_conn_close(conn);
			ptr = last;
		} else {
			last = ptr;
		}
		ship_obj_unlockref(conn);
	}
        ship_unlock(conn_all_conn);

	/* check keepalives */
	if (conn_keepalive > 0) {
		time_t now = time(NULL);
		if ((now - keepalive_sent) >= conn_keepalive) {
			keepalive_sent = now;
			
			/* ignore any errors and use IP addresses - dns might not be available always! */
			if (!ka_sa) {
				//ident_addr_str_to_sa_lookup("ip92.infrahip.net:9876", &ka_sa, &ka_salen);
				ident_addr_str_to_sa("193.167.187.92:9876", &ka_sa, &ka_salen);
			}

			if (ka_sa) {
				/* note: I bet an ARP or something else might be more appropriate */
				LOG_VDEBUG("Sending keepalive (%d)\n", 
					   netio_packet_anon_send("ping", 4, ka_sa, ka_salen));
			}
		}
	}

	/* check if we should update our listeners */
	if (!ship_list_first(conn_lis_sockets))
		conn_rebind();

	/* check for ack-waiting packets that have been here just for too long */
	ship_lock(conn_waiting_packets);
	ptr = 0; last = 0;
	LOG_DEBUG("Checking %d waiting packets ...\n", ship_list_length(conn_waiting_packets));
	while ((p = ship_ht_next(conn_waiting_packets, &ptr))) {
		if ((p->sent + PACKET_ACK_TIMEOUT) < now) {
			LOG_DEBUG("timeout on packet %s ...\n", p->pkg_id);
			ship_ht_remove(conn_waiting_packets, p);
			p->code = -3;
			ship_obj_unref(p);
			ptr = last;
		}
		last = ptr;
	}
	ship_unlock(conn_waiting_packets);
	return 0;
}

#ifndef NEW_CONNS
/* @sync ok
 * check if we have an established & working connection to the given
 * peer. */
static int
conn_has_connection_to(char *sip_aor, ident_t *ident, int flags)
{
        int ret = 0;
        conn_connection_t *conn;

        conn = conn_find_connection_by_aor(sip_aor, ident->sip_aor);
        if (conn && conn->state == STATE_CONNECTED) {
		time_t now;
		struct sockaddr *addr = 0;
		socklen_t addrlen = 0;
		int heard;
		
		time(&now);
		heard = now - conn->last_heard;
		if (heard < 20 && !getpeername(conn->socket, addr, &addrlen))
			ret = 1;
		else
			conn_conn_close(conn);
        }
	ship_obj_unlockref(conn);
        return ret;
}
#endif

/* a func for returning all the peers a given ident has a connection
   to. if NULL, then ALL peers all returned. ownership is given */
void
conn_get_connected_peers(char *sip_aor, ship_list_t *ret)
{
        conn_connection_t *c = NULL;
	void *ptr = 0;
	
        if (conn_all_conn) {
		ship_lock(conn_all_conn);
		while ((c = ship_list_next(conn_all_conn, &ptr))) {
			ship_lock_conn(c);
			if (!sip_aor ||
			    ((c->local_aor && !strcmp(sip_aor, c->local_aor)) &&
			     c->sip_aor)) {
				char *t = strdup(c->sip_aor);
				ship_list_add(ret, t);
			}
			ship_unlock(c);
		}
		ship_unlock(conn_all_conn);
	}
}

#ifdef OLD_QUEUE
static int
conn_queue_fragment(char *to, char *from,
                   int id, int part, int parts,
                   service_type_t service,
                   char *data, int data_len,
                   void *ptr, void (*callback) (char *to, char *from, service_type_t service,
                                                char *data, int data_len, void *ptr,
                                                int code))
{
	void **arr = 0;
	int ret = -1, i;

	ASSERT_TRUE(arr = mallocz(7 * sizeof(void*)), err);
	ASSERT_TRUE(arr[0] = strdup(to), err);
	ASSERT_TRUE(arr[1] = strdup(from), err);
	ASSERT_TRUE(arr[2] = mallocz(sizeof(service_type_t)), err);
	memcpy(arr[2], &service, sizeof(service));

	if (parts < 2) {
		ASSERT_TRUE(arr[3] = mallocz(data_len+CONN_SERVICE_NORMAL_HEADER_LEN+1), err);
		ship_inroll(0, ((char*)arr[3]), 1);
		memcpy(arr[3]+CONN_SERVICE_NORMAL_HEADER_LEN, data, data_len);
		data_len += CONN_SERVICE_NORMAL_HEADER_LEN;
	} else {
		ASSERT_TRUE(arr[3] = mallocz(data_len+CONN_SERVICE_SPLIT_HEADER_LEN+1), err);
		ship_inroll(1, ((char*)arr[3]), 1);
		ship_inroll(id, ((char*)arr[3]+1), 4);
		ship_inroll(part, ((char*)arr[3]+5), 4);
		ship_inroll(parts, ((char*)arr[3]+9), 4);
		memcpy(arr[3]+CONN_SERVICE_SPLIT_HEADER_LEN, data, data_len);
		data_len += CONN_SERVICE_SPLIT_HEADER_LEN;
	}

	ASSERT_TRUE(arr[4] = mallocz(sizeof(data_len)), err);
	memcpy(arr[4], &data_len, sizeof(data_len));
	arr[5] = ptr;
	arr[6] = callback;

	STATS_LOG("queue;%s;%s;%d;%d;%d;%d\n",
		  to, from, service, odata_len, data_len, 0);
	
	processor_tasks_add(conn_send_do, arr,
			    conn_send_done);
	
	arr = 0;
	ret = 0;
 err:
	for (i=0; arr && i < 5; i++)
		freez(arr[i]);
	freez(arr);
	return ret;
}
#endif

/* try to establish a fast connection, else use slow */
int conn_send_default(char *to, char *from,
		      service_type_t service,
		      char *data, int data_len,
		      void *ptr, conn_packet_callback callback)
{
	return conn_send(CONN_SEND_SECURE, 
			 to, from, service, data, data_len, ptr, callback);
}

/* send on fast if connected, else use slow (if possible). else establish fast */
int conn_send_slow(char *to, char *from,
		   service_type_t service,
		   char *data, int data_len,
		   void *ptr, conn_packet_callback callback)
{
	return conn_send(CONN_SEND_SECURE | CONN_SEND_PREFER_SLOW, 
			 to, from, service, data, data_len, ptr, callback);
}

/* send on fast only, return error if a connection couldn't be established */
int conn_send_fast(char *to, char *from,
		   service_type_t service,
		   char *data, int data_len,
		   void *ptr, conn_packet_callback callback)
{
	return conn_send(CONN_SEND_SECURE | CONN_SEND_REQUIRE_FAST, 
			 to, from, service, data, data_len, ptr, callback);
}

/* send IF connected, nodelay, don't care whether it is delivered; best-effort */
int conn_send_simple(char *to, char *from,
		     service_type_t service,
		     char *data, int data_len)
{
	return conn_send(CONN_SEND_SECURE | CONN_SEND_REQUIRE_FAST, 
			 to, from, service, data, data_len, NULL, NULL);
}


/* dtn: packet id. what? hash(from-to + shared secret?)_instanceid[random...32bit?]_counter? */
static char*
conn_create_pkgid(const char *from, const char *to)
{
	char *ret = 0, *ret2 = 0;
	int len = sizeof(conn_instance_id)+strlen(from)+strlen(to);
	
	ASSERT_TRUE(ret = mallocz(len), err);
	strcpy(ret, from);
	strcat(ret, to);
	memcpy(ret+strlen(ret), conn_instance_id, 32);
	ASSERT_TRUE(ret2 = ship_hash_sha1_base64(ret, len), err);
	freez(ret);
	ASSERT_TRUE(ret = mallocz(strlen(ret2) + 10), err);
	sprintf(ret, "%s:%d", ret2, packet_count++);
	freez(ret2);
	return ret;
 err:
	freez(ret);
	freez(ret2);
	return NULL;
}


/* sends an ack / nack for a service packet 
 * @param conn the conn on which the part was received. can be null
 * 
 */
static int
conn_send_ack(conn_packet_t *o,
	      int code, const char *data, const int data_len)
{
	int ret = -1;
	conn_packet_t *p = 0;

	ASSERT_TRUE(p = conn_packet_new_ack(o, code, data, data_len), err);
	if (processor_tasks_add(conn_send_do, p,
				conn_send_done))
		ship_obj_ref(p);
	ret = 0;
 err:
	ship_obj_unref(p);
	return ret;
}
	      
	      

/* This function tries to send a packet to a remote host, calling the
   provided callback when complete. */
int
conn_send(int flags,
	  char *to, char *from, 
	  service_type_t service,
	  char *data, int data_len,
	  void *ptr, conn_packet_callback callback)
{
#ifndef OLD_QUEUE
	int ret = -1;
	conn_packet_t *p = 0;

	ASSERT_TRUE(p = conn_packet_new_service(to, from,
						service,
						data, data_len,
						flags, ptr, callback), err);
	ship_obj_ref(p);
	if (!processor_tasks_add(conn_send_do, p,
				 conn_send_done)) {
		ship_obj_unref(p);
	} else
		ret = 0;
 err:
	ship_obj_unref(p);
	return ret;
#else
	int i, ret = -1, cs, parts, dpp;

	/* dtn: do not split this up yet. create packet id */
	
	/* dtn: this splitting up of packets should be something protocol-specific, e.g.
	   a parameter in the protocol struct that says what the mtu is. 

	   and the splitup should be based on byte ranges, not sequence numbers as different protocols
	   can have different sized mtu's.

	   .. maybe the 'direct connection' could actually be just a single-use tube for a packet?
	   mm. .. maybe not.
	*/

	/* hm, is it a security risk to use the same counter for all peers? */
	if (data_len > (CONN_MAX_PKG_SERVICE_CONTENT_LEN - CONN_SERVICE_NORMAL_HEADER_LEN)) {
		parts = data_len / (CONN_MAX_PKG_SERVICE_CONTENT_LEN - CONN_SERVICE_SPLIT_HEADER_LEN);
		if ((data_len % (CONN_MAX_PKG_SERVICE_CONTENT_LEN - CONN_SERVICE_SPLIT_HEADER_LEN)))
			parts++;
		cs = splitcounter++;
		dpp = CONN_MAX_PKG_SERVICE_CONTENT_LEN - CONN_SERVICE_SPLIT_HEADER_LEN;
		LOG_DEBUG("Queing %d bytes from %s to %s for service %d in %d parts\n", data_len, from, to, service, parts);
	} else {
		dpp = CONN_MAX_PKG_SERVICE_CONTENT_LEN - CONN_SERVICE_NORMAL_HEADER_LEN;
		parts = 1;
		cs = -1;
		LOG_VDEBUG("Queing %d bytes from %s to %s for service %d in %d part\n", data_len, from, to, service, parts);
	}
	
	/* PROTOCOL:
	   - if first byte != 0, then we have a split-up package!
	   - if not, then the next word(32) is some sort of unique id
	   
	   - if first byte 1, then follows the part number (32 bit) and total parts (32bit)
	   (1 + 4 + 4 + 4 = 13 bytes header)
	*/

	STATS_LOG("fragments;%s;%s;%d;%d;%d;%d\n",
		  to, from, service, data_len, data_len, parts);
	for (i=0; i < parts; i++) {
		if (i == (parts-1)) {
			ASSERT_ZERO(conn_queue_fragment(to, from, cs, i, parts, service, data+(i*dpp), data_len, ptr, callback), err);
		} else {
			ASSERT_ZERO(conn_queue_fragment(to, from, cs, i, parts, service, data+(i*dpp), dpp, NULL, NULL), err);
			data_len -= dpp;
		}
	}
	
	ret = 0;
 err:
	return ret;
#endif
}

#ifdef NEW_CONNS

void
conn_deinit_transports(ident_t *ident)
{
	conn_transport_handler_t *conn = 0;
	while ((conn = ship_list_pop(ident->transport_handlers)))
		conn->close_instance(conn);
}

/* inits & fills the user's transport handlers */
int
conn_init_transports(ident_t *ident)
{
	conn_transport_handler_t *conn = 0;
	void *ptr = 0;
	char **tokens = 0;
	int toklen = 0, i;
	ship_ht_t *tmp = 0;

	// todo: make this a setting
	char *preference = "hip,tcp,chord";
	
	if (!conn_transports)
		return 0;

	ship_lock(conn_transports);

	// remove old ones not valid anymore
	ASSERT_TRUE(tmp = ship_ht_new(), err);
	while ((conn = ship_list_next(ident->transport_handlers, &ptr))) {
		if (!ship_ht_get_string(conn_transports, conn->name))
			conn->close_instance(conn);
		else
			ship_ht_put_string(tmp, conn->name, conn);
	}
	
	// add new ones
	while ((conn = ship_ht_next(conn_transports, &ptr))) {
		if (!ship_ht_get_string(tmp, conn->name)) {
			ASSERT_TRUE(conn = conn->new_instance(ident), err);
			ship_ht_put_string(tmp, conn->name, conn);
		}
	}

	// sort
	ASSERT_ZERO(ship_tokenize_trim(preference, -1, &tokens, &toklen, ','), err);
	ship_list_clear(ident->transport_handlers);
	for (i = 0; i < toklen; i++) {
		if ((conn = ship_ht_remove_string(tmp, tokens[i])))
			ship_list_add(ident->transport_handlers, conn);
	}

	while ((conn = ship_ht_pop(tmp)))
		ship_list_add(ident->transport_handlers, conn);
 err:
	ship_unlock(conn_transports);
	ship_tokens_free(tokens, toklen);
	ship_ht_free(tmp);
	return 0;
}


/* registers the handler, initing it for each of the currently
   registered identities */
int
conn_register_transport(conn_transport_handler_t *handler)
{
	ASSERT_ZERO(ship_ht_get_string(conn_transports, handler->name), err);
	ASSERT_ZERO(handler->init(), err);
	ship_ht_put_string(conn_transports, handler->name, handler);
	ident_reinit_transport_handlers();
	return 0;
 err:
	return -1;
}

void
conn_unregister_transport(const char *name)
{
	conn_transport_handler_t *h;
	if ((h = ship_ht_remove_string(conn_transports, name))) {
		/* go through identities .. refresh those */
		ident_reinit_transport_handlers();
		h->close();
	}
}

/* note, modules:

- hip
- tls
- plain-tcp
- overlay
- im (aol, jabber etc?)
- mail?
- file-dtn

*/

#endif


#ifdef NEW_CONNS

static void conn_send_loop_cb(int success, conn_packet_t *p, conn_transport_handler_t *oconn);

static void
conn_connect_cb(int success, conn_packet_t *p, conn_transport_handler_t *conn) {
	if (success == 0) {
		conn->send(conn, p, conn_send_loop_cb);
	} else {
		conn_send_loop_cb(-1, p, conn);
	}
}

static void
conn_send_loop_cb(int success, conn_packet_t *p, conn_transport_handler_t *oconn)
{
	void *ptr = 0;

	ship_lock(p);
	ASSERT_TRUE(p->wait, end);
	if (oconn && success == 0) {
		LOG_HL("send over, we got a winner!\n");
		processor_signal_wait(p->wait, 0);
		p->wait = 0;
		ship_list_clear(p->conns);
		ship_list_clear(p->secondary_conns);
	} else { 
		conn_transport_handler_t *conn = 0;

		// either not sent or 'perhaps / pending / not sent'
		while ((conn = ship_list_next(p->conns, &ptr)))
			if (conn->is_connected(conn, p->to))
				break;
		if (conn) {
			// let it be there unless we are preferring slow AND this
			// is the first round.
			if ((p->flags & CONN_SEND_PREFER_SLOW) &&
			    p->secondary_conns)
				ship_list_remove(p->conns, conn);

			ship_obj_ref(p);
			if (conn->send(conn, p, conn_send_loop_cb) < 0) {
				ship_obj_unref(p);
				conn->disconnect(conn, p->to);
				conn_send_loop_cb(-1, p, NULL);
			}
		} else if ((conn = ship_list_pop(p->conns))) {
			ship_obj_ref(p);
			if (conn->connect(conn, p, conn_connect_cb) < 0) {
				ship_obj_unref(p);
				conn_send_loop_cb(-1, p, NULL);
			}
		} else if (p->secondary_conns) {
			ship_list_free(p->conns);
			p->conns = p->secondary_conns;
			p->secondary_conns = 0;
			conn_send_loop_cb(-1, p, NULL);
		} else {
			/* game over? */
			LOG_HL("send over, no luck!\n");
			processor_signal_wait(p->wait, -1);
			p->wait = 0;
		}
	}
 end:
	ship_unlock(p);
	if (oconn)
		ship_obj_unref(p);
}

#endif

static void 
conn_send_done(void *data, int code)
{
	conn_packet_t *p = (conn_packet_t *)data;

	p->code = code;
	ship_obj_unref(p);
}

static int 
conn_send_do(void *data, processor_task_t **wait, 
	     int wait_for_code)
{
        int ret = -2;
	conn_packet_t *p = (conn_packet_t *)data;
#ifndef NEW_CONNS
	//ident_t *ident = 0;
#else
	conn_transport_handler_t *conn = 0;
	void *ptr = 0;

	/* done with the loops? */
	if ((*wait)) { // && ((*wait) != p->reg_wait)) {
		LOG_HL("got wait with code %d\n", wait_for_code);
		return wait_for_code;
	}
#endif

	if (!p->ident) {
		ship_wait("Waiting to get the default ident to use with send!\n");
		if (!(p->ident = (ident_t *)ident_find_by_aor(p->from))) {
			ASSERT_ZERO(strlen(p->from), err);
			LOG_WARN("No identity given, using default!\n");
			ASSERT_TRUE(p->ident = ident_get_default_ident(), err);
			ASSERT_TRUE(p->from = strdup(p->ident->sip_aor), err);
		}
		ship_complete();
	}

#ifdef NEW_CONNS
	/* order: first check whether we have connections matching
	   that actually are connected!  if not, check that we have a
	   valid registration for the user. then start the loop! */

	/* no, new order: try to get a valid reg packet, update if necessary. */
	/* skip this. do it the right way(r): start a lookup for reg packets when a transport module 
	   asks for an address not currently known .. */
	/*
	reg_package_t *pkg = 0;
	if ((ret = ident_lookup_registration(ident, p->to, &pkg, &(p->reg_wait)))) {
		LOG_HL("pkg lookup with code %d\n", ret);

		if (!(*wait) || wait_for_code == 0) {
		
		*wait = p->reg_wait;
		return ret;
	} else 
		ship_unlock(pkg);
	*/
	
	ship_list_free(p->conns);
	ASSERT_TRUE(p->conns = ship_list_new(), err);
	ship_list_free(p->secondary_conns);
	ASSERT_TRUE(p->secondary_conns = ship_list_new(), err);

	p->wait = processor_create_wait();
	*wait = p->wait;
	if (p->flags & CONN_SEND_REQUIRE_FAST) {
		while ((conn = ship_list_next(p->ident->transport_handlers, &ptr))) {
			if (conn->is_fast(conn, p->to))
				ship_list_add(p->conns, conn);
		}
	} else if (p->flags & CONN_SEND_PREFER_SLOW) {
		// put all connected conns plus slow conns in conns
		// put fast in secondary_conns
		while ((conn = ship_list_next(p->ident->transport_handlers, &ptr))) {
			if ((conn->is_fast(conn, p->to) && conn->is_connected(conn, p->to)) ||
			    conn->is_slow(conn, p->to))
				ship_list_add(p->conns, conn);
			if (conn->is_fast(conn, p->to))
				ship_list_add(p->secondary_conns, conn);
		}
	} else {
		// just all conns, but in preferred order. fast first!
		while ((conn = ship_list_next(p->ident->transport_handlers, &ptr)))
			ship_list_add(p->conns, conn);
	}
	LOG_HL("Starting send thing!\n");
	conn_send_loop_cb(-1, p, NULL);
	ret = 1;
#else
	ret = 0;
	if (!conn_has_connection_to(p->to, p->ident, p->flags)) { /* dtn: check connection type as well! */
		/* try only once! */
		if (!(*wait)) {
			
			/* dtn: choose one of the connection types according to policies and
			   the requirements of the packet to be sent */

			/* dtn: save 'state' in the data array above */

			ret = conn_open_connection_to(p->to, p->ident, wait, p->flags);
		} else
			ret = -1;
	}
	
	if (!ret) {
		
		/* dtn: create the connection-checking state thing here on the first loop through */
		
		if (conn_has_connection_to(p->to, p->ident, p->flags)) {
			ret = conn_send_service_package_to(p);
		} else {
			ret = -2;
		}
	}
#endif
 err:
#ifdef NEW_CONNS
        ship_unlock(p->ident);
#else
        ship_obj_unlockref(p->ident);
	p->ident = NULL;
#endif
        return ret;
}

#ifndef NEW_CONNS

/* @sync ok
   starts the connecting-process to the given peer.  returns error if
   it will not be even attempted, otherwise error / ok will be
   reported through a processor event eventually. */
static int
conn_open_connection_to(char *sip_aor, ident_t *ident, processor_task_t **wait, int flags)
{
        conn_connection_t *conn = 0;
        int ret = -1;
        
        LOG_INFO("should open connection to %s from %s\n", sip_aor, ident->sip_aor);

        /* yes, this needs to be synced as we dont want > 1 simulataneously trying this! */
        ship_lock(conn_all_conn); {

                if ((conn = conn_find_connection_by_aor(sip_aor, ident->sip_aor))) {
                        if (conn->wait) {
                                LOG_DEBUG("waiting for existing wait..\n");
                                (*wait) = conn->wait;
                                ret = 1;
                        }
                } else {
			conn_connection_t c;
			bzero(&c, sizeof(c));
			c.sip_aor = sip_aor;
			c.ident = ident;
                        if ((conn = (conn_connection_t *)ship_obj_new(TYPE_conn_connection, &c))) {
				ship_obj_list_add(conn_all_conn, conn);
				ship_lock_conn(conn);
			} else
                                ret = -4;
                }

                if (conn) {
                        if (conn->state == STATE_CONNECTED) {
                                ret = 0;
                        } else if (!conn->wait) {
				
				ship_obj_ref(conn);
				(*wait) = processor_tasks_add(conn_open_connection_to_do, 
							      conn,
							      conn_open_connection_to_done);
				conn->wait = (*wait);
				ret = 1; 
                        }
                        ship_obj_unlockref(conn);
                }
        } ship_unlock(conn_all_conn);

        return ret;
}

/* finds from a list of addr's the first one with a valid port number
   (transport address) */
static addr_t*
conn_find_first_with_port(ship_list_t *list)
{
	addr_t *ret = 0;
	void *ptr = 0;
	while (!ret && (ret = ship_list_next(list, &ptr))) {
		if (!ret->port)
			ret = 0;
	}
	return ret;
}
#endif

/* gets the connection address */
int
conn_can_connect_to(reg_package_t *pkg)
{
#ifdef NEW_CONNS
	return 1;
#else
#ifdef CONFIG_HIP_ENABLED
	if (conn_find_first_with_port(pkg->hit_addr_list) ||
	    (conn_allow_nonhip && conn_find_first_with_port(pkg->ip_addr_list)))
		return 1;
#else
	if (conn_find_first_with_port(pkg->ip_addr_list))
		return 1;
#endif
	return 0;
#endif
}


#ifndef NEW_CONNS
/* @sync ok
   initiates a hip connection to a peer. */
static int
conn_open_connection_to_do(void *data, processor_task_t **wait, int wait_for_code)
{
        reg_package_t *pkg = NULL;
        int ret = -2;
        conn_connection_t * conn = (conn_connection_t*)data;
	ident_t *ident = 0;

	/* we need to lock this as we might get netio callback before
	   assigning the socket to the conn */
	ident = ident_find_by_aor(conn->local_aor);
	ship_lock_conn(conn);
	conn->ident = ident;
	if (!(*wait) || wait_for_code == 0) {
                int hadwait = 0;

                ret = -1;
                if ((*wait))
                        hadwait = 1;
                *wait = NULL;

                /* if happily connected, end! */
                if (conn->state == STATE_CONNECTED) {
                        ret = 0;
                } else if (!(ret = ident_lookup_registration(conn->ident, conn->sip_aor, &pkg, wait))) {
                        addr_t *addr = 0;
                        struct sockaddr *sa = 0;
                        socklen_t salen;
                        
                        ret = -2;
#ifdef CONFIG_HIP_ENABLED
			/* don't try HIP if we aren't running it */
			if (hipapi_hip_running()) {
				LOG_DEBUG("trying to find HIT..\n");
				addr = conn_find_first_with_port(pkg->hit_addr_list);
				if (addr && !hipapi_has_linkto(addr)) {
					if (hipapi_establish(addr, pkg->ip_addr_list, pkg->rvs_addr_list)) {
						LOG_ERROR("HIP connection could not be established.\n");
						addr = NULL;
					}
				}
			}
			
			if (!addr && conn_allow_nonhip) {
				LOG_DEBUG("using first non-hit ip..\n");
				addr = conn_find_first_with_port(pkg->ip_addr_list);
			}
#else
                        addr = conn_find_first_with_port(pkg->ip_addr_list);
#endif
			/* mark the registration as faul if it doesn't have this */
                        if (!addr) {
				LOG_ERROR("No working address / HIT found.\n");
				pkg->need_update = 1;
			}
			if (addr && !ident_addr_addr_to_sa(addr, &sa, &salen)) {
				conn->state = STATE_CONNECTING;
				time(&conn->last_content);

				/* mark the start time of the connect! */
				STATS_LOG("conn start from %s to %s\n", conn->local_aor, conn->sip_aor);
#ifdef CONFIG_SIP_ENABLED
#ifdef DO_STATS
				ac_packetfilter_stats_event(conn->local_aor, conn->sip_aor, "conn_start");
#endif				
#endif
				conn->socket = netio_connto(sa, salen, conn_cb_conn_opened);
				if (conn->socket != -1) {
					LOG_DEBUG("waiting for netio connect..\n");
					ret = 1;
					conn->wait = processor_create_wait();
					(*wait) = conn->wait;
				}
				
                                free(sa);
                        }
			ship_unlock(pkg);
                } else if (ret == 1 && !hadwait) {
                        LOG_DEBUG("waiting for reg package lookup..\n");
                        ret = 1;
                } else {
			LOG_DEBUG("error fetching registration package\n");
                        ret = -1;
                }
        }
	ship_obj_unlockref(conn->ident);
        ship_unlock(conn);
        return ret;
}

/* @sync ok
   called when a connection-open task has been completed by the processor. */
static void
conn_open_connection_to_done(void *data, int code)
{
        conn_connection_t *conn = (conn_connection_t*)data;

        LOG_INFO("open connection task done with %d\n", code);
	ship_lock_conn(conn);
	
	conn->wait = NULL;
	ship_obj_ref(conn);
	if (code == 0) {
		conn->state = STATE_CONNECTED;
		processor_event_generate("conn_made", conn, conn_event_cb);
	} else if (code < 0) {
		conn->state = STATE_ERROR;
		processor_event_generate("conn_failed", conn, conn_event_cb);
	}
	ship_obj_unlockref(conn);
}

/* @sync ok
   called by the netio module when a connection has been opened
   somewhere */
static void
conn_cb_conn_opened(int s, struct sockaddr *sa, socklen_t addrlen)
{
        conn_connection_t *conn = 0;
        int status = 0;
	addr_t addr;
	
	if (!ident_addr_sa_to_addr(sa, addrlen, &addr)) {
		LOG_INFO("socket %d connected to %s:%d\n", s, addr.addr, addr.port);
	}

        /* store sa */
        if ((conn = conn_find_connection_by_socket(s))) {
		ship_wait("handing established conn");

		/* mark the end time of the connect! */
		STATS_LOG("conn end from %s to %s\n", conn->local_aor, conn->sip_aor);
#ifdef CONFIG_SIP_ENABLED
#ifdef DO_STATS
		ac_packetfilter_stats_event(conn->local_aor, conn->sip_aor, "conn_end");
#endif
#endif
		freez(conn->sa);
                conn->sa = (struct sockaddr*)mallocz(addrlen);
                if (conn->sa) {
                        memcpy(conn->sa, sa, addrlen);
                        conn->addrlen = addrlen;
                        
			if (!netio_read(s, conn_cb_data_got)) {
				char *reg_str = NULL;
				ident_t *ident = NULL;
				
				/* first, send reg package, then send target. */
				ship_unlock(conn);
				if ((ident = ident_find_by_aor(conn->local_aor)))
					reg_str = ident_get_regxml(conn->ident);
				ship_obj_unlockref(ident);
				ship_lock(conn);

				ship_wait("sending reg_pkg on conn");
				if (!reg_str) {
					status = -2;
				} else if (!(status = conn_send_conn(conn, (char*)reg_str, strlen(reg_str), PKG_REG)) &&
					   !(status = conn_send_conn(conn, conn->sip_aor, strlen(conn->sip_aor), PKG_TARGET))) {
					LOG_DEBUG("sent reg and target packets\n");
					time(&conn->last_content);
					status = 0;
				} else {
					LOG_ERROR("could not send data on %d (peer doesn't have proxy running?)\n", s);
					status = -3;
				}
				freez(reg_str);
				ship_complete();
			} else {
				LOG_ERROR("could not start receiving data\n");
				status = -3;
			} 
                } else {
                        status = -4;
                }        

                /* now we wait to receive a valid reg-package from the
                 * tunnel before notifying the process initiator that
                 * we are connected */
		if (status) {
			conn_conn_close(conn);
			processor_signal_wait(conn->wait, status);
			conn->wait = NULL;
		}
		ship_complete();
		ship_obj_unlockref(conn);
        } else {
                netio_close_socket(s);
        }
        
        LOG_INFO("socket %d conn end with %d\n", s, status);
}
#endif

/**********************************
 ** some misc. utility functions **
 **********************************/


/* Fills the connectivity-related values of the given reg package */
int
conn_fill_reg_package(ident_t *ident, reg_package_t *pkg)
{
	void *ptr = 0;
#ifdef NEW_CONNS
	conn_transport_handler_t *handler = 0;
	ship_ht_empty_free(pkg->transport_addresses);
	while ((handler = ship_list_next(ident->transport_handlers, &ptr))) {
		char *addr = 0;
		if (handler->get_transport_address)
			addr = handler->get_transport_address(handler);
		ship_ht_put_string(pkg->transport_addresses, handler->name, addr);
	}
#else
	addr_t *addr = 0;
#ifdef CONFIG_HIP_ENABLED
	void *last = 0;
#endif
        /* get my hit & rvs */
        ship_list_empty_free(pkg->ip_addr_list);
        ship_list_empty_free(pkg->hit_addr_list);
        ship_list_empty_free(pkg->rvs_addr_list);

	/* add the actual ip addresses of the ones we are listening to */
	ship_lock(conn_lis_sockets);
	while ((addr = ship_list_next(conn_lis_socket_addrs, &ptr))) {
		addr_t *tmp = mallocz(sizeof(addr_t));
		if (tmp) {
			memcpy(tmp, addr, sizeof(addr_t));
			ship_list_add(pkg->ip_addr_list, tmp);
		}
	}

#ifdef CONFIG_HIP_ENABLED
	/* add ip's without port - for mapping hits! */
	conn_getips(pkg->ip_addr_list, conn_ifaces, conn_ifaces_count, 0);
	
	/* if some of those were hits, then put them into the hits
	   array. it doesen't really make any difference right now in
	   which array they are, but lets do it anyway ..*/
	ptr = 0;
	last = 0;
	while ((addr = ship_list_next(pkg->ip_addr_list, &ptr))) {
		if (hipapi_addr_is_hit(addr)) {
			ptr = last;
			ship_list_remove(pkg->ip_addr_list, addr);
			ship_list_add(pkg->hit_addr_list, addr);
		}
		last = ptr;
	}

	/* y los rvsos.. */
	hipapi_getrvs(pkg->rvs_addr_list);
#endif
	ship_unlock(conn_lis_sockets);
#endif
	return 0;
}

/* validates that the list of interfaces really are interfaces! */
int
conn_validate_ifaces(char **ifaces, int c)
{
	int i;
	int ret = 0;

	for (i=0; i < c; i++) {
		if (strcmp(ifaces[i], "all") &&
		    strcmp(ifaces[i], "ext") &&
		    strcmp(ifaces[i], "none") &&
		    !if_nametoindex(ifaces[i])) {
			USER_ERROR("invalid interface '%s'\n", ifaces[i]);
			ret = -1;
		}
	}
	return ret;
}

static int
conn_if_matches_any(const int index, char **ifaces, int ifaces_len)
{
	char bb[IF_NAMESIZE];
	int i;
	
	if_indextoname(index, bb);
	
	for (i=0; i < ifaces_len; i++) {
		char *name = ifaces[i];
		
		if (!strcmp(name, bb) ||
		    !strcmp(name, "all") ||
		    (!strcmp(name, "ext") &&
		     /* add more here as needed.. */
		     (str_startswith(bb, "eth") ||
		      str_startswith(bb, "ath") ||
		      str_startswith(bb, "ppp") ||
		      str_startswith(bb, "wlan") ||
		      str_startswith(bb, "teredo")
		      ))) {
			return 1;
		}
	}
	return 0;
}


int
conn_getips_af(ship_list_t *ips, char **ifaces, int ifaces_len, int port, const int af)
{
	int ret = -1;
	struct nlmsghdr *h;
	
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;

	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[16384];
	
	int i;
        int s = -1;
	
	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	ASSERT_TRUE(s != -1, err);
	
	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = RTM_GETADDR;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = time(0);
	req.g.rtgen_family = af;
	
	ASSERT_TRUE(send(s, (void*)&req, sizeof(req), 0) != -1, err);

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	i = recvmsg(s, &msg, 0);
	ASSERT_TRUE(i > 0, err);

	h = (struct nlmsghdr*)buf;	
	while (NLMSG_OK(h, i)) {
		struct ifaddrmsg *ifa = NLMSG_DATA(h);

		/* right pe, right interface */
		if (h->nlmsg_type != NLMSG_DONE &&
		    h->nlmsg_type != NLMSG_ERROR &&
		    (ifa->ifa_scope == RT_SCOPE_UNIVERSE ||
		     ifa->ifa_scope == RT_SCOPE_SITE ||
		     ifa->ifa_scope == RT_SCOPE_HOST) &&
		    conn_if_matches_any(ifa->ifa_index, ifaces, ifaces_len)) {
			int rtasize = h->nlmsg_len - NLMSG_HDRLEN;
			struct rtattr *rta = (struct rtattr *) (((char *) NLMSG_DATA(h)) +
								NLMSG_ALIGN(NLMSG_ALIGN(sizeof(*ifa))));;
				
			while (RTA_OK(rta, rtasize)) {
				char *rtadata = RTA_DATA(rta);

				switch (rta->rta_type) {
				case IFA_ADDRESS: {
					struct sockaddr_in6 sin6;
					struct sockaddr_in sin;
					struct sockaddr *sa = 0;
					socklen_t sa_len = 0;
						
					if (ifa->ifa_family == AF_INET6) {
						memcpy(&sin6.sin6_addr, rtadata, sizeof(sin6.sin6_addr));
						sin6.sin6_family = ifa->ifa_family;
						sa = (struct sockaddr *)&sin6;
						sa_len = sizeof(sin6);
					} else if (ifa->ifa_family == AF_INET) {
						memcpy(&sin.sin_addr, rtadata, sizeof(sin.sin_addr));
						sin.sin_family = ifa->ifa_family;
						sa = (struct sockaddr *)&sin;
						sa_len = sizeof(sin);
					}
						
					if (sa) {
						addr_t *addr = mallocz(sizeof(addr_t));
						if (addr && !ident_addr_sa_to_addr(sa, sa_len, addr)) {
							ship_list_add(ips, addr);
							addr->port = port;
							addr = 0;
						} else 
							freez(addr);
					}
						
					break;
				}
				}
				rta = RTA_NEXT(rta, rtasize);
			}
		}
		h = NLMSG_NEXT(h, i);
	}
 err:
	/* remove duplicates (this has happened on the tablet .. */
	
	close(s);
	return ret;
}


/* fills the given list with the addresses of the given interfaces */
int 
conn_getips(ship_list_t *ips, char **ifaces, int c, int port) 
{
	addr_t *addr = 0;
	void *tmp = 0;
	
	conn_getips_af(ips, ifaces, c, port, AF_INET);
	conn_getips_af(ips, ifaces, c, port, AF_INET6);

	/* remove duplicates */
	while ((addr = ship_list_next(ips, &tmp))) {
		void *tmp2 = tmp, *last = tmp;
		addr_t *addr2 = 0;
		while ((addr2 = ship_list_next(ips, &tmp2))) {
			if (!ident_addr_cmp(addr, addr2)) {
				char *str = 0;
				ident_addr_addr_to_str(addr2, &str);
				LOG_WARN("Removed duplicate address: %s\n", str);
				freez(str);
				
				ship_list_remove(ips, addr2);
				tmp2 = last;
				freez(addr2);
			}
			last = tmp2;
		}
	}

	return 0;
}

/* returns the lo addr */
int
conn_get_lo(addr_t *addr)
{
	addr->family = AF_INET;
	strcpy(addr->addr, "127.0.0.1");
	addr->type = IPPROTO_NONE;
	addr->port = 0;
	return 0;
}

/* returns one public ip */
int
conn_get_publicip(addr_t *addr)
{
	addr_t *a2 = NULL;
	ship_list_t *tmp = ship_list_new();
	int ret = -1;
	if (tmp) {
		if (!conn_getips(tmp, conn_ifaces, conn_ifaces_count, 0) && 
		    (a2 = ship_list_first(tmp))) {
			memcpy(addr, a2, sizeof(addr_t));
			ret = 0;
		}
		ship_list_empty_free(tmp);
		ship_list_free(tmp);
	}
	return ret;
}


/* the conn register */
static struct processor_module_s processor_module = 
{
	.init = conn_init,
	.close = conn_close,
	.name = "conn",
#ifdef CONFIG_HIP_ENABLED
	.depends = "netio,netio_ff,netio_man,ident,hipapi,olclient",
#else
	.depends = "netio,netio_ff,netio_man,ident,olclient",
#endif
};

/* register func */
void
conn_register() {
	processor_register(&processor_module);
}


#ifdef NEW_CONNS
/* plain-tcp transport */
static int trans_tcp_init();
static void trans_tcp_close();
static conn_transport_handler_t* trans_tcp_new_instance(ident_t *ident);
static int trans_tcp_connect(conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback);
static int trans_tcp_is_connected(conn_transport_handler_t *self, const char *sip_aor);
static int trans_tcp_disconnect(conn_transport_handler_t *self, const char *sip_aor);
static int trans_tcp_is_fast(conn_transport_handler_t *self, const char *sip_aor);
static int trans_tcp_is_slow(conn_transport_handler_t *self, const char *sip_aor);
static int trans_tcp_send(conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback);
static void trans_tcp_close_instance(conn_transport_handler_t *self);
static char* trans_tcp_get_transport_address(conn_transport_handler_t *self);

struct trans_tcp_transport_s {
	conn_transport_handler_t handler;
	ship_ht_t *connections;
};

static struct trans_tcp_transport_s trans_tcp_transport =
	{
		.handler = {
			.name = "tcp",
			
			.init = trans_tcp_init,
			.close = trans_tcp_close,
			.new_instance = trans_tcp_new_instance,
			
			.connect = trans_tcp_connect,
			.is_connected = trans_tcp_is_connected,
			.disconnect = trans_tcp_disconnect,
			
			.is_fast = trans_tcp_is_fast,
			.is_slow = trans_tcp_is_slow,
			
			.send = trans_tcp_send,
			
			.close_instance = trans_tcp_close_instance,

			.get_transport_address = trans_tcp_get_transport_address,
		},

		//.data = "hello",
	};
		
	


static int 
trans_tcp_init()
{
	LOG_HL("initing tcp transport\n");
	return 0;
}

static void 
trans_tcp_close()
{
	LOG_HL("closing tcp transport\n");
}

static conn_transport_handler_t*
trans_tcp_new_instance(ident_t *ident)
{
	struct trans_tcp_transport_s *ret = 0;
	
	LOG_HL("new instance for %s\n", ident->sip_aor);
	ASSERT_TRUE(ret = mallocz(sizeof(*ret)), err);
	memcpy(ret, &trans_tcp_transport, sizeof(*ret));
	ASSERT_TRUE(ret->connections = ship_ht_new(), err);
	return (conn_transport_handler_t*)ret;
 err:
	trans_tcp_close_instance((conn_transport_handler_t*)ret);
	return NULL;
}

/* callback from the identity module when a reg packet has been received */
static void
_trans_tcp_connect_cb(const char *addr, void *ptr)
{
	conn_transport_handler_t *self = 0;
	conn_packet_t *packet = 0;
	conn_transport_handler_cb callback = 0;
	LOG_HL("callback with %s\n", addr);

	ship_unpack_keep(ptr, &self, &packet, &callback);

	/* use the address (if any) somehow */
	if (addr) {
		
		
		callback(-1, packet, self);


	} else
		callback(-1, packet, self);
	ship_pack_free(ptr);
}

static int 
trans_tcp_connect(conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback)
{
	struct trans_tcp_transport_s *tcp = (struct trans_tcp_transport_s*)self;
	conn_connection_t *conn;
	int ret = -1;
	void *ptr = 0;
	char *addr = 0;
	
	LOG_HL("connect to %s\n", packet->to);

	ship_lock(tcp->connections);
	conn = ship_ht_get_string(tcp->connections, packet->to);
	if (!conn) {
		/* create a new connection for this .. */
		
		//conn = new();
	}
	
	if (conn->state == STATE_CONNECTED) {
		callback(0, packet, self);
		ret = 0;
	} else {
		//ship_list_add(conn->connection_waiters, [ packet, callback ]);
		
		/* if not in the process of connecting, do it now! */

	}

	ret = 1;
	ship_unlock(tcp->connections);



	ASSERT_TRUE(ptr = ship_pack("ppp", self, packet, callback), err);
	if ((addr = ident_get_transport_params(packet->ident, packet->to, self->name))) {
		_trans_tcp_connect_cb(addr, ptr);
		freez(addr);
	} else {
		/* get the transport addresses for this one */
		ASSERT_ZERO(ident_update_transport_params(packet->ident, packet->to, self->name,
							  _trans_tcp_connect_cb, ptr), err);
	}
	ptr = 0;
	ret = 0;
 err:
	ship_pack_free(ptr);
	return ret;
}

static int 
trans_tcp_is_connected(conn_transport_handler_t *self, const char *sip_aor)
{
	struct trans_tcp_transport_s *tcp = (struct trans_tcp_transport_s*)self;
	int ret = 0;
	conn_connection_t *conn;
	
	LOG_HL("is connected to %s\n", sip_aor);
	ship_lock(tcp->connections);
	conn = ship_ht_get_string(tcp->connections, sip_aor);
	if (conn && conn->state == STATE_CONNECTED)
		ret = 1;
	ship_unlock(tcp->connections);
	return ret;
}

static int 
trans_tcp_disconnect(conn_transport_handler_t *self, const char *sip_aor)
{
	struct trans_tcp_transport_s *tcp = (struct trans_tcp_transport_s*)self;
	conn_connection_t *conn;

	LOG_HL("disconnect %s\n", sip_aor);
	ship_lock(tcp->connections);
	if ((conn = ship_ht_remove_string(tcp->connections, sip_aor))) {
		conn_connection_free(conn);
	}
	ship_unlock(tcp->connections);
	return 0;
}

static int 
trans_tcp_is_fast(conn_transport_handler_t *self, const char *sip_aor)
{
	return 1;
}

static int
trans_tcp_is_slow(conn_transport_handler_t *self, const char *sip_aor)
{
	return 0;
}

static int
trans_tcp_send(conn_transport_handler_t *self, conn_packet_t *packet, 
	       conn_transport_handler_cb callback)
{
	LOG_HL("send to %s\n", packet->to);
	return -1;
}

static void
trans_tcp_close_instance(conn_transport_handler_t *self)
{
	struct trans_tcp_transport_s *tcp = (struct trans_tcp_transport_s*)self;
	conn_connection_t *conn;

	LOG_HL("closing instance\n");
	ship_lock(tcp->connections);
	while ((conn = ship_ht_pop(tcp->connections))) {
		conn_connection_free(conn);
	}
	ship_ht_free(tcp->connections);
	freez(self);
}

static char* 
trans_tcp_get_transport_address(conn_transport_handler_t *self)
{
	return strdup("123.4.2.3:2334");
}

/*
 * dummy (testing) transport
 */
static int trans_dummy_init();
static void trans_dummy_close();
static conn_transport_handler_t *trans_dummy_new_instance(ident_t *ident);
static int trans_dummy_connect(conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback);
static int trans_dummy_is_connected(conn_transport_handler_t *self, const char *sip_aor);
static int trans_dummy_disconnect(conn_transport_handler_t *self, const char *sip_aor);
static int trans_dummy_is_fast(conn_transport_handler_t *self, const char *sip_aor);
static int trans_dummy_is_slow(conn_transport_handler_t *self, const char *sip_aor);
static int trans_dummy_send(conn_transport_handler_t *self, conn_packet_t *packet, 
			    conn_transport_handler_cb callback);
static void trans_dummy_close_instance(conn_transport_handler_t *self);
static char* trans_dummy_get_transport_address(conn_transport_handler_t *self);

static conn_transport_handler_t trans_dummy_transport =
	{
		.name = "dummy",
		
		.init = trans_dummy_init,
		.close = trans_dummy_close,
		.new_instance = trans_dummy_new_instance,
		
		.connect = trans_dummy_connect,
		.is_connected = trans_dummy_is_connected,
		.disconnect = trans_dummy_disconnect,
		
		.is_fast = trans_dummy_is_fast,
		.is_slow = trans_dummy_is_slow,
		
		.send = trans_dummy_send,
		
		.close_instance = trans_dummy_close_instance,
		
		.get_transport_address = trans_dummy_get_transport_address,
	};

static int
trans_dummy_init()
{
	LOG_HL("initing dummy transport\n");
	return 0;
}

static void 
trans_dummy_close()
{
	LOG_HL("closing dummy transport\n");
}

static conn_transport_handler_t*
trans_dummy_new_instance(ident_t *ident)
{
	conn_transport_handler_t *ret = 0;
	LOG_HL("new instance for %s\n", ident->sip_aor);
	ASSERT_TRUE(ret = mallocz(sizeof(*ret)), err);
	memcpy(ret, &trans_dummy_transport, sizeof(*ret));
	return (conn_transport_handler_t*)ret;
 err:
	trans_dummy_close_instance((conn_transport_handler_t*)ret);
	return NULL;
}

static int 
trans_dummy_connect(conn_transport_handler_t *self, conn_packet_t *packet, conn_transport_handler_cb callback)
{
	LOG_HL("connect to %s\n", packet->to);
	return -1;
}

static int 
trans_dummy_is_connected(conn_transport_handler_t *self, const char *sip_aor)
{
	LOG_HL("is connected to %s\n", sip_aor);
	return 0;
}

static int 
trans_dummy_disconnect(conn_transport_handler_t *self, const char *sip_aor)
{
	LOG_HL("disconnect %s\n", sip_aor);
	return -1;
}

static int 
trans_dummy_is_fast(conn_transport_handler_t *self, const char *sip_aor)
{
	return 1;
}

static int
trans_dummy_is_slow(conn_transport_handler_t *self, const char *sip_aor)
{
	return 0;
}

static int
trans_dummy_send(conn_transport_handler_t *self, conn_packet_t *packet, 
	       conn_transport_handler_cb callback)
{
	LOG_HL("send to %s\n", packet->to);
	return -1;
}

static void
trans_dummy_close_instance(conn_transport_handler_t *self)
{
	LOG_HL("closeing instance\n");
	freez(self);
}

static char* 
trans_dummy_get_transport_address(conn_transport_handler_t *self)
{
	return strdup("dummy-stuff");
}	

/* registers the transports */
int
trans_tcp_register()
{
	conn_register_transport(&trans_dummy_transport);
	return conn_register_transport(&trans_tcp_transport.handler);
}



#endif
