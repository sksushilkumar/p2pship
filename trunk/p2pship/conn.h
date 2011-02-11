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
/*
 * Module for managing the connections to peers. Sort of an adapter
 * between the ident module and the hip api (and the sipp)
 */
#ifndef __CONN_H__
#define __CONN_H__

#include <sys/socket.h> 

#include "processor_config.h"
#include "processor.h"
#include "ship_utils.h"
#include "ident.h"
#include "ident_addr.h"

//#define OLD_QUEUE 1

/* how many packets can be queued for one connection */
#define CONN_IN_QUEUE_LIMIT 10

/* struct for holding info regarding to whom we are trying to
   establish connections, to who we alread have etc.. */
typedef struct conn_connection_s {
	ship_obj_t parent;

        int state;
        char *sip_aor;
        char *local_aor;

	/* this contains the UN locked ident while processing some received packet */
 	ident_t *ident;

        struct sockaddr *sa;
        socklen_t addrlen;
        int socket;
        
        /* the in-queue */
        ship_list_t *in_queue;

	/* dummy to get a lock */
	ship_list_t *processing;

        processor_task_t *wait;
        processor_task_t *subwait;

	/* the last-heard values. first for *anything* */
	time_t last_heard;
	
	/* the second for anything useful - close if the conn hasn't
	   been used for anything useful for a while */
	time_t last_content;

	/* the time when the previous packet of *anything* was sent on this socket */
	time_t last_sent;

	/* a byte counter for all the bytes sent / rec'd */
	int sent_data;
	int rec_data;

	/* fragments collected during .. */
	ship_ht_t *fragments;

	/* the last addr used. This is NOT owned by this, just used for pointer comparison! */
	void *last_addr;
} 
conn_connection_t;


/* connection state */
enum {
        STATE_ERROR = -1,
        STATE_CLOSED = 0, // when created
        STATE_INIT = 1, // when first received
        STATE_CONNECTED = 2, // handshake done
        STATE_CONNECTING = 3, // when establishing a connection
        STATE_CLOSING = 4
};

/* package types */
enum {
        PKG_UNKNOWN = 0,
        PKG_REG = 81,
        PKG_TARGET = 82,
        /* PKG_SIP = 84, // should be service */
        PKG_MP = 85, // shouldn't exist. or 'tunnel' more generically
/*         PKG_TRUST = 86, // should be service */
	PKG_PING = 87,
        PKG_SERVICE = 88
};

#ifdef OLD_QUEUE
#define CONN_PKG_LEN_LEN 2
#define CONN_MAX_PKG_LEN 64000
#else
#define CONN_PKG_LEN_LEN 4
#define CONN_MAX_PKG_LEN 0x0fffffff
#endif
#define CONN_MAX_PKG_CONTENT_LEN (CONN_MAX_PKG_LEN - 3)
#define CONN_MAX_PKG_SERVICE_CONTENT_LEN (CONN_MAX_PKG_CONTENT_LEN - 4)

#define CONN_SERVICE_SPLIT_HEADER_LEN (4+4+4+1)
#define CONN_SERVICE_NORMAL_HEADER_LEN (1)

/* sending flags */
#define CONN_SEND_SECURE        1
#define CONN_SEND_PREFER_SLOW   2
#define CONN_SEND_REQUIRE_FAST  4


/*
 * module init
 */
void conn_register();
int conn_init(processor_config_t *config);
void conn_close();

/* the callback function type */
typedef void (*conn_packet_callback) (char *to, char *from, service_type_t service,
				      int code, char *return_data, int data_len,
				      void *ptr);

/*
 * sending service packets
 */
int conn_send(int flags, /* ALLOW_DELAYED, PREFER_DELAYED, SECURE?... */
	      char *to, char *from,
	      service_type_t service,
	      char *data, int data_len,
	      void *ptr, conn_packet_callback callback); /* code: fail, sent, pending */

/* try to establish a fast connection, else use slow */
int conn_send_default(char *to, char *from,
		      service_type_t service,
		      char *data, int data_len,
		      void *ptr, conn_packet_callback callback);

/* send on fast if connected, else use slow (if possible). else establish fast */
int conn_send_slow(char *to, char *from,
		   service_type_t service,
		   char *data, int data_len,
		   void *ptr, conn_packet_callback callback);

/* send on fast only, return error if a connection couldn't be established */
int conn_send_fast(char *to, char *from,
		   service_type_t service,
		   char *data, int data_len,
		   void *ptr, conn_packet_callback callback);

/* send IF connected, nodelay, don't care whether it is delivered; best-effort */
int conn_send_simple(char *to, char *from,
		     service_type_t service,
		     char *data, int data_len);

/*
 * dtn: pipes, dedicated connections: 
 *
 * dtn: stream_descriptor is the one returned by the above. it is formatted as:
 * stream_type1;stream_type2; etc..
 * e.g.,
 * hip+tcp:[2001:00:001]:1234;tls:128.2.1.3:2000
 * etc
 */
char* conn_accept(const int flags, /* CS_SECURE, CS_STREAM, CS_PACKET, .. */
		  ident_t *ident, void *obj,
		  void (*callback) (int socket,
				    const char *from, const char *to,
				    void *obj));

int conn_open(const char *stream_descriptor,
	      void *obj,
	      void (*conn_cb) (int s, void *obj),
	      void (*data_cb) (int s, void *obj, char *data, int datalen));

/* dtn: fill with all connection type addresses */
int conn_fill_reg_package(ident_t *ident, reg_package_t *pkg);
int conn_can_connect_to(reg_package_t *pkg);
void conn_get_connected_peers(char *sip_aor, ship_list_t *ret);


/* 
 * utility functions. could be in netio actually
 */
int conn_get_publicip(addr_t *addr);
int conn_validate_ifaces(char **ifaces, int c);
int conn_getips_af(ship_list_t *ips, char **ifaces, int ifaces_len, int port, const int af);
int conn_getips(ship_list_t *ips, char **ifaces, int c, int port);
int conn_get_lo(addr_t *addr);
int conn_can_send_to(addr_t *from, addr_t *to);

/* weird little one that should be obsoleted */
int conn_send_mp_to(char *sip_aor, ident_t *ident,
		    char *source_addr, int source_port,
		    char *target_addr, int target_port,
		    char *callid,
		    char *buf, size_t len);

#ifdef CONFIG_HIP_ENABLED	
int conn_connection_uses_hip(char *remote_aor, char *local_aor);
#endif

/*
 * data packet 
 */
typedef struct conn_packet_s {
	ship_obj_t parent;

	char *to;
	char *from;
	ident_t *ident;

	int type;
	service_type_t service;
	char *data;
	int data_len;

	char *pkg_id;
	int flags;
	int is_ack;

	time_t sent;
	void *ptr;
	conn_packet_callback callback;
	int code;

	char *return_data;
	int return_data_len;

} conn_packet_t;

SHIP_INCLUDE_TYPE(conn_packet);
int conn_packet_serialize(conn_packet_t *p, char **retv, int *len);

#endif
