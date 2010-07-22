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

} 
conn_connection_t;


/* connection state */
enum {
        STATE_ERROR = -1,
        STATE_CLOSED = 0,
        STATE_INIT = 1,
        STATE_CONNECTED = 2,
        STATE_CONNECTING = 3,
        STATE_CLOSING = 4
};

/* package types */
enum {
        PKG_UNKNOWN = 0,
        PKG_REG = 81,
        PKG_TARGET = 82,
        PKG_SIP = 84,
        PKG_MP = 85,
        PKG_TRUST = 86,
	PKG_PING = 87,
        PKG_SERVICE = 88
};

#define CONN_MAX_PKG_LEN 64000
#define CONN_MAX_PKG_CONTENT_LEN (CONN_MAX_PKG_LEN - 3)
#define CONN_MAX_PKG_SERVICE_CONTENT_LEN (CONN_MAX_PKG_CONTENT_LEN - 4)

#define CONN_SERVICE_SPLIT_HEADER_LEN (4+4+4+1)
#define CONN_SERVICE_NORMAL_HEADER_LEN (1)

int conn_open_connection_to(char *sip_aor, ident_t *ident, processor_task_t **wait);
int conn_send_sip_to(char *sip_aor, ident_t *ident, char *buf, size_t len);
int conn_init(processor_config_t *config);
void conn_register();
void conn_close();
int conn_stosa(char *str, struct sockaddr **addr, socklen_t *len);
int conn_get_publicip(addr_t *addr);
int conn_validate_ifaces(char **ifaces, int c);
int conn_getips_af(ship_list_t *ips, char **ifaces, int ifaces_len, int port, const int af);
int conn_getips(ship_list_t *ips, char **ifaces, int c, int port);
int conn_queue_to_peer(char *to, char *from, 
		       service_type_t service,
		       char *data, int data_len,
		       void *ptr, void (*callback) (char *to, char *from, service_type_t service,
						    char *data, int data_len, void *ptr,
						    int code));
int conn_resend_reg_pkg(ident_t *ident);
int conn_fill_reg_package(reg_package_t *pkg);
int conn_can_connect_to(reg_package_t *pkg);
int conn_getips(ship_list_t *ips, char **ifaces, int c, int port);
int conn_get_lo(addr_t *addr);

int conn_send_mp_to(char *sip_aor, ident_t *ident,
		    char *source_addr, int source_port,
		    char *target_addr, int target_port,
		    char *callid,
		    char *buf, size_t len);


#ifdef CONFIG_HIP_ENABLED	
int conn_create_peer_hit_locator_mapping(char *sip_aor, addr_t *hit);
int conn_connection_uses_hip(char *remote_aor, char *local_aor);
#endif

void conn_get_connected_peers(char *sip_aor, ship_list_t *ret);

#endif
