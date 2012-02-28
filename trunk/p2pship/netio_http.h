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
#ifndef __NETIO_HTTP_H__
#define __NETIO_HTTP_H__

#include "ident_addr.h"
#include "ship_utils.h"
#include "services.h"

/* struct for holding one parameter */
typedef struct netio_http_param_s {
	char *name;
	char *data;
	int data_len;
} netio_http_param_t;

/* a conn struct */
typedef struct netio_http_conn_s {

	ship_lock_t lock;
	int socket;
	int owns_socket;

	/* the buf */
	char *buf;
	int data_len;
	int buf_len;

	/* the html heads */
	int content_len;
	int header_got;
	int header_len;

	/* the parameters of the connection */
	ship_ht_t *params;

	/* the other .. */
	addr_t addr;

	/* the headers */
	ship_ht_t *headers;
	char *url;
	char *original_url;
	char *url_extras;
	char *http_version;

	/** server-conn specifics */

	/* the server socket on which this was received */
	int ss;
	char *method;
	
	/** client-initiated specifics */

	void (*func) (char *url, int respcode, char *data, int data_len, void *pkg);
	void *pkg;

	/* connection- specifics, when initiating */
	char *host;
	char *fullurl;
	char *content_type;
	int resp_code;
	char *resp_code_line;
	
	/* the connection tracking id */
	char tracking_id[32];

	/* proxy forwarding */
	int forward_socket;	

	char *service_forward_to;
	char *service_forward_from;
	service_type_t service_forward_service;

	/* whether has been added to the conns tracking */
	int added;
} netio_http_conn_t;

/* struct holding a single server */
typedef struct netio_http_server_s {

	int s;
	int (*func) (netio_http_conn_t *conn, void *pkg);
	void *pkg;
	
} netio_http_server_t;




void netio_http_register();


/* functions */

ship_list_t *netio_http_conn_get_header_keys(netio_http_conn_t *conn);
ship_list_t *netio_http_conn_get_param_keys(netio_http_conn_t *conn);
char *netio_http_conn_get_param(netio_http_conn_t *conn, char *name);
void netio_http_respond(netio_http_conn_t *conn, 
			int code, char *code_str, 
			char *content_type,
			char *data, int data_len);
int netio_http_create_response(int code, char *code_str, 
			       char *content_type,
			       char *data, int data_len,
			       char **ret, int *retlen);

void netio_http_respond_str(netio_http_conn_t *conn, 
			    int code, char *code_str, 
			    char *data);

void netio_http_redirect(netio_http_conn_t *conn, 
			 char *url);

int netio_http_redirect_data(netio_http_conn_t *conn, int s);

int netio_http_server_create(char *address, 
			     int (*func) (netio_http_conn_t *conn, void *pkg),
			     void *pkg);

int netio_http_server_modif(int ss, char *new_address);

void netio_http_server_close(int ss);


#define netio_http_get_attr netio_http_get_header
#define netio_http_set_attr netio_http_set_header

netio_http_conn_t *netio_http_parse_data(char *data, int datalen);
netio_http_conn_t *netio_http_parse_header(char *data, int datalen);
netio_http_conn_t *netio_http_get_conn_by_id(const char *id);

int netio_http_get(char *url,
		   void (*func) (char *url, int respcode, char *data, int data_len, void *pkg),
		   void *pkg);

char *netio_http_get_header(netio_http_conn_t* conn, char *key);
int netio_http_set_header(netio_http_conn_t* conn, char *key, char *data);

int netio_http_post_host(char *host, char *path, char *urlstr, char *content_type, char *data, int data_len,
			 void (*func) (char *url, int respcode, char *data, int data_len, void *pkg),
			 void *pkg);
int netio_http_conn_set_param(netio_http_conn_t *conn, char *name, int namelen, char *value, int len);
void netio_http_respond_multipart(netio_http_conn_t *conn, 
				  char *content_type, 
				  char *data, int data_len);
void netio_http_conn_close(netio_http_conn_t *conn);
int netio_http_serialize(netio_http_conn_t* conn, char **ret, int *retlen);
int netio_http_serialize_payload(netio_http_conn_t* conn, char **ret, int *retlen);
void netio_http_packet_orderer_put(char *tracking_id, int piece, char *content, int len);
int netio_http_packet_orderer_pop_next(char *tracking_id, int *piece, char **content, int *len);
void netio_http_respond_html(netio_http_conn_t *conn, 
			     int code, char *code_str, 
			     char *data);
void netio_http_packet_orderer_create(char *tracking_id);
void netio_http_respond_auth(netio_http_conn_t *conn, 
			     char *realm,
			     char *content_type,
			     char *data);

#endif
