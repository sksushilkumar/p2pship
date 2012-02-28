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
#ifndef __EXT_API_H__
#define __EXT_API_H__

#include "ship_utils.h"

typedef struct extapi_http_req_s {

	char id[17]; // clumsy’ but ..
	char *request;
	int request_len;
	char *tracking_id;
	int piece_number;

	char *from_aor;
	char *to_aor;

	char *buf;
	int buf_len;
	int data_len;
	int is_connect;
	
	int s;
} extapi_http_req_t;

#ifdef CONFIG_HTTPPROXY_ENABLED
int extapi_register_p2phttp_handler(char *aor, const int dport, addr_t *addr, const int expire, 
				    int (*func) (netio_http_conn_t *conn, void *pkg, extapi_http_req_t* req), void *pkg);
#endif

void extapi_register();
extapi_http_req_t *extapi_get_http_req(const char *id);
void extapi_http_data_return(extapi_http_req_t *req, const char *data, int odatalen);

#endif
