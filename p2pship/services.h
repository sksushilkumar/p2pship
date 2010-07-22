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
#ifndef __SERVICES_H__
#define __SERVICES_H__

#define SERVICE_TYPE_NONE 0
#define SERVICE_TYPE_SIP 1
#define SERVICE_TYPE_HTTP 2
#define SERVICE_TYPE_HTTPRESPONSE 3
#define SERVICE_TYPE_STATS 4
#define SERVICE_TYPE_MP_INFO 5
#define SERVICE_TYPE_PRIVACYPAIRING 6
#define SERVICE_TYPE_RESOURCEFETCH 7
#define SERVICE_TYPE_BLOOMBUDDIES 8

typedef int service_type_t;

#define service_create_id(service, subservice) ((service << 16) | (subservice & 0xffff))
#define service_id(fullid) ((fullid >> 16) & 0xffff)
#define service_subid(fullid) (fullid & 0xffff)

typedef struct service_s 
{
	/* data received from ..far away. */
 	int (*data_received) (char *data, int data_len, ident_t *target, char *source, service_type_t service_type);

	/* this notifies the service handler that the service is being closed */
	void (*service_closed) (service_type_t service_type, ident_t *ident, void *pkg);

	/* this is the unique id for this service handler */
	char *service_handler_id;

} service_t;

service_type_t service_str_to_type(char *service);

#endif
