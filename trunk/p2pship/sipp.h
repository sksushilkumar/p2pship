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
#ifndef __SIPP_H__
#define __SIPP_H__

#ifdef CONFIG_SIP_ENABLED

#include <pthread.h>
#include "processor_config.h"
#include <netinet/in.h>
#include <osipparser2/osip_message.h>
#include <osip2/osip.h>
#include "ident_addr.h"
#include "ident.h"

#ifdef HAVE_OSIP2_V3
#define OSIPMSG_PTR(arg) (&arg)
#else
#define OSIPMSG_PTR(arg) (arg)
#endif

/* the data needed for a single port listener */
typedef conn_listener_t sipp_listener_t;

/* a request, this is a ship_obj now */
typedef struct sipp_request_s
{
	ship_obj_t parent;

        osip_event_t *evt;        

	addr_t from_addr;

        sipp_listener_t *lis;

	char *local_aor;
	char *remote_aor;

} sipp_request_t;

SHIP_INCLUDE_TYPE(sipp_request);

/* inits & fires up the sip proxy sub-system */
int sipp_init(processor_config_t *config);

/* closes the sip proxy sub-system */
void sipp_close();

/* some sip-message related functions */
char *sipp_url_to_short_str(osip_uri_t *url);
char *sipp_get_call_id(osip_message_t *sip);


/* a log entry */
typedef struct call_log_entry_s {
	
	char *id;
	char *local_aor;
	char *remote_aor;
	
	/* initated by whom.. */
	int remotely_initiated;
	
	/* the verdict */
	int verdict;
	
	/* should these be here..? */
	int pathlen;

	/* last seen, started */
	time_t last_seen;
	time_t started;

} call_log_entry_t;

/* a struct describing a gateway to use for outgoing traffic */
typedef struct sipp_gateway_s {

	char *local_pattern; /* our identity */
	char *remote_pattern; /*  */

	char *gateway_ident_aor; /*  */

} sipp_gateway_t;

/* a struct describing routing of relayed traffic (by a gateway) */
typedef struct sipp_relay_s {

	char *ident_aor; /* the local ident for the gatewaying. could be *, but now just an ident! */

	char *local_pattern; /* for (to) whom should we relay */
	char *remote_pattern; /* who is allowed to use this relay - all right now */

	addr_t relay_addr; /* the address where to relay the packets */
} sipp_relay_t;

#endif
#endif
