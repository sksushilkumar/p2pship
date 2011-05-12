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
#ifndef __SIPP_MP_H__
#define __SIPP_MP_H__

#include <netinet/in.h>
#include "ident.h"

/* timeout for mps, in seconds */
#define MP_DEAD_TO (30*60)

/* whether to print media proxy debugging to stderr */
//#define MP_DEBUG 1

/* data struct for mps */
struct sipp_media_proxy_s
{
        addr_t remote_addr;
        addr_t local_addr;
        
        int socket;
        char *sip_aor; /* our own! */
        char *remote_aor;

        /* some sort of timestamp for when last heard so we can remove
           dead proxies.. */
        time_t last;
        time_t start_time;

        /* meta data */
        char *mediatype;
        char *callid;

        /* ..start? */
        int started;

	/* how to send the packets */
	int sendby;
	
	/* counter of bytes sent */
	int counter;

	/* flag whether the recipient supports fragments */
	int frag_support;
};

typedef struct sipp_media_proxy_s sipp_media_proxy_t;

/* how the data should be sent to the peer, directly or through the
   conn tunnel */
#define SIPP_MP_SENDBY_NONE 0
#define SIPP_MP_SENDBY_DIRECT 1
#define SIPP_MP_SENDBY_TUNNEL 2

/* creates a new one */
sipp_media_proxy_t *
sipp_mp_create_new(char *callid, char *local_aor, char *remote_aor, char *mediatype, 
                   addr_t *bindaddr, addr_t *targetaddr, int sendby);
     
/* cleans up all proxies for the given identity */
void sipp_mp_clean_by_id(char * ident);
void sipp_mp_clean_by_call(char * callid);

/* releases the media proxy */
void sipp_mp_free(sipp_media_proxy_t *mp);

/* just sets the target */
int sipp_mp_set_target(sipp_media_proxy_t *mp, addr_t *targetaddr);

/* starts the media proxy */
int sipp_mp_start(sipp_media_proxy_t *mp, int remotely_got);

/* stops the media proxy */
int sipp_mp_stop(sipp_media_proxy_t *mp);

/* stops & releases the media proxy */
void sipp_mp_close(sipp_media_proxy_t *mp);

/* stops & releases all media proxy */
void sipp_mp_close_all();

int sipp_mp_init();
void sipp_mp_close_sys();

/* calls to route traffic */
int sipp_mp_route(char *source_aor, char *target_aor,
                  char *source_addr, int source_port,
                  char *target_addr, int target_port,
                  char *callid,
                  char *data, int datalen);

sipp_media_proxy_t *sipp_mp_find(char *callid, addr_t *target_addr, int sendby);

/* finds by target */
sipp_media_proxy_t *sipp_mp_find_by_source(char *addr, int port);

/* finds by socket */
sipp_media_proxy_t *sipp_mp_find_by_socket(int socket);

sipp_media_proxy_t *sipp_mp_find_by_callid(char *callid);

int sipp_mp_dump_json(char **msg);


#endif
