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
#include "sipp_mp.h"
#include "ship_utils.h"
#include "ship_debug.h"
#include "ident.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "services.h"
#include "conn.h"
#include "netio.h"

extern ship_list_t *sipp_mps;
static ship_list_t *mp_infos = 0;

/* whether to use the FF direct interface or not */
#define USE_FF_DIRECT 1

static char *
sipp_mp_create_mp_info_str(char *aor, addr_t *addr)
{
	char *buf = 0;
	if ((buf = mallocz(strlen(aor) + strlen(addr->addr) + 32))) {
		strcpy(buf, aor);
		strcat(buf, ";[");
		strcat(buf, addr->addr);
		strcat(buf, "]:");
		sprintf(buf+strlen(buf), "%d", addr->port);
	}
	return buf;
}

static int
sipp_mp_info_handle_message(char *data, int data_len, 
			    ident_t *target, char *source, 
			    service_type_t service_type)
{
	char *pos = strchr(data, ';');
	if (pos && !strncmp(data, source, pos-data)) {
		char *tmp = 0;
		LOG_DEBUG("got mp fragmentation support notification: %s\n", data);
		if ((tmp = mallocz(data_len+1))) {
			memcpy(tmp, data, data_len);
			ship_list_add(mp_infos, tmp);

			
			/* this isn't perfect, but good enought for now */
			while (ship_list_length(mp_infos) > 10)
				free(ship_list_pop(mp_infos));
		}
	}
	return 0;
}

static struct service_s sipp_mp_info_service =
	{
		.data_received = sipp_mp_info_handle_message,
		.service_closed = 0,
		.service_handler_id = "sipp_mp_info_service"
	};

int 
sipp_mp_init()
{
	ident_register_default_service(SERVICE_TYPE_MP_INFO, &sipp_mp_info_service);
	ASSERT_TRUE(mp_infos = ship_list_new(), err);
	
	return 0;
 err:
	return -1;
} 

void
sipp_mp_close_sys()
{
	if (mp_infos) {
		ship_list_empty_free(mp_infos);
		ship_list_free(mp_infos);
	}
}

/* releases the media proxy */
void 
sipp_mp_free(sipp_media_proxy_t *mp)
{
        if (!mp)
                return;
        
        LOG_INFO("freeing mp for %s (%s:%d -> %s:%d)..\n", mp->sip_aor, 
                 mp->local_addr.addr, mp->local_addr.port,
                 mp->remote_addr.addr, mp->remote_addr.port);
	
        freez(mp->sip_aor);
        freez(mp->remote_aor);
        freez(mp->mediatype);
        freez(mp->callid);
        free(mp);
}

/* cleans up all proxies for the given identity */
void 
sipp_mp_clean_by_id(char *aor)
{
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                void *prev = NULL;
                sipp_media_proxy_t *mp;
                
                while ((mp = ship_list_next(sipp_mps, &ptr))) {
                        if (!strcmp(aor, mp->sip_aor)) {
                                ship_list_remove(sipp_mps, mp);
                                sipp_mp_close(mp);
                                ptr = prev;
                        } else {
                                prev = ptr;
                        }
                }
        } ship_unlock(sipp_mps);
}

/* cleans up all proxies for the given call */
void 
sipp_mp_clean_by_call(char* callid)
{
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                void *prev = NULL;
                sipp_media_proxy_t *mp;
                
                while ((mp = ship_list_next(sipp_mps, &ptr))) {
                        if (!strcmp(mp->callid, callid)) {
                                ship_list_remove(sipp_mps, mp);
                                sipp_mp_close(mp);
                                ptr = prev;
                        } else {
                                prev = ptr;
                        }
                }
        } ship_unlock(sipp_mps);
}

sipp_media_proxy_t *
sipp_mp_find(char *callid, addr_t *target_addr, int sendby)
{
	sipp_media_proxy_t * mp = 0;
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                
                while (!mp && (mp = ship_list_next(sipp_mps, &ptr))) {
                        if (strcmp(mp->callid, callid) ||
			    mp->sendby != sendby ||
			    ident_addr_cmp(target_addr, &(mp->remote_addr))) {
				mp = 0;
			}
		}
	} ship_unlock(sipp_mps);

	return mp;
}


/* does some periodic cleanups of dead proxies */
/* this isn't used right now.. 
void
sipp_mp_autoclean()
{
        void *ptr = NULL, *prev = NULL;
        sipp_media_proxy_t *mp;
	time_t now;
	time(&now);
	
        ship_list_sync(sipp_mps, {
                while (mp = ship_list_next(sipp_mps, &ptr)) {
                        if ((now - mp->last) > MP_DEAD_TO) {
                                ship_list_remove(sipp_mps, mp);
                                sipp_mp_close(mp);
                                ptr = prev;
                        } else
                                prev = ptr;
                }
        });
}
*/

static void 
sipp_mp_cb_data_got(int s, char *data, size_t len,
                    struct sockaddr *sa, socklen_t addrlen)
{
        sipp_media_proxy_t *mp;
	int err = 0;
        if ((mp = sipp_mp_find_by_socket(s))) {
                ident_t *ident;

                if (!mp->started)
                        return;
		
		switch (mp->sendby) {
#ifndef USE_FF_DIRECT
		case SIPP_MP_SENDBY_DIRECT: 
			{
				struct sockaddr *tsa;
				socklen_t tsa_len;
				if (ident_addr_addr_to_sa(&(mp->remote_addr), &tsa, &tsa_len) ||
				    netio_packet_anon_send(data, len, tsa, tsa_len) == -1)
					err = -1;
				
				freez(tsa);
				break;
			}
#endif			
		case SIPP_MP_SENDBY_TUNNEL: 
			if ((ident = ident_find_by_aor(mp->sip_aor))) {
				addr_t addr;
				if (!ident_addr_sa_to_addr(sa, len, &addr) &&
				    conn_send_mp_to(mp->remote_aor, ident,
						    addr.addr, addr.port,
						    mp->remote_addr.addr, mp->remote_addr.port,
						    mp->callid,
						    data, len))
					err = -1;
				ship_obj_unlockref(ident);
			}
			break;
		default:
			err = -1;
			LOG_WARN("invalid send route for proxy\n", len);
			break;
		}
	
		if (err) {
			sipp_mp_close(mp);
		} else {
			mp->counter += len;
			time(&mp->last);
		}
		
        } else {
                LOG_WARN("got %d bytes for unknown media proxy\n", len);
        }
}
     
/* 
   Creates a new media proxy

   callid, local_aor, remote_aor should be clear
   mediatype is the mediatype (currently not used..)
   bindaddr is the address on which we should bind the listener
   targetaddr is where the media should be sent
   sendby indicates whether direct / through tunnel

 */
sipp_media_proxy_t *
sipp_mp_create_new(char *callid, char *local_aor, char *remote_aor, char *mediatype, 
                   addr_t *bindaddr, addr_t *targetaddr, int sendby)
{
        sipp_media_proxy_t *ret;
        struct sockaddr *sa = NULL;
        socklen_t size;

        ASSERT_TRUE(ret = (sipp_media_proxy_t *)mallocz(sizeof(sipp_media_proxy_t)), err);
        ASSERT_TRUE(ret->callid = strdup(callid), err);
        ASSERT_TRUE(ret->mediatype = strdup(mediatype), err);
	ret->sendby = sendby;
        time(&ret->last);

	memcpy(&(ret->local_addr), bindaddr, sizeof(addr_t));

        ASSERT_TRUE(ret->sip_aor = strdup(local_aor), err);
        ASSERT_TRUE(ret->remote_aor = strdup(remote_aor), err);
        if (targetaddr) {
		memcpy(&(ret->remote_addr), targetaddr, sizeof(addr_t));
        } else {
		bzero(&(ret->remote_addr), sizeof(addr_t));
	}

	/* todo: this doesn't work for tcp or anything else */
	ASSERT_TRUE(ret->local_addr.type == IPPROTO_UDP, err);
	ASSERT_ZERO(ident_addr_addr_to_sa(&(ret->local_addr), &sa, &size), err);
	ret->socket = netio_new_packet_socket(sa, size);
        if (ret->socket == -1)
                goto err;
	
	ASSERT_ZERO(getsockname(ret->socket, sa, &size), err);
	ASSERT_ZERO(ident_addr_sa_to_addr(sa, size, &(ret->local_addr)), err);
	ret->local_addr.type = IPPROTO_UDP;

	ship_list_add(sipp_mps, ret);

	freez(sa);
        return ret;
 err:
	freez(sa);
        sipp_mp_close(ret);
        return 0;
}


static int
sipp_mp_supports_fragmentation(char *remote_aor, addr_t *addr)
{
	int ret = 0;
	char *line, *tmp;
	void *ptr = 0;

	if (!(tmp = sipp_mp_create_mp_info_str(remote_aor, addr)))
		return 0;

	ship_lock(mp_infos);
	while (!ret && (line = ship_list_next(mp_infos, &ptr))) {
		if (!strcmp(line, tmp)) {
			ret = 1;
		}
	}
	ship_unlock(mp_infos);
	freez(tmp);
	return ret;
}

static int
sipp_mp_notify_fragmentation_support(sipp_media_proxy_t *mp)
{
	char *buf = 0;
	int ret = -1;
	if ((buf = sipp_mp_create_mp_info_str(mp->sip_aor, &mp->local_addr))) {
		LOG_DEBUG("sending mp support on %s\n", buf);
		ret = conn_queue_to_peer(mp->remote_aor, mp->sip_aor,
					 SERVICE_TYPE_MP_INFO,
					 buf, strlen(buf)+1,
					 NULL, NULL);
		freez(buf);
	}
	
	return ret;
}		




/* just sets the target */
int
sipp_mp_set_target(sipp_media_proxy_t *mp, addr_t *targetaddr)
{
	memcpy(&(mp->remote_addr), targetaddr, sizeof(addr_t));
	return 0;
}

/* starts the media proxy */
int 
sipp_mp_start(sipp_media_proxy_t *mp, int remotely_got)
{
        LOG_INFO("starting mp (type %d) for %s (%s:%d -> %s:%d)..\n", 
		 mp->sendby, mp->sip_aor, 
                 mp->local_addr.addr, mp->local_addr.port,
                 mp->remote_addr.addr, mp->remote_addr.port);

	if (remotely_got && sipp_mp_supports_fragmentation(mp->remote_aor, &(mp->remote_addr))) {
		mp->frag_support = 1;
		LOG_DEBUG("detected fragmentation-aware endpoint at %s:%d!\n",
			  mp->remote_addr.addr, mp->remote_addr.port);
	}
	
	/* start reading packets */
	switch (mp->sendby) {
	case SIPP_MP_SENDBY_DIRECT:
#ifdef USE_FF_DIRECT
		ASSERT_ZERO(netio_ff_add(mp->socket, &(mp->remote_addr), &(mp->counter),
					 mp->frag_support), err);
		break;
#endif
	default:
		ASSERT_ZERO(netio_packet_read(mp->socket, sipp_mp_cb_data_got), err);
	}
	
	mp->started = 1;
	time(&mp->start_time);

	if (!remotely_got) {
		LOG_DEBUG("sending fragmentation-support flag for the proxy at %s:%d\n", 
			  mp->local_addr.addr, mp->local_addr.port);
		
		sipp_mp_notify_fragmentation_support(mp);
	}
	return 0;
 err:
	return -1;
}

/* calls to route traffic */
int
sipp_mp_route(char *source_aor, char *target_aor,
              char *source_addr, int source_port,
              char *target_addr, int target_port,
              char *callid,
              char *data, int datalen)
{
	int ret = -1;
	struct sockaddr *sa = 0;
	socklen_t sa_len;
	addr_t addr;
	addr_t *addrptr = 0;
	
	/* todo: we should somehow check whether the remote peer is
	   authorized to send to the given address packets */
	
	/* no accesscontrol here for now .. we can spam just about any
	   machine in our intranet through this tunnel stuff */
	
	/* we should search if we have a mediaproxy that listens to
	   the address that this one sends to */

	/* todo: this should sync around the mp after getting finding it */
        sipp_media_proxy_t *mp = NULL;
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                while (!mp && (mp = ship_list_next(sipp_mps, &ptr))) {
			if (strcmp(mp->local_addr.addr, target_addr) || 
			    mp->local_addr.port != target_port)
                                mp = NULL;
		}
        } ship_unlock(sipp_mps);

	if (mp) {
		addrptr = &(mp->remote_addr);
	} else if (!ident_addr_str_to_addr(target_addr, &addr)) {
		addr.port = target_port;
		addrptr = &addr;
	}
	
	if (addrptr && !ident_addr_addr_to_sa(addrptr, &sa, &sa_len)) {			
		ret = netio_packet_anon_send(data, datalen, sa, sa_len);
		if (ret != -1)
			ret = 0;
	}
	freez(sa);

	if (ret) {
		LOG_WARN("invalid mediaproxy packet got\n");
	}
        return ret;
}

/* finds by callid */
sipp_media_proxy_t *
sipp_mp_find_by_callid(char *callid)
{
        sipp_media_proxy_t *mp = NULL;
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                while (!mp && (mp = ship_list_next(sipp_mps, &ptr)))
                        if (strcmp(mp->callid, callid))
                                mp = NULL;
        } ship_unlock(sipp_mps);
        return mp;
}

/* finds by target */
sipp_media_proxy_t *
sipp_mp_find_by_source(char *addr, int port)
{
        sipp_media_proxy_t *mp = NULL;
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                while (!mp && (mp = ship_list_next(sipp_mps, &ptr)))
                        if (mp->remote_addr.port != port || !strcmp(addr, mp->remote_addr.addr))
                                mp = NULL;
        } ship_unlock(sipp_mps);

        return mp;
}

/* finds by socket */
sipp_media_proxy_t *
sipp_mp_find_by_socket(int socket)
{
        sipp_media_proxy_t *mp = NULL;
        ship_lock(sipp_mps); {
                void *ptr = NULL;
                while (!mp && (mp = ship_list_next(sipp_mps, &ptr)))
                        if (mp->socket != socket)
                                mp = NULL;
        } ship_unlock(sipp_mps);

        return mp;
}


/* stops & releases the media proxy */
void 
sipp_mp_close(sipp_media_proxy_t *mp)
{
        /* close socket, remove from list */
	ship_list_remove(sipp_mps, mp);
        
	switch (mp->sendby) {
	case SIPP_MP_SENDBY_DIRECT:
#ifdef USE_FF_DIRECT
		netio_ff_remove(mp->socket);
		break;
#endif
	default:
		netio_close_socket(mp->socket);
/* 		netio_remove(mp->socket); */
	}

        sipp_mp_free(mp);
}

/* stops & releases all media proxy */
void 
sipp_mp_close_all()
{        
	ship_list_empty_with(sipp_mps, sipp_mp_close);
}


static const char* SIPP_MP_SENDBY_NONE_STR = "none";
#ifndef USE_FF_DIRECT
static const char* SIPP_MP_SENDBY_DIRECT_STR = "direct";
#else
static const char* SIPP_MP_SENDBY_DIRECT_STR = "direct_ff";
#endif
static const char* SIPP_MP_SENDBY_TUNNEL_STR = "tunnel";
static const char* SIPP_MP_SENDBY_UNKNOWN_STR = "none";

/* returns just a string-description of the current send-by status */
static const char *
sipp_mp_sendby_str(int sendby)
{
	switch (sendby) {
	case SIPP_MP_SENDBY_NONE:
		return SIPP_MP_SENDBY_NONE_STR;
	case SIPP_MP_SENDBY_DIRECT:
		return SIPP_MP_SENDBY_DIRECT_STR;
	case SIPP_MP_SENDBY_TUNNEL:
		return SIPP_MP_SENDBY_TUNNEL_STR;
	default:
		return SIPP_MP_SENDBY_UNKNOWN_STR;
	}

}

/* dumps the current status of all mediaproxies as a json blob */
int
sipp_mp_dump_json(char **msg)
{
	int buflen = 0, datalen = 0;
	char *buf = 0;
	void *ptr = 0, *ptr2 = 0;
        sipp_media_proxy_t *mp = NULL;
	char *tmpaddr1 = 0, *tmpaddr2 = 0, *tmp = 0;
	ship_list_t *callids = 0;
	char *str = 0;
	int ret = -1;
	ship_lock(sipp_mps);
	
	/* collect callids */
	ASSERT_TRUE(callids = ship_list_new(), err);
	while ((mp = ship_list_next(sipp_mps, &ptr))) {
		int found = 0;
		while (!found && (str = ship_list_next(callids, &ptr2))) {
			if (!strcmp(str, mp->callid))
				found = 1;
		}
		
		if (!found) {
			ship_list_add(callids, mp->callid);
		}
	}
	
	/* for each call id .. */
	ASSERT_TRUE(buf = append_str("var p2pship_mps = {\n", buf, &buflen, &datalen), err);
	ptr2 = 0;
	while ((str = ship_list_next(callids, &ptr2))) {
		ASSERT_TRUE(buf = append_str("     \"", buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str(str, buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str("\" : [\n", buf, &buflen, &datalen), err);

		ptr = 0;
		while ((mp = ship_list_next(sipp_mps, &ptr))) {
			int len = 0;
			
			if (!strcmp(mp->callid, str)) {
				ASSERT_ZERO(ident_addr_addr_to_str(&(mp->local_addr), &tmpaddr1), err);
				ASSERT_ZERO(ident_addr_addr_to_str(&(mp->remote_addr), &tmpaddr2), err);
				
				len = zstrlen(mp->sip_aor) + zstrlen(tmpaddr1) + zstrlen(mp->remote_aor) + zstrlen(tmpaddr2) + 
					zstrlen(mp->callid) + zstrlen(mp->mediatype) + 512;
				ASSERT_TRUE(tmp = mallocz(len), err);
				
				sprintf(tmp, "         [ \"%s\", \"%s\", \"%s\", \"%s\", \"%s\",\n           \"%s\", \"%s\", \"%d\", \"%d\", \"%d\", \"%d\" ],\n",
					mp->sip_aor, tmpaddr1, mp->remote_aor, tmpaddr2, sipp_mp_sendby_str(mp->sendby),
					mp->callid, mp->mediatype,
					mp->started, (int)mp->start_time, (int)mp->last, mp->counter);
				
				ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
				freez(tmp);
				freez(tmpaddr1);
				freez(tmpaddr2);
			}
		}
		ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
		ASSERT_TRUE(buf = append_str("     ],\n", buf, &buflen, &datalen), err);
	}

	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("};\n", buf, &buflen, &datalen), err);
	*msg = buf;
	buf = 0;
	ret = 0;
 err:
	ship_unlock(sipp_mps);
	ship_list_free(callids);
	freez(buf);
	freez(tmpaddr1);
	freez(tmpaddr2);
	freez(tmp);
	return ret;
}
