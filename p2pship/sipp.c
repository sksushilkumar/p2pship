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
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <osipparser2/osip_message.h>
#include <osip2/osip.h>
#include <osipparser2/sdp_message.h>
#include <regex.h>
#include "sipp.h"
#include "ship_debug.h"
#include "ship_utils.h"
#include "processor.h"
#include "ident.h"
#include "sipp_mp.h"
#include "conn.h"
#include "access_control.h"
#include "services.h"
#include "trustman.h"
#include "netio.h"
#include "addrbook.h"
#ifdef CONFIG_HIP_ENABLED
#include "hipapi.h"
#endif
#include "ui.h"

/* this should be defined so that the tablets don't think things are
   getting looped up and start sending 482 responses (which kill the
   call) */
#define IGNORE_VIAS 1

/* this makes us send data to the local ip in case the UA has been
   bound to the HIT, as lo-hit routing doesn't seem to work. This is
   needed for maemo (at least). */
#ifdef CONFIG_HIP_ENABLED
#define CONFIG_DISABLE_LO_HIT_ROUTING 1 
#endif


static ship_list_t *sipp_client_handlers = 0;

/* list of all the listeners */
static ship_list_t *sipp_all_listeners = NULL;

/* the media proxies (used by sipp_mp.c) */
ship_list_t *sipp_mps;

/* the response-tracker */
static ship_ht_t *prox_resps = 0;

/* config values */
static int sip_proxy_port;
static int sipp_media_proxy;
static int sipp_tunnel_proxy;
static int sipp_force_proxy;
static int sipp_media_proxy_mobility;

/* the list of relay configurations */
static ship_list_t *relays = 0;

/* the list of gateways */
static ship_list_t *gateways = 0;

/* prototypes */
static int sipp_handle_message_do(sipp_request_t *req);
static int sipp_send_response(sipp_request_t *req, int code);
static int sipp_send_buf(char *buf, int len, sipp_listener_t *lis, addr_t *to);
static int sipp_send_sip_to_ident(osip_message_t *sip, ident_t *ident, addr_t *from, const char *remote_aor);
static int sipp_send_remote_response(osip_message_t* sip, int code, char *sip_aor, ident_t *ident);
static int sipp_check_and_mark(osip_message_t *sip, char *prefix, int code);
static int sipp_handle_remote_message(char *msg, int msglen, ident_t *ident, char *sip_aor, service_type_t service);
static void sipp_call_log_record(char *local_aor, char *remote_aor, osip_event_t *evt, int verdict, int remote1);
static char *sipp_real_aor(char *aor);
//static char *sipp_aor_group_code(char *aor);

/* sipp_requests */
static void sipp_request_free(sipp_request_t *req);
static int sipp_request_init(sipp_request_t *ret, sipp_request_t *param);

SHIP_DEFINE_TYPE(sipp_request);

/* the list of callids */
static ship_list_t *call_log = 0;

/* frees it up */
static void sipp_call_log_free(call_log_entry_t* e);

/* call or chat? */
static const char *TYPE_CALL_STRING = "Call";
static const char *TYPE_CHAT_STRING = "Conversation";

/* whether to show the dropped / info popups */
static int call_log_show_dropped = 1;
static int call_log_show_pathinfo = 1;

/* the sip service description / handle */
static struct service_s sipp_service =
{
 	.data_received = sipp_handle_remote_message,
	.service_closed = 0,
	.service_handler_id = "sipp_service"
};

/*
 * data processing stuff 
 */

/* extracts the callid from a sip message */
char *
sipp_get_call_id(osip_message_t *sip)
{
	char *callid = 0;
	ASSERT_TRUE(sip->call_id, err);
	ASSERT_TRUE(callid = (char*)mallocz(zstrlen(sip->call_id->number) + 
					    zstrlen(sip->call_id->host) + 2), err);
	zstrcat(callid, sip->call_id->number);
	zstrcat(callid, "@");
	zstrcat(callid, sip->call_id->host);
	goto end;
 err:
	freez(callid);
 end:
	return callid;
}

/* fetches the address of the proxy that is known to the given SIP
   UA */
static int
sipp_get_addr_to_ua(ident_t *ident, addr_t *addr)
{
	int ret = -1;
	sipp_listener_t *lis = (sipp_listener_t *)ident_get_service_data(ident, SERVICE_TYPE_SIP);
	if (lis) {
		memcpy(addr, &(lis->addr), sizeof(addr_t));
		ret = 0;
	}
	return ret;
}

#ifndef IGNORE_VIAS
static osip_record_route_t *
sipp_create_own_rr(ident_t *ident)
{
        osip_record_route_t *rr = NULL;
	addr_t addr;
	if (sipp_get_addr_to_ua(ident, &addr)) {
		strcpy(addr.addr, "127.0.0.1");
		addr.port = sip_proxy_port;
	}
	
        if (!osip_record_route_init(&rr)) {
                char buf[64];
                sprintf(buf, "<sip:%s:%d;lr>", addr.addr, addr.port);
                if (osip_record_route_parse(rr, buf)) {
                        osip_record_route_free(rr);
                        rr = NULL;
                }
        }
        return rr;
}

static osip_via_t *
sipp_create_own_via(ident_t *ident)
{
        osip_via_t *via = NULL;
	addr_t addr;
	if (sipp_get_addr_to_ua(ident, &addr)) {
		strcpy(addr.addr, "127.0.0.1");
		addr.port = sip_proxy_port;
	}

        if (!osip_via_init(&via)) {
                char *v = strdup("2.0");
                char *p = strdup("UDP");
                char *h = strdup(addr.addr);
                char *port = (char*)mallocz(10);
                sprintf(port, "%d", addr.port);
                
                if (v && p && h) {
                        via_set_version(via, v);
                        via_set_protocol(via, p);
                        via_set_host(via, h);
                        via_set_port(via, port);
                } else {
                        freez(v);
                        freez(p);
                        freez(h);
                        osip_via_free(via);
                        via = NULL;
                }
        }
        
        return via;
}
#endif

static int
sipp_get_sip_aors(osip_message_t *sip, char **fullfromurl,  char **fulltourl, int remote)
{
        *fulltourl = sipp_url_to_short_str(sip->to->url);
        *fullfromurl = sipp_url_to_short_str(sip->from->url);
        
	ASSERT_TRUE(*fulltourl && *fullfromurl, err);

        if ((MSG_IS_RESPONSE(sip) && !remote) ||
	    (!MSG_IS_RESPONSE(sip) && remote)) {
                char *tmp = *fulltourl;
                *fulltourl = *fullfromurl;
                *fullfromurl = tmp;
        }
	
	return 0;
 err:
	freez((*fulltourl));
	freez((*fullfromurl));
	return 1;
}

/*
 * GATEWAY functions
 */

/* function for checking whether the given string matches a set of regexp-like filters 
 *
 * @param str The string which might match the patterns
 * @param patterns A comma-separated list of patterns 
 */
static int
ship_str_matches(const char *str, const char *patterns)
{
	regex_t exp;
	int ret = -1;
	char **tokens = 0;
	int toklen = 0, i = 0;

	ASSERT_ZERO(ship_tokenize_trim(patterns, strlen(patterns), &tokens, &toklen, ','), err);
	for (i = 0; i < toklen; i++) {
		ASSERT_ZERO(regcomp(&exp, tokens[i], REG_ICASE), err);
		if (!regexec(&exp, str, 0, NULL, 0))
			ret = 1;
		regfree(&exp);
		if (ret == 1)
			goto err;
	}
	ret = 0;
 err:
	LOG_DEBUG("did %s match any of the patterns in '%s': %d\n",
		  str, patterns, ret);
	ship_tokens_free(tokens, toklen);
	return ret;
}

/* tries the find the address (host:port) to which to relay the given
   packet. if no relay has been configured, returns NULL.
 */
static addr_t*
sipp_get_relay_addr(ident_t *ident, osip_message_t *sip)
{
	char *local_sip = 0, *remote_sip = 0;
	void *ptr = 0;
	sipp_relay_t *relay = 0;
	addr_t *ret = 0;
	
	/* the ident_t struct should have a field which specifies the
	   patterns for which it is a gateway */
	ASSERT_ZERO(sipp_get_sip_aors(sip, &local_sip, &remote_sip, 1), err);
	while (!ret && (relay = ship_list_next(relays, &ptr))) {
		if (ship_str_matches(ident->sip_aor, relay->ident_aor) &&
		    ship_str_matches(local_sip, relay->local_pattern) &&
		    ship_str_matches(remote_sip, relay->remote_pattern)) {
			ret = &relay->relay_addr;
			LOG_INFO("Relay found for packet, relaying to %s:%d\n",
				 ret->addr, ret->port);
		}
	}
	
	freez(local_sip);
	freez(remote_sip);
 err:
	return ret;
}

/* return the identity we should use when sending packets from some
   aor we are acting as a gateway for
*/
static ident_t*
sipp_get_gateway_ident(char *local_sip, char *remote_sip)
{
	void *ptr = 0;
	sipp_relay_t *relay = 0;
	
	while ((relay = ship_list_next(relays, &ptr))) {
		if (ship_str_matches(local_sip, relay->local_pattern) &&
		    ship_str_matches(remote_sip, relay->remote_pattern)) {
			LOG_INFO("Gateway identity found, using %s..\n", relay->ident_aor);
			return ident_find_by_aor(relay->ident_aor);
		}
	}
	return 0;
}


/**
 * @param forlocal If the address is meant for local clients 
 *        (clients that have registered to the proxy with REGISTER)
 *        or either remote or gateway'd clients
 */
static int
sipp_get_default_media_proxy_interface(addr_t *newaddr, int forlocal)
{
	/* todo gw: */
	TODO("we should configure some default media proxy interface!!\n");
	bzero(newaddr, sizeof(addr_t));
	if (forlocal || conn_get_publicip(newaddr)) {
		strcpy(newaddr->addr, "127.0.0.1");
		newaddr->family = AF_INET;
	}
	return 0;
}

/* find the ident to which to forward packets for gatewaying */
static char *
sipp_find_to_ident(char *local_sip, char *remote_sip)
{
	void *ptr = 0;
	sipp_gateway_t *gw = 0;
	
	while ((gw = ship_list_next(gateways, &ptr))) {
		if (ship_str_matches(local_sip, gw->local_pattern) &&
		    ship_str_matches(remote_sip, gw->remote_pattern)) {
			LOG_INFO("Gateway for packet found, routing via %s..\n", 
				 gw->gateway_ident_aor);
			return strdup(gw->gateway_ident_aor);
		}
	}

	/* no gateway? check multiparty / alias stuff */
	return sipp_real_aor(strdup(remote_sip));

	/*
	ASSERT_TRUE(ret = mallocz(strlen(remote_sip)+1), err);
	if ((p1 = strchr(remote_sip, '+'))) {
		strncpy(ret, remote_sip, (int)(p1-remote_sip));
		if ((p2 = strchr(p1, '@')))
			strcat(ret, p2);
	} else
		strcpy(ret, remote_sip);
 err:
	return ret;
	*/
}

/*
 * listener funcs
 */

static void
sipp_listener_free(sipp_listener_t *lis)
{
	if (!lis)
		return;

	if (lis->socket != -1) {
		netio_close_socket(lis->socket);
	}
	
	freez(lis->queued_data);
	free(lis);
}

static void
sipp_listener_close(sipp_listener_t *lis)
{
	if (!lis)
		return;
	
	ship_list_remove(sipp_all_listeners, lis);
	sipp_listener_free(lis);
}

static sipp_listener_t*
sipp_listener_new(addr_t *addr)
{
        sipp_listener_t *ret = NULL;
        ASSERT_TRUE(ret = (sipp_listener_t *)mallocz(sizeof(sipp_listener_t)), err);
	memcpy(&(ret->addr), addr, sizeof(addr_t));
        ret->socket = -1;
        return ret;
 err:
        sipp_listener_close(ret);
        return ret;
}

static sipp_listener_t*
sipp_listener_new_queued(addr_t *addr, char *data, int data_len)
{
        sipp_listener_t *ret = NULL;
        ASSERT_TRUE(ret = sipp_listener_new(addr), err);
	ASSERT_TRUE(ret->queued_data = mallocz(data_len),  err);
	memcpy(ret->queued_data, data, data_len);
        return ret;
 err:
        sipp_listener_close(ret);
        return ret;
}

/* frees a request */
static void
sipp_request_free(sipp_request_t *req)
{
	if (req->evt) {
		osip_event_free(req->evt);
	}
	freez(req->local_aor);
	freez(req->remote_aor);
}

/* creates a request */
static int
sipp_request_init(sipp_request_t *ret, sipp_request_t *param)
{
	ret->evt = param->evt;
	ret->lis = param->lis;
	memcpy(&(ret->from_addr), &(param->from_addr), sizeof(addr_t));
	if (ret->evt && ret->evt->sip && ret->evt->sip->from && ret->evt->sip->to) {
		char *local = sipp_real_aor(sipp_url_to_short_str(ret->evt->sip->from->url));
		char *remote = sipp_real_aor(sipp_url_to_short_str(ret->evt->sip->to->url));
		if (MSG_IS_RESPONSE(ret->evt->sip)) {
			char *tmp = local;
			local = remote;
			remote = tmp;
		}
		
		ret->local_aor = local;
		ret->remote_aor = remote;
	}
        return 0;
}

static void
sipp_cb_packetfilter_local(char *local_aor, char *remote_aor, void *msg, int verdict)
{
        /* put on queue for processing */
        sipp_request_t *req = msg;
	int respcode = -1;

	/* record the call / conversation .. */
	LOG_VDEBUG("got back from AC for local, verdict %d\n", verdict);
	sipp_call_log_record(local_aor, remote_aor, req->evt, verdict, 0);

	switch (verdict) {
	case AC_VERDICT_ALLOW:
		respcode = sipp_handle_message_do(req);
		break;
	case AC_VERDICT_REJECT:
                respcode = 487;
		break;
	case AC_VERDICT_DROP:
                respcode = 404;
		break;
	case AC_VERDICT_UNSUPP:
                respcode = 420;
		break;
	case AC_VERDICT_IGNORE:
	default:
		/* silently ignore */
		respcode = 0;
		break;
	}
	
	/* send a response, if one was provided */
	if (respcode) {
		LOG_DEBUG("processed the SIP message with return code %d\n", respcode);
		if (respcode < 0)
			respcode = 500;
		sipp_send_response(req, respcode);
	}
	
	ship_obj_unref(req);
}

/* processes received messages (datagrams) */
static void
sipp_handle_message(char *msg, int len, sipp_listener_t *lis, addr_t *addr)
{
        osip_event_t *evt = 0;
        sipp_request_t *req = 0;
	sipp_request_t param;

	LOG_DEBUG("got %d bytes of data from %s:%d\n", len, addr->addr, addr->port);
        LOG_VDEBUG("data: %s\n", msg);

        ASSERT_TRUE(evt = osip_parse(msg, len), err);
        ASSERT_TRUE(evt->sip, err);
        
	param.lis = lis;
	param.evt = evt;
	memcpy(&(param.from_addr), addr, sizeof(addr_t));
        ASSERT_TRUE(req = (sipp_request_t*)ship_obj_new(TYPE_sipp_request, &param), err);

	/* take this through the AC module */
	ASSERT_ZERO(ac_packetfilter_local(req, sipp_cb_packetfilter_local), err);
        return;
 err:
        LOG_VDEBUG("invalid message!\n");
        if (req) { 
		ship_obj_unref(req);
        } else if (evt)
                osip_event_free(evt);
}


/* extracts the contact-string's address to the given addr. includes
   ip addr & af_family */
static int
sipp_sdp_extract_contact(char *bodystr, int bodystrlen, addr_t *addrd)
{
	char *ls, *de;
	char **tokens = NULL;
        int toklen = 0, ret = -1;
	
	ls = bodystr;
	de = bodystr + bodystrlen;
	do {
		char *le = ls;
		/* one row at a time.. */
		while (le < de && (*le) != '\n')
			le++;
		if (le < de)
			le++;
		if (le != ls) {
			int slen = le-ls;
			if (!memcmp(ls, "c=", 2)) {
				ASSERT_ZERO(ship_tokenize(ls+2, slen-2, &tokens, &toklen, ' '), err);
				if (toklen == 3) {
					ASSERT_ZERO(ident_addr_str_to_addr(tokens[2], addrd), err);
					le = de; /* stop the loop */
				}
				
				ship_tokens_free(tokens, toklen);
				tokens = NULL;
			}
		}
		ls = le;
	} while (ls < de);
	
	ret = 0;
 err:
        if (tokens)
                ship_tokens_free(tokens, toklen);
	return ret;
}


static int
sipp_sdp_replace_addr_create_proxies(char *bodystr, int bodystrlen, char **newmsg, int *newmsglen,
				     char *callid, char *local_aor, char *remote_aor, addr_t *new_addr, 
				     int sendby, int remotely_got)
{
	int newbodysize, newbodylen = 0;
        char *newbodystr = NULL;

	char *ls, *de;
	size_t len = bodystrlen;

	char **tokens = NULL;
        int toklen = 0;

        addr_t target_addr;
 	char *tmp = NULL;

	int ret = -1;
	
        /* todo: modifs required to support tcp or anything != udp */

	/* Parse manually, find all c and m lines. As (in theory) the
	   c line (containing the ip addr) could come after the m line
	   (containing the ports), we create the mediaproxies using
	   the ports and init them all afterwards with the ip. */
	newbodysize = len + 512;
	ASSERT_TRUE(newbodystr = (char*)mallocz(newbodysize), err);
	bzero(&target_addr, sizeof(addr_t));
	
	ls = bodystr;
	de = bodystr + len;
	do {
		char *le = ls;
		/* one row at a time.. */
		while (le < de && (*le) != '\n')
			le++;
		if (le < de)
			le++;
		if (le != ls) {
			int slen = le-ls;
			if (!memcmp(ls, "c=", 2) || !memcmp(ls, "m=", 2)) {
				char prefi[3];
				ASSERT_ZERO(ship_tokenize(ls+2, slen-2, &tokens, &toklen, ' '), err);
				switch (ls[0]) {
				case 'c':
					if (toklen == 3) {
						/* the ipv4/6 flag should get set automatically here .. */
						ASSERT_ZERO(ident_addr_str_to_addr(tokens[2], &target_addr), err);

						/* todo gw: if we are in gateway mode, we should not have the
						   mobility hack enabled ever! */
						TODO("check whether we are in proxy mode, disable mobility hack\n");

						/* support for mobility: replace it with lo, as that doesn't change during mobility. */
						if (!remotely_got && (target_addr.family == AF_INET) &&
						    sipp_media_proxy_mobility) {
							strcpy(target_addr.addr, "127.0.0.1");
						}

						LOG_DEBUG("replacing c's ip of %s to %s\n", target_addr.addr, new_addr->addr);
						
						ASSERT_TRUE(tmp = mallocz(strlen(new_addr->addr) + 5), err);
						strcpy(tmp, new_addr->addr);
						strcat(tmp, "\r\n");
						ASSERT_ZERO(ship_tokens_replace(tokens, tmp, 2), err);
						freez(tmp);
						
						switch (new_addr->family) {
						case AF_INET6:
							ASSERT_ZERO(ship_tokens_replace(tokens, "IP6", 1), err);
							break;
						case AF_INET:
							ASSERT_ZERO(ship_tokens_replace(tokens, "IP4", 1), err);
							break;
						}
					}
					break;
				case 'm':
					if (toklen > 2) {
						char portstr[10];
						sipp_media_proxy_t *proxy = NULL;
						
						/* we need to ensure that we have the target address at this point.
						   we could wait, but that could result in redundant media proxies.
						   this isn't really optimal, but good enough for now */
						
						/* if port == 0, then ignore. */
						if (atoi(tokens[1]) && (target_addr.addr[0] ||
									!sipp_sdp_extract_contact(bodystr, bodystrlen, &target_addr))) { 
							
							/* udp, please .. */
							target_addr.type = IPPROTO_UDP;
							target_addr.port = atoi(tokens[1]);
							
							/* check to find if we already have a proxy for that */
							if (!(proxy = sipp_mp_find(callid, &target_addr, sendby))) {
								
								/* todo: we should check if udp / other from the medialine */
								new_addr->type = IPPROTO_UDP;
								ASSERT_TRUE(proxy = sipp_mp_create_new(callid, local_aor, 
												       remote_aor, tokens[0],
												       new_addr, &target_addr, 
												       sendby), err);
								
								if (sipp_mp_start(proxy, remotely_got)) {
									sipp_mp_close(proxy);
									ASSERT_TRUE(0, err);
								}
							}
							
							sprintf(portstr, "%d", proxy->local_addr.port);
							LOG_DEBUG("replacing m's port for %s of %s to %s\n", 
								  tokens[0], tokens[1], portstr);
							ASSERT_ZERO(ship_tokens_replace(tokens, portstr, 1), err);
						}
					}
					break;
				}
                                                
				strncpy(prefi, ls, 2);
				prefi[2] = 0;
				ASSERT_TRUE(tmp = ship_untokenize(tokens, toklen, " ", prefi), err);
				ship_tokens_free(tokens, toklen);
				tokens = NULL;
                                                
				slen = strlen(tmp);
			}
			
			if (newbodysize < (newbodylen + slen + 1)) {
				char *bodytmp;
				newbodysize = newbodylen + slen + 512;
				ASSERT_TRUE(bodytmp = (char*)mallocz(newbodysize), err);
				memcpy(bodytmp, newbodystr, newbodylen);
				free(newbodystr);
				newbodystr = bodytmp;
			}
                                        
			if (tmp)
				memcpy(newbodystr + newbodylen, tmp, slen);
			else
				memcpy(newbodystr + newbodylen, ls, slen);

			newbodylen += slen;
			freez(tmp);
		}

		ls = le;
	} while (ls < de);

	(*newmsg) = newbodystr;
	(*newmsglen) = newbodylen;
	newbodystr = NULL;
	ret = 0;
 err:
        if (tokens)
                ship_tokens_free(tokens, toklen);
	
        freez(newbodystr);
        freez(tmp);
	return ret;
}

/* processes the body of a locally got message. replaces values,
   creates media proxies etc.. */
static int
sipp_process_sdp_message_body(osip_message_t* sip, 
			      ident_t* local_ident, char *remote_aor,
			      int remotely_got)
{
        int ret = -1;
	osip_body_t *newbody = NULL;
	char *callid = 0;
	char *newbodystr = NULL, *bodystr = NULL;
	char *local_sip = 0, *remote_sip = 0;

        /* process all sdp going through */
        if (sipp_media_proxy &&
	    sip->content_type && 
            !strcmp(sip->content_type->type, "application") &&
            !strcmp(sip->content_type->subtype, "sdp")) {
                void *next = NULL;

		ASSERT_TRUE(callid = sipp_get_call_id(sip), err);
		next = OSIPMSG_PTR(sip->bodies)->node;
                while (next) {
                        osip_body_t *body = NULL;
                        int sendby = SIPP_MP_SENDBY_NONE;
			addr_t addrt, newaddr;
                        size_t len;
                        
			freez(bodystr);
                        body = (osip_body_t *)((__node_t*)next)->element;
			ASSERT_ZERO(osip_body_to_str(body, &bodystr, &len), err);                        
			if (sipp_media_proxy && !sipp_sdp_extract_contact(bodystr, len, &addrt)) {
				/* remotely got or from local UA? */
				if (remotely_got) {
					/* ok, use first the addr to which the packetlistener is
					   bound to that is receiving SIP signalling from the target host */
					if (sipp_get_relay_addr(local_ident, sip))
						sipp_get_default_media_proxy_interface(&newaddr, 0);
					else if (sipp_get_addr_to_ua(local_ident, &newaddr))
						sipp_get_default_media_proxy_interface(&newaddr, 1);
					newaddr.type = IPPROTO_NONE;
					newaddr.port = 0;
					
					/* if this is not a HIT or [a HIT, but we don't have any locator for it],
					   then force the traffic through the tunnel */
					if (sipp_tunnel_proxy
#ifdef CONFIG_HIP_ENABLED
					    || (hipapi_addr_is_hit(&addrt)
						&& hipapi_create_peer_hit_locator_mapping(remote_aor, &addrt))
					    || (!processor_config_bool(processor_get_config(), P2PSHIP_CONF_ALLOW_NONHIP)
						&& !hipapi_addr_is_hit(&addrt))
#endif					    
					    ) {
						LOG_DEBUG("Creating TUNNEL mediaproxy\n");
						sendby = SIPP_MP_SENDBY_TUNNEL;
					} else if (sipp_force_proxy) {
						LOG_DEBUG("Creating DIRECT mediaproxy\n");
						sendby = SIPP_MP_SENDBY_DIRECT;
					}
				} else {
					/* we always send directly these, right? */
					if (sipp_force_proxy) {
						sendby = SIPP_MP_SENDBY_DIRECT;
					}

					/* use public interface if possible (if peer has != mp, then
					   it will send packets to its own 127.0.0.1 otherwise..) */
					sipp_get_default_media_proxy_interface(&newaddr, 0);
#ifdef CONFIG_HIP_ENABLED	
					/* we need to know whether the peer supports hip or not */
					if (processor_config_bool(processor_get_config(), P2PSHIP_CONF_ALLOW_NONHIP) && 
					    !conn_connection_uses_hip(remote_aor, local_ident->sip_aor)) {
						if (sipp_force_proxy || hipapi_addr_is_hit(&addrt)) {
							sendby = SIPP_MP_SENDBY_DIRECT;
							/* keep the public address.. */
						}
					} else {
						if (sipp_force_proxy || !hipapi_addr_is_hit(&addrt)) {
							sendby = SIPP_MP_SENDBY_DIRECT;
							ASSERT_ZERO(hipapi_gethit(&newaddr), err);
						}
					}
#endif
					newaddr.type = IPPROTO_NONE;
					newaddr.port = 0;
				}
			}
			
			if (sendby != SIPP_MP_SENDBY_NONE) {
				int newbodylen = 0;

				freez(newbodystr);
				ASSERT_ZERO(sipp_get_sip_aors(sip, &local_sip, &remote_sip, remotely_got), err);
				ASSERT_ZERO(sipp_sdp_replace_addr_create_proxies(bodystr, len, &newbodystr, &newbodylen, 
										 callid, local_sip, remote_sip,
										 &newaddr, sendby, remotely_got), err);
				
				/* todo mpfw: we should somehow mark
				   that we should accept mp-packets
				   from the remote host to either the
				   original contact-addresses or the
				   the substitutes if we do a
				   substitution */

				if (newbodystr) {
					/* parse & put into sip message */
					ASSERT_ZERO(osip_body_init(&newbody), err);
					ASSERT_ZERO(osip_body_parse(newbody, newbodystr, newbodylen), err);
					((__node_t*)next)->element = newbody;
					newbody = NULL;
					osip_body_free(body);
				}
			}
                        next = ((__node_t*)next)->next;
                }
        }

        ret = 0;
 err:        
	freez(local_sip);
	freez(remote_sip);
	freez(callid);
	freez(bodystr);	
	if (newbody)
		osip_body_free(newbody);
	freez(newbodystr);

        return ret;
}

/* does some cleanup when a call has been terminated */
	static void
sipp_call_terminated(osip_message_t* sip, int remotely_got)
{
	char *callid;
	
	LOG_DEBUG("call termianted by %s, checking for mediaproxies..\n", (remotely_got? "remote":"local"));
	if ((callid = sipp_get_call_id(sip))) {
		sipp_mp_clean_by_call(callid);
		free(callid);
	}
	
	/* if we are in pdd measurement-mode, reset the sa:s */

	/* .. except that they would just be re-inited when we receive
	   the ACK or actually want to send the cancel / bye */

	/* .. that should be done when receiving the invite
	   instead. */

}

/*
static int
sipp_handle_group_message(osip_message_t* sip, ident_t *ident, 
			  char *remote_aor, 
			  char *group)
{
	printf("got message for group %s on ident %s from %s\n",
	       group, ident->sip_aor, remote_aor);

	sipp_send_remote_response(sip, 200, remote_aor, ident);
	
	
	
	return 0;
}
*/

/* processes remotely received messages (datagrams) */
static int
sipp_forward_remote_message(osip_message_t* sip, ident_t *ident, char *remote_aor)
{      
        char *tmp = NULL;
	// char *local = NULL, *remote = NULL;
	//int ret = -1;

	/* check Via - remove my own entry on responses, add on requests! */
        if (MSG_IS_RESPONSE(sip)) {
                /* remove my Via */
#ifndef IGNORE_VIAS
                via = (osip_via_t*)osip_list_get(OSIPMSG_PTR(sip->vias), 0);
                if (via)
                        osip_list_remove(OSIPMSG_PTR(sip->vias), 0);
                osip_via_free(via);
#endif
	} else {
		addr_t *addr = 0;
		
                /* perform the following on externally generated requests:
                   - rewrite request-uri (replace domain with contact-IP)
                   - add a record-route
                   - add a via
                */
		
		/* skip any sort of ident substitution in GW mode */
		if (!sipp_get_relay_addr(ident, sip)) {
			ASSERT_TRUE(addr = ident_get_service_addr(ident, SERVICE_TYPE_SIP), err);
			ASSERT_TRUE(tmp = (char*)mallocz(10), err);
			sprintf(tmp, "%d", addr->port);
			free(sip->req_uri->port);
			sip->req_uri->port = tmp;
			
			ASSERT_TRUE(tmp = strdup(addr->addr), err);
			LOG_DEBUG("replacing contact '%s' -> '%s'\n", 
				  sip->req_uri->host, tmp);
			
			freez(sip->req_uri->host);
			sip->req_uri->host = tmp;
			tmp = NULL;
		}
		
#ifndef IGNORE_VIAS
                if (!(rr = sipp_create_own_rr(ident)))
                        goto err;
                osip_list_add(OSIPMSG_PTR(sip->record_routes), rr, 0);

                if (!(via = sipp_create_own_via(ident)))
                        goto err;
                osip_list_add(OSIPMSG_PTR(sip->vias), via, 0);
#endif
        }

        ASSERT_ZERO(sipp_process_sdp_message_body(sip, ident, remote_aor, 1), err);

	/* check if the message is a bye! */
	if (MSG_IS_BYE(sip) || MSG_IS_CANCEL(sip))
		sipp_call_terminated(sip, 1);
	goto end;
 err:
	LOG_WARN("Error while processing remotely got message.\n");
 end:
	/* check the SIP client hooks */
	/* no.. tihs comes later, just before sending! 
	ASSERT_ZERO(sipp_get_sip_aors(sip, &local, &remote, 1), end);
	if (strlen(sipp_aor_group_code(local)) > 0)
		return sipp_handle_group_message(sip, ident, remote_aor, local);
	freez(local);
	freez(remote);
	*/

	return sipp_send_sip_to_ident(sip, ident, NULL, remote_aor);
}

static void
sipp_cb_packetfilter_remote2(ident_t* ident, char *remote_aor, osip_event_t *evt, int verdict)
{
	int respcode = -1;

	/* record the message / call */
	ship_unlock(ident);
	sipp_call_log_record(ident->sip_aor, remote_aor, evt, verdict, 1);
	ship_lock(ident);

	switch (verdict) {
	case AC_VERDICT_NONE:
	case AC_VERDICT_ALLOW:
		sipp_forward_remote_message(evt->sip, ident, remote_aor);
		break;
	case AC_VERDICT_REJECT:
		respcode = 487;
		break;
	case AC_VERDICT_DROP:
		respcode = 404;
		break;
	case AC_VERDICT_IGNORE:
	default:
		/* silently ignore */
		break;
	}

	/* do not respond to a response! */
	if (!MSG_IS_RESPONSE(evt->sip) && respcode > 0) {
		sipp_send_remote_response(evt->sip, respcode, remote_aor, ident);
	}
}

static void
sipp_cb_packetfilter_remote(char *local_aor, char *remote_aor, void *msg, int verdict)
{
        osip_event_t *evt = msg;
	ident_t* ident = ident_find_by_aor(local_aor);

	if (!ident)
		goto end;

	sipp_cb_packetfilter_remote2(ident, remote_aor, evt, verdict);
	ship_obj_unlockref(ident);
 end:
	osip_event_free(evt);
}

/* processes remotely received messages (datagrams), called from
   conn.c, when this is registered as the service for that user..  */
static int
sipp_handle_remote_message(char *msg, int msglen, ident_t *ident, char *sip_aor, service_type_t service)
{
        int ret = -3;
        osip_event_t *evt = 0;
	
        ASSERT_TRUE(evt = osip_parse(msg, msglen), err);
        ASSERT_TRUE(evt->sip, err);
	ASSERT_ZERO(ac_packetfilter_remote(ident->sip_aor, sip_aor,
					   evt, sipp_cb_packetfilter_remote), err);
	
	ret = 0;
	evt = 0;
	goto end;
 err:
	LOG_WARN("An invalid remote message got, dropping it:\n>>>>>\n%s\n<<<<<\n", msg);
 end:
        if (evt)
                osip_event_free(evt);
        return ret;
}

static void sipp_cb_data_got(int s, char *data, ssize_t len);

/* siptcp: callback function for new connections */
static void
sipp_cb_tcpconn_got(int s, struct sockaddr *sa, socklen_t addrlen, int ss)
{
	sipp_listener_t *lis = 0;
	addr_t addr;
	LOG_DEBUG("Got TCP connection\n");

	ASSERT_ZERO(ident_addr_sa_to_addr(sa, addrlen, &addr), err);
	addr.type = IPPROTO_TCP;
	ASSERT_TRUE(lis = sipp_listener_new(&addr), err);
	lis->socket = s;
	ASSERT_ZERO(netio_read(s, sipp_cb_data_got), err);
	ship_list_add(sipp_all_listeners, lis);
	lis = 0;
 err:
	if (lis)
		sipp_listener_close(lis);
}

static sipp_listener_t *
sipp_get_listener_by_socket(int s) 
{
	sipp_listener_t *lis = NULL;
	void *ptr = NULL;
        if (!sipp_all_listeners)
                goto end;

        ship_lock(sipp_all_listeners); {
                while ((lis = (sipp_listener_t *)ship_list_next(sipp_all_listeners, &ptr))) {
                        if (lis->socket == s)
                                break;
                        lis = NULL;
                }
        } ship_unlock(sipp_all_listeners);
 end:
	return lis;
}
        

static void
sipp_cb_data_got(int s, char *data, ssize_t len)
{
        sipp_listener_t *lis = sipp_get_listener_by_socket(s);

	if (!lis) {		
		netio_close_socket(s);
	} else if (len < 1) {
                sipp_listener_close(lis);
	} else  if (len > 1) {
                sipp_handle_message(data, len, lis, &(lis->addr));
	}
}

static void 
sipp_cb_datagram_got(int s, char *data, size_t len,
                     struct sockaddr *sa, socklen_t addrlen)
{
        /* find lis */
        sipp_listener_t *lis = sipp_get_listener_by_socket(s);
        addr_t addr;
	
        if (!lis) {
                netio_close_socket(s);
        } else if (len == -1) {
                sipp_listener_close(lis);
        } else if (len > 1 && !ident_addr_sa_to_addr(sa, addrlen, &addr)) {
		addr.type = IPPROTO_UDP;
                sipp_handle_message(data, len, lis, &addr);
        }
}

static void
sipp_cb_config_update(processor_config_t *config, char *k, char *v)
{
	/* the lazy approach: */
	ASSERT_ZERO(processor_config_get_int(config, P2PSHIP_CONF_SIPP_PROXY_PORT, 
					     &sip_proxy_port), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY, 
					      &sipp_media_proxy), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_SIPP_TUNNEL_PROXY, 
					      &sipp_tunnel_proxy), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_SIPP_FORCE_PROXY, 
					      &sipp_force_proxy), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY_MOBILITY_SUPPORT, 
					      &sipp_media_proxy_mobility), err);

	/* show the call log popups */
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_CALL_LOG_SHOW_PATHINFO,
					      &call_log_show_pathinfo), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_CALL_LOG_SHOW_DROPPED,
					      &call_log_show_dropped), err);

	return;
 err:
	PANIC();
}

/***
 ***
 *
 * routing / gateway - related 
 *
 */

// new routing, del routing & gateway entries..
static void
sipp_gateway_free(void *_gw)
{
	sipp_gateway_t *gw = _gw;
	if (!gw)
		return;
	freez(gw->local_pattern);
	freez(gw->remote_pattern);
	freez(gw->gateway_ident_aor);
	freez(gw);
}

static void
sipp_relay_free(void *_relay)
{
	sipp_relay_t *relay = _relay;
	if (!relay)
		return;
	freez(relay->ident_aor);
	freez(relay->local_pattern);
	freez(relay->remote_pattern);
	freez(relay);
}


static int
sipp_load_routing_xml(xmlNodePtr cur, void *ptr)
{
	sipp_gateway_t *gw = 0;
	sipp_relay_t *relay = 0;
	void **arr = ptr;
	ship_list_t *gws = arr[1];
	ship_list_t *rls = arr[0];
	int ret = -1;
	char *tmp = 0;
	xmlNodePtr node = NULL;
	
	if (!xmlStrcmp(cur->name, (xmlChar*)"sip-routing")) {
		for (node = cur->children; node; node = node->next) {
			if ((ret = sipp_load_routing_xml(node, arr)))
				return ret;
		}
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"route")) {
		ASSERT_TRUE(gw = mallocz(sizeof(sipp_gateway_t)), err);
		ASSERT_TRUE(gw->local_pattern = ship_xml_get_child_field(cur, "source"), err);
		ASSERT_TRUE(gw->remote_pattern = ship_xml_get_child_field(cur, "target"), err);
		ASSERT_TRUE(gw->gateway_ident_aor = ship_xml_get_child_field(cur, "via"), err);
		ship_list_add(gws, gw);
		gw = 0;
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"relay")) {
		ASSERT_TRUE(relay = mallocz(sizeof(sipp_relay_t)), err);
		ASSERT_TRUE(relay->ident_aor = ship_xml_get_child_field(cur, "ident"), err);
		ASSERT_TRUE(relay->local_pattern = ship_xml_get_child_field(cur, "subject"), err);
		ASSERT_TRUE(relay->remote_pattern = ship_xml_get_child_field(cur, "allow"), err);
		ASSERT_TRUE(tmp = ship_xml_get_child_field(cur, "address"), err);
		ASSERT_ZERO(ident_addr_str_to_addr(tmp, &(relay->relay_addr)), err);
		relay->relay_addr.type = IPPROTO_UDP;
		ship_list_add(rls, relay);
		relay = 0;
	}
	
	ret = 0;
 err:
	sipp_gateway_free(gw);
	sipp_relay_free(relay);
	freez(tmp);
	return ret;
}

#define SIPP_RELAY_REGISTRATION_TIME (60*10)

/* update all the relay registrations. to be called periodically */
static int
sipp_update_relay_registrations()
{
	void *ptr = 0;
	sipp_relay_t *relay = 0;
	
	if (!relays)
		return 0;

	while ((relay = ship_list_next(relays, &ptr))) {
		ident_process_register(relay->ident_aor, SERVICE_TYPE_SIP, &sipp_service,
				       NULL, SIPP_RELAY_REGISTRATION_TIME, NULL);
	}

	return 1;
}

static int
sipp_load_routing()
{
	void *arr[2];
	arr[0] = relays;
	arr[1] = gateways;
	
	/* should we clear those arrays first? */

	return ship_load_xml_file(processor_config_string(processor_get_config(), P2PSHIP_CONF_SIPP_ROUTING_FILE), 
				  sipp_load_routing_xml, arr);
}

/*
static int
test_client_handler(ident_t *ident, const char *remote_aor, addr_t *contact_addr, char **buf, int *len,
		    void *data)
{
	char *tmp = 0;
	while ((tmp = strstr(*buf, "huff"))) {
		memcpy(tmp, "!?#%", 4);
	}
	return 1;
}
*/

int 
sipp_init(processor_config_t *config)
{
        sipp_listener_t *lis = 0;
        struct sockaddr *sa = 0;
        socklen_t salen = 0;
	char **ifs = 0;
	int ifs_c = 0, ret = -1;
	char *tmp = 0;
	ship_list_t *list = 0;
	addr_t *addr = 0;
	
	sipp_cb_config_update(config, NULL, NULL);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_SIPP_PROXY_PORT, sipp_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY, sipp_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY_MOBILITY_SUPPORT, sipp_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_SIPP_TUNNEL_PROXY, sipp_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_SIPP_FORCE_PROXY, sipp_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_CALL_LOG_SHOW_PATHINFO, sipp_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_CALL_LOG_SHOW_DROPPED, sipp_cb_config_update);

	/* this is for osip2 */
	ASSERT_ZERO(parser_init(), err);
        ASSERT_TRUE(sipp_mps = ship_list_new(), err);
        ASSERT_TRUE(call_log = ship_list_new(), err);

	ASSERT_TRUE(prox_resps = ship_ht_new(), err);

	/* .. */
        ASSERT_TRUE(relays = ship_list_new(), err);
        ASSERT_TRUE(gateways = ship_list_new(), err);
	ASSERT_ZERO(sipp_load_routing(), err);
	processor_tasks_add_periodic(sipp_update_relay_registrations, SIPP_RELAY_REGISTRATION_TIME / 2);

        LOG_INFO("initializing legacy sip proxies on port %d..\n", sip_proxy_port);
	ASSERT_TRUE(sipp_all_listeners = ship_list_new(), err);

	/* */
	ASSERT_TRUE(tmp = processor_config_string(config, P2PSHIP_CONF_SIPP_PROXY_IFACES), err);
	ASSERT_ZERO(ship_tokenize_trim(tmp, strlen(tmp), &ifs, &ifs_c, ','), err);
	ASSERT_ZERO(conn_validate_ifaces(ifs, ifs_c), err);
	ASSERT_TRUE(list = ship_list_new(), err);
	conn_getips(list, ifs, ifs_c, sip_proxy_port);
	
	/* loop ... */
	while ((addr = ship_list_pop(list))) {
		LOG_INFO("\tsip UDP proxy on %s\n", addr->addr);
		addr->type = IPPROTO_UDP;
		ASSERT_TRUE(lis = sipp_listener_new(addr), err);
		ASSERT_ZERO(ident_addr_addr_to_sa(addr, &sa, &salen), err);
		lis->socket = netio_new_packet_reader(sa, salen,
						      sipp_cb_datagram_got);
		if (lis->socket == -1)
			goto err;
		ship_list_add(sipp_all_listeners, lis);
		lis = 0;
		
		/* start tcp listener(s) for the same addr */
		LOG_INFO("\tsip TCP proxy on %s\n", addr->addr);
		addr->type = IPPROTO_TCP;
		ASSERT_TRUE(lis = sipp_listener_new(addr), err);
		lis->socket = netio_new_listener(sa, salen,
						 sipp_cb_tcpconn_got);
		if (lis->socket == -1)
			goto err;
		ship_list_add(sipp_all_listeners, lis);
		lis = 0;
		freez(addr);
		freez(sa);			
	}

	ASSERT_ZERO(ac_init(config), err);
	
	/* register the sipp service */
	ASSERT_ZERO(ident_service_register(&sipp_service), err);
	ASSERT_ZERO(sipp_mp_init(), err);

	ASSERT_TRUE(sipp_client_handlers = ship_list_new(), err);

	//sipp_register_client_handler(test_client_handler, NULL);

        ret = 0;
	goto end;
 err:
        LOG_ERROR("failed to init legacy sip proxy listener\n");
 end:
	ship_tokens_free(ifs, ifs_c);
	ship_list_empty_free(list);
	ship_list_free(list);
        sipp_listener_close(lis);
	freez(addr);
	freez(sa);
	return ret;
}


void
sipp_close()
{
        ship_list_t *liss = NULL;
	LOG_INFO("closing the legacy sip proxy\n");
	
	ship_list_empty_with(sipp_client_handlers, ship_pack_free);
	ship_list_free(sipp_client_handlers);
	sipp_client_handlers = NULL;

	sipp_mp_close_sys();
	ac_close();
        if (sipp_mps) {
                sipp_mp_close_all();
                ship_list_free(sipp_mps);
        }

	ship_ht_empty_free(prox_resps);
	ship_ht_free(prox_resps);
	prox_resps = NULL;
	
	/* spurious netio packets might interrupt this */
	liss = sipp_all_listeners;
	sipp_all_listeners = NULL;
	ship_list_empty_with(liss, sipp_listener_free);
	ship_list_free(liss);

	ship_list_empty_with(call_log, sipp_call_log_free);
	ship_list_free(call_log);

	ship_list_empty_with(relays, sipp_relay_free);
	ship_list_free(relays);
	
	ship_list_empty_with(gateways, sipp_gateway_free);
	ship_list_free(gateways);
}


/* utility func */
char *
sipp_url_to_short_str(osip_uri_t *url)
{
        char *str;
        str = NULL;
        if (url->username && url->host) {
                str = (char*)mallocz(strlen(url->username ) +
                                     strlen(url->host) + 2);
                if (str) {
                        strcpy(str, url->username);
                        strcat(str, "@");
                        strcat(str, url->host);
                }
        }
        return str;
}

/* shortens the aor, removing any multiparty groups */
static char *
sipp_real_aor(char *aor)
{
	char *p1, *p2;
	if (aor && (p1 = strchr(aor, '+'))) {
		if ((p2 = strchr(p1, '@'))) {
			while (*p2)
				*(p1++) = *(p2++);
		}
		*p1 = '\0';
	}
	return aor;
}

/* extracts the group code from a sip aor */
/*
static char *
sipp_aor_group_code(char *aor)
{
	char *p1, *p2;
	if (!aor)
		return aor;
	
	p1 = p2 = aor;
	while ((*p1) && (*p1 != '+')) p1++;
	p1++;
	while ((*p1) && (*p1 != '@')) *(p2++) = *(p1++);
	*p2 = '\0';
	return aor;
}
*/

/* called when an event has been processed by the processor */
static void
sipp_queued_sent(char *to, char *from, service_type_t service,
		 int code, char *return_data, int data_len, void *ptr)
{
	sipp_request_t* req = ptr;
	ship_lock(req);
        LOG_VDEBUG("The SIP packet was sent with code %d\n", code);
	if (code) {
#ifndef IGNORE_VIAS
		if (req && req->evt && req->evt->sip && 
		    !MSG_IS_RESPONSE(req->evt->sip)) {
			osip_via_t* via = (osip_via_t*)osip_list_get(OSIPMSG_PTR(req->evt->sip->vias), 0);
			if (via)
				osip_list_remove(OSIPMSG_PTR(req->evt->sip->vias), 0);
			osip_via_free(via);
		}
#endif
		/* todo: intepret the code better! */
		sipp_send_response(req, 404);
	}
	ship_obj_unlockref(req);
}


/* return != 0 on failures - the caller should then take care of the packet! */
static int
sipp_handle_message_do(sipp_request_t *req)
{
        osip_event_t* evt;
        osip_message_t* sip;
        char *fulltourl = 0, *fullfromurl = 0, *toident = 0;;
        osip_header_t *h;
        int expire, alreadyseen, ret = -1, same_domain = 0;
        ident_t *ident = 0;

	/* lock for processing */
	ship_lock(req);
        ASSERT_TRUE(evt = req->evt, end);
        ASSERT_TRUE(sip = evt->sip, end);

	/* have we seen this request already? */
	alreadyseen = sipp_check_and_mark(req->evt->sip, "req", 0);

        /* to & expire used by all */
	ASSERT_ZERO(sipp_get_sip_aors(sip, &fullfromurl, &fulltourl, 0), end);

	LOG_DEBUG("got a %s %s for %s -> %s\n", 
		  sip->sip_method, (MSG_IS_RESPONSE(sip)? "response":"request"),
		  fullfromurl, fulltourl);
	
	/* do some domain checks .. */
	if (fulltourl && fullfromurl) {
		char *d1 = strchr(fulltourl, '@');
		char *d2 = strchr(fullfromurl, '@');
		if (d1 && d2 && !strcmp(d1,d2))
			same_domain = 1;
	}
	
	/* this is for gateway'ing & responses to gateway'd requests */
	ASSERT_TRUE(toident = sipp_find_to_ident(fullfromurl, fulltourl), end);

        h = NULL;
        osip_message_get_expires(sip, 0, &h);
        if (h) {
                expire = atoi(h->hvalue);
        } else {
                expire = 3600;
        }

        ident = NULL;
        if (!MSG_IS_REGISTER(sip)) {
                ident = (ident_t *)ident_find_by_aor(fullfromurl);
                if (!ident || !ident_registration_is_valid(ident, SERVICE_TYPE_SIP)) {
			ship_obj_unlockref(ident);
			ident = NULL;
                }
        }

	/* if we have a gateway identity registered, we should pick that for ident now .. */
	if (!ident)
		ident = sipp_get_gateway_ident(fullfromurl, fulltourl);
	
        if (MSG_IS_REGISTER(sip)) {
		//int retcode = 0;
		osip_contact_t *c;
		addr_t addr;
		bzero(&addr, sizeof(addr));
		
		/* process only once */
		if (alreadyseen) 
			goto end_noresponse;
		
		/* get contact address */
		if (!osip_message_get_contact(sip, 0, &c) &&
		    c->url) {
			if (c->url->port)
				addr.port = atoi(c->url->port);
			else
				addr.port = 5060;
			strcpy(addr.addr, c->url->host);
		} else {
			addr.port = req->from_addr.port;
			strcpy(addr.addr, req->from_addr.addr);
		}
		
		/* we should set ip type! */
		if (strchr(addr.addr, ':'))
			addr.family = AF_INET6;
		else
			addr.family = AF_INET;

		LOG_DEBUG("using contact of %s, port %d\n", 
			  addr.addr, addr.port);
		addr.type = req->lis->addr.type;
			
		ret = ident_process_register(fulltourl, SERVICE_TYPE_SIP, &sipp_service,
						 (&addr), expire, req->lis);
		if (ret == 200) {
#ifdef CONFIG_ABS_ENABLED
			ship_list_t *list = 0;
#endif
			if (expire == 0)
				sipp_mp_clean_by_id(fulltourl);

#ifdef CONFIG_ABS_ENABLED
			ship_obj_unlockref(ident);
			ident = ident_find_by_aor(fulltourl);
			if (ident && (list = ship_list_new())) {
				contact_t *buddy = 0;
				char **subs = 0;
				
				/* this will clear old subscribes, so be careful .. */
				if (!addrbook_retrieve_contacts(list)) {
					if ((subs = (char**)mallocz((ship_list_length(list) + 1) * sizeof(char*)))) {
						void *ptr = 0;
						int p = 0;
						while ((buddy = ship_list_next(list, &ptr)))
							subs[p++] = buddy->sip_aor;
						
						sipp_buddy_handle_subscribes(ident, subs, expire, "");
						freez(subs);
					}
					while ((buddy = ship_list_pop(list)))
						ident_contact_free(buddy);
				}
				ship_list_free(list);
			}
#endif
		}
        } else if (!ident) {

		/* process only once */
		if (alreadyseen) 
			goto end_noresponse;
                LOG_WARN("request denied as the sender has no valid, registered identity (%s)!\n", 
			 fullfromurl);
		ret = 403;
        } else if (MSG_IS_PUBLISH(sip)) {

		/* process only once */
		if (alreadyseen) 
			goto end_noresponse;
		TODO("We should process & save the published presence!\n");
		
		/* what we should do:
		   
		- save the publish information in the ident use this
		- info together with the trust stuff to fend off
		  unwanted calls etc

		*/

		ret = 200;
        } else if (MSG_IS_SUBSCRIBE(sip)) {

		/* process only once */
		if (alreadyseen)
			goto end_noresponse;

		/* first, separately process those dummy reg-to-myselfs */
		if (!strcmp(fulltourl, fullfromurl)) {
			ret = 200;
		} else {
			/* todo: get id & event & to-header 'tag' parameter */
			char *callid;
			if ((callid = sipp_get_call_id(sip))) {
				if (sipp_buddy_handle_subscribe(ident, fulltourl, expire, callid)) {
					ret = 500;
				} else {
					ret = 202;
				}
				free(callid);
                        } else {
				ret = 489;
			}
		}
        } else if (MSG_IS_OPTIONS(sip) && 
		   ((same_domain && !memcmp("ping", fulltourl, strlen("ping"))) ||
		    (!strcmp(fulltourl, fullfromurl)))) {

		/* process only once */
		if (alreadyseen) 
			goto end_noresponse;
		
		LOG_DEBUG("detected keep-alive options\n");
		ret = 200;
        } else {
		/* ok, these are all messages that will be forwarded
		   to the other peer */

                /* check if the message is a bye! */
                if (MSG_IS_BYE(sip) || MSG_IS_CANCEL(sip)) {
			sipp_call_terminated(sip, 0);
                } else if (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip)) {

			/* mark that we should send trust parameters
			   to this person */
			trustman_mark_send_trust_to(ident->sip_aor, toident);	
		}

                /* process vias & body */
#ifndef IGNORE_VIAS
		if (MSG_IS_RESPONSE(sip)) {
			via = (osip_via_t*)osip_list_get(OSIPMSG_PTR(sip->vias), 0);
			if (via)
				osip_list_remove(OSIPMSG_PTR(sip->vias), 0);
			osip_via_free(via);
		} else {
			if (via = sipp_create_own_via(ident)) {
				osip_list_add(OSIPMSG_PTR(sip->vias), via, 0);
			}
		}
		
		/* remove any route's (sorry..) */
		while (rt = (osip_route_t*)osip_list_get(OSIPMSG_PTR(sip->routes), 0)) {
			osip_list_remove(OSIPMSG_PTR(sip->routes), 0);
			osip_route_free(rt);
		}
#endif

		if (sipp_process_sdp_message_body(sip, ident, toident, 0)) {
			LOG_WARN("Error processing the SIP message\n");
			ret = 400;
		} else {
                        char *buf = 0;                
                        size_t len;
                        if (osip_message_to_str(sip, &buf, &len) ||
			    conn_send_slow(toident, ident->sip_aor, SERVICE_TYPE_SIP, 
					   buf, len, req, 
					   sipp_queued_sent)) {
				ret = 500; //-2;
			} else {
				/* add a ref for the callback */
				ship_obj_ref(req);
				ret = 100;
			}
			freez(buf);
                }

		/* don't send codes on responses */
                if (MSG_IS_RESPONSE(sip))
			ret = 0; 
        }

	goto end;
 end_noresponse:
	ret = 0;
 end:	
	ship_obj_unlockref(ident);
	ship_unlock(req);
	freez(fulltourl);
	freez(fullfromurl);
	freez(toident);
        return ret;
}

/* from exosip */
static char *
osip_call_id_new_random ()
{
  char *tmp = (char *) osip_malloc (33);
  unsigned int number = osip_build_random_number ();

  sprintf (tmp, "%u", number);
  return tmp;
}

/* from exosip */
static char *
osip_to_tag_new_random (void)
{
  return osip_call_id_new_random ();
}


/* mostly ripped off partysip */
static int
sipp_create_sip_response(osip_message_t **dest, int status, osip_message_t *request)
{
        osip_generic_param_t *tag;
        osip_message_t *response;
        char *tmp;
        int pos;
        int i;
        
        *dest = NULL;
        i = osip_message_init (&response);
        if (i != 0)
                return -1;
        
        osip_message_set_version (response, osip_strdup ("SIP/2.0"));
        osip_message_set_status_code (response, status);
        
        tmp = osip_strdup(osip_message_get_reason (status));
        if (tmp == NULL)
                osip_message_set_reason_phrase (response, osip_strdup ("Unknown status code"));
        else
                osip_message_set_reason_phrase (response, tmp);
        
        osip_message_set_method (response, NULL);
        osip_message_set_uri (response, NULL);

        i = osip_to_clone (request->to, &(response->to));
        if (i != 0)
                goto mcubr_error_1;

        i = osip_to_get_tag (response->to, &tag);
        if (i != 0) {
                if (status == 200 && MSG_IS_REGISTER (request)) {
                        osip_to_set_tag (response->to, (char*)osip_to_tag_new_random ());
                } else if (status >= 200) {
                        osip_to_set_tag (response->to, (char*)osip_to_tag_new_random ());
                }
        }
        
        i = osip_from_clone (request->from, &(response->from));
        if (i != 0)
                goto mcubr_error_1;
        
        pos = 0;
        while (!osip_list_eol (OSIPMSG_PTR(request->vias), pos)) {
                osip_via_t *via;
                osip_via_t *via2;
                
                via = (osip_via_t *) osip_list_get (OSIPMSG_PTR(request->vias), pos);
                i = osip_via_clone (via, &via2);
                if (i != -0)
                        goto mcubr_error_1;
                osip_list_add (OSIPMSG_PTR(response->vias), via2, -1);
                pos++;
        }
        
        i = osip_call_id_clone (request->call_id, &(response->call_id));
        if (i != 0)
                goto mcubr_error_1;
        i = osip_cseq_clone (request->cseq, &(response->cseq));
        if (i != 0)
                goto mcubr_error_1;
        
        /* fun with veal */
        osip_message_set_server (response, "HIIT P2PSHIP");

        if (MSG_IS_STATUS_2XX(response) && MSG_IS_SUBSCRIBE(request)) {
                char tmp[1024];
                osip_header_t *event;
                  
                snprintf(tmp, 1024, "sip:%s@localhost", request->req_uri->username);
                osip_message_set_contact(response, tmp);
                
                /* copy event header */
                osip_message_header_get_byname(request, "event", 0, &event);
                if (event==NULL || event->hvalue==NULL) {
                        /* serach for compact form of Event header: "o" */
                        osip_message_header_get_byname(request, "o", 0, &event);
                        if (event==NULL || event->hvalue==NULL) {
                                OSIP_TRACE (osip_trace (__FILE__, __LINE__, OSIP_WARNING, NULL,
                                                        "missing event header in SUBSCRIBE request\n"));
                        }
                }
                
                if (event!=NULL && event->hvalue!=NULL)
                        osip_message_set_header(response, "Event", event->hvalue);
                
                /* copy all record-route values */
                pos=0;
                while (!osip_list_eol(OSIPMSG_PTR(request->record_routes), pos)) {
                        osip_record_route_t *rr;
                        osip_record_route_t *rr2;
                        rr = osip_list_get(OSIPMSG_PTR(request->record_routes), pos);
                        i = osip_record_route_clone(rr, &rr2);
                        if (i!=0) return -1;
                        osip_list_add(OSIPMSG_PTR(response->record_routes), rr2, -1);
                        pos++;
                }
        }
        
        if (MSG_IS_STATUS_2XX(response) && MSG_IS_REGISTER(request)) {
                /* copy "Path" informations */
                pos=0;
                while (!osip_list_eol(OSIPMSG_PTR(request->headers), pos)) {
                                osip_header_t *p;
                                osip_header_t *p2;
                                p = osip_list_get(OSIPMSG_PTR(request->headers), pos);
                                if (p!=NULL && p->hname!=NULL
                                    && 0==osip_strcasecmp(p->hname, "path")) {
                                        i = osip_header_clone(p, &p2);
                                        if (i!=0) return -1;
                                        osip_list_add(OSIPMSG_PTR(response->headers), p2, -1);
                                }
                                pos++;
                }

		/* jk: added for the Symbian clients, need contact */
                {
			osip_contact_t *c = NULL;
			char *c_str = NULL;

			if (!osip_message_get_contact(request, 0, &c) && 
			    !osip_uri_to_str_canonical(c->url, &c_str)) {
				osip_message_set_contact(response, c_str);
			} else if ((c_str = mallocz(1024))) {
				snprintf(c_str, 1024, "sip:%s@localhost", request->req_uri->username);
				osip_message_set_contact(response, c_str);
			}
			freez(c_str);
		}
        }
        
        *dest = response;
        return 0;
        
 mcubr_error_1:
        osip_message_free (response);
        return -1;
}

static void 
sipp_cb_tcpconn(int s, struct sockaddr *sa, socklen_t addrlen)
{
	sipp_listener_t *lis = sipp_get_listener_by_socket(s);

	if (!lis || netio_read(s, sipp_cb_data_got)) {		
		netio_close_socket(s);
	} else if (lis->queued_data) {
		/* we don't need to specify the addr */
		sipp_send_buf(lis->queued_data, lis->queued_data_len, lis, NULL);
		freez(lis->queued_data);
	}
}

/* this tries to send the given packet to the given address. If the
   listener is given, that is used for sending the stuff. Otherwise we
   try to find another listener similar enough (or create one).. */
static int 
sipp_send_buf(char *buf, int len, sipp_listener_t *lis, addr_t *to)
{
	int s = -1;
        struct sockaddr *sa = 0;
        socklen_t salen;
	
	if (!sipp_all_listeners)
		return -1;

	/* priority 1: use the same listener to send as we got it on */
	if (lis && sipp_get_listener_by_socket(lis->socket) && 
	    (conn_can_send_to(&(lis->addr), to) || lis->addr.type == IPPROTO_TCP)) {
		s = lis->socket;
	} else if (!to) {
		LOG_ERROR("trying to send to a null-address something!\n");
		return -2;
	} else if (to->type == IPPROTO_TCP) {
		
		/* todo: is this right?? shouldn't we always use the same
		   socket. if that's now available, then the client is down? */

		/* if tcp: create new lis & connect to the other host. */
		if (!ident_addr_addr_to_sa(to, &sa, &salen)) {
			
			ship_lock(sipp_all_listeners);
			s = netio_connto(sa, salen, sipp_cb_tcpconn);
			
			if ((lis = sipp_listener_new_queued(to, buf, len))) {
				lis->socket = s;
				ship_list_add(sipp_all_listeners, lis);
			} else {
				netio_close_socket(s);
				s = -1;
			}
			ship_unlock(sipp_all_listeners);
			
			freez(sa);
			if (s != -1)
				return 0;
		}
		
		LOG_ERROR("Got request for an non-existing listener / connection\n");
		return -1;
	} else if (to->type == IPPROTO_UDP && sipp_all_listeners) {
		/* find a suitable listener which we can use to send! */
		sipp_listener_t *lis = NULL;
		void *ptr = NULL;
		ship_lock(sipp_all_listeners); {
			while ((lis = (sipp_listener_t *)ship_list_next(sipp_all_listeners, &ptr))) {
				if (conn_can_send_to(&(lis->addr), to))
					break;
				lis = NULL;
			}
		} ship_unlock(sipp_all_listeners);
		
		if (lis)
			s = lis->socket;
	}

	if (to && to->type == IPPROTO_UDP) {
		if (!ident_addr_addr_to_sa(to, &sa, &salen)) {
			LOG_VDEBUG("Sending %d bytes over UDP %s:%d..\n", len, to->addr, to->port);
			if (s != -1)
				s = netio_packet_send(s, buf, len, sa, salen);
			else
				s = netio_packet_anon_send(buf, len, sa, salen);
			freez(sa);
			return s;
		}
	} else {
		LOG_VDEBUG("Sending %d bytes over TCP..\n", len);
		return netio_send(s, buf, len);
	}
	
	LOG_ERROR("Invalid transport type / sending error for contact %d\n", to->type);
	return -1;
}

int
sipp_register_client_handler(sipp_client_handler handler, void *data)
{
	void *ptr = 0;
	int ret = -1;
	
	ASSERT_TRUE(ptr = ship_pack("pp", handler, data), err);
	ship_list_add(sipp_client_handlers, ptr);
	ret = 0;
 err:
	return ret;
}

/* untested .. */
void
sipp_unregister_client_handler(sipp_client_handler handler, void *data)
{
	void *ptr = 0, *pack = 0;
	ship_lock(sipp_client_handlers);
	while ((pack = ship_list_next(sipp_client_handlers, &ptr))) {
		sipp_client_handler handler2;
		void *data2;
		ship_unpack_keep(pack, &handler2, &data2);
		if (handler2 == handler && data2 == data) {
			ship_list_remove(sipp_client_handlers, pack);
			ship_pack_free(pack);
			break;
		}
	}
	ship_unlock(sipp_client_handlers);
}

static int
sipp_run_client_handlers(ident_t *ident, const char *remote_aor, addr_t *contact_addr, char **buf, int *len)
{
	void *ptr = 0, *pack = 0;
	int ret = -1;

	/* filters: for ident, remote aor, contact addr,
	   sip-from, sip-to, message type */

	ASSERT_TRUE(ident && *buf, err);
	ship_lock(sipp_client_handlers);
	ret = 1;
	while (ret && *buf && (pack = ship_list_next(sipp_client_handlers, &ptr))) {
		sipp_client_handler handler;
		void *data;
		
		ship_unpack_keep(pack, &handler, &data);
		ret = handler(ident, remote_aor, contact_addr, buf, len, data);
	}
	ship_unlock(sipp_client_handlers);
	if (ret)
		ret = 1;
 err:
	return ret;
}

static int 
sipp_send_sip_to_ident(osip_message_t *sip, ident_t *ident, addr_t *from, const char *remote_aor)
{        
	addr_t *contact_addr = 0;
#ifdef CONFIG_DISABLE_LO_HIT_ROUTING
	addr_t addr;
#endif
	char *buf = 0;
	int len, ret = 0;

	/* create the msg */
	ASSERT_ZERO(osip_message_to_str(sip, &buf, (unsigned int*)&len), err); //, "Could not serialize sip message! Message dropped!\n");
	LOG_VDEBUG("Sending message:\n>>>>>\n%s\n<<<<<\n", buf);
	
	/* get the address where to send the packet! */
	if (ident && !(contact_addr = sipp_get_relay_addr(ident, sip)))
		contact_addr = ident_get_service_addr(ident, SERVICE_TYPE_SIP);
	
	/* if no contact, then send to where we got it from! */
	if (!contact_addr && from) {
		LOG_WARN("no contact addr found for %s, sending back to source!\n", (ident? ident->sip_aor:"<unknown>"));
		contact_addr = from;
	}

#ifdef CONFIG_DISABLE_LO_HIT_ROUTING
	/* if the target is our own HIT, then we're screwed! Change to
	   Our public IP, hope that it's ok! */
	TODO("We should check only if this is OUR hit!\n");
	if (contact_addr && hipapi_addr_is_hit(contact_addr) &&
	    !conn_get_lo(&addr)) {
		LOG_DEBUG("HIT detected as local UA address, using %s instead\n", addr.addr);
		addr.type = contact_addr->type;
		addr.port = contact_addr->port;
		contact_addr = &addr;
	}
#endif	

	/* let the output processors do their thing .. */
	ret = sipp_run_client_handlers(ident, remote_aor, contact_addr, &buf, &len);
	if (ret && buf) {
		ret = sipp_send_buf(buf, len, 
				    (sipp_listener_t *)ident_get_service_data(ident, SERVICE_TYPE_SIP), 
				    contact_addr);
	} else
		LOG_INFO("Dropping SIP packet as a client handler stole it\n");
	
 err:
	freez(buf);
	return ret;
}

/* this func checks if we have already sent a proxy-generated
   terminating response to this message / call. The message is
   identified by its cseq, from, to and callid, and terminating
   responses are considered to be all non 1xx responses. Timeout for
   this thing is 10 (?) seconds.
*/
static int
sipp_check_and_mark(osip_message_t *sip, char *prefix, int code)
{
	/* create the string */
	char *callid = 0;
        osip_generic_param_t *tag = 0;
	time_t *now = 0;
	int len = 0, size = 0;
	char *str = 0, *tmp = 0;
	int found = 0;
	ship_ht_entry_t *e = NULL;
	void *ptr = 0, *ptr2 = 0;
	
	/* if 1xx, don't bother */
	if ((code / 100) == 1)
		goto err;

	/* create the string */
	ASSERT_TRUE(now = mallocz(sizeof(time_t)), err);
	time(now);
	
	ASSERT_TRUE((tmp = append_str(prefix, str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(":t:", str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(sip->to->url->username, str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str("@", str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(sip->to->url->host, str, &size, &len)) && (str = tmp), err);
	
	if (!osip_to_get_tag(sip->to, &tag)) {
		ASSERT_TRUE((tmp = append_str(";", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(tag->gvalue, str, &size, &len)) && (str = tmp), err);
	}

	ASSERT_TRUE((tmp = append_str(",f:", str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(sip->from->url->username, str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str("@", str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(sip->from->url->host, str, &size, &len)) && (str = tmp), err);

	if (!osip_to_get_tag(sip->from, &tag)) {
		ASSERT_TRUE((tmp = append_str(";", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(tag->gvalue, str, &size, &len)) && (str = tmp), err);
	}
	
	if (sip->cseq) {
		ASSERT_TRUE((tmp = append_str(",cs:", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(sip->cseq->method, str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(sip->cseq->number, str, &size, &len)) && (str = tmp), err);
	}

	/* callid */
	if ((callid = sipp_get_call_id(sip))) {
		ASSERT_TRUE((tmp = append_str(",id:", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(callid, str, &size, &len)) && (str = tmp), err);
	}
	
	LOG_DEBUG("Checking for code %d response to %s..\n", code, str);
	
	/* lock the array, loop through, check. */
	ASSERT_TRUE(prox_resps, err);
	ship_lock(prox_resps);

	/* remove all over 60 sec old ones */
	while ((e = ship_list_next(prox_resps, &ptr))) {
		if ((*now) - (*((time_t*)e->value)) > 60) {
			ship_list_remove(prox_resps, e);
			freez(e->value);
			freez(e->key);
			freez(e);
			ptr = ptr2;
		} else if (!strcmp(str, e->key)) {
			found = 1;
		}
		ptr2 = ptr;
	}
	
	/* if not found .. */
	if (!found) {
		ship_ht_put_string(prox_resps, str, now);
		now = 0;
	} else {
		LOG_INFO("Supressing duplicate response..\n");
		//found = 0;
	}

	ship_unlock(prox_resps);
 err:
	freez(now);
	freez(str);
	freez(callid);
	return found;
}

void 
sipp_send_sip_to_ident_done(void *qt, int code)
{
	void **data_arr = qt;
	if (data_arr) {
		if (data_arr[0])
			osip_message_free(data_arr[0]);
		freez(data_arr[1]);
		freez(data_arr[2]);
		free(data_arr);
	}
}

static int
sipp_send_sip_to_ident_do(void *d, processor_task_t **wait, int wait_for_code)
{
	void **data_arr = (void**)d;
	osip_message_t* sip = data_arr[0];
	char *aor = data_arr[1];
	addr_t *addr = data_arr[2];
	ident_t *ident = 0;

	LOG_DEBUG("sending async message to %s..\n", aor);
	if ((ident = ident_find_by_aor(aor)) || addr) {
		sipp_send_sip_to_ident(sip, ident, addr, NULL);
		ship_obj_unlockref(ident);
	} else {
		LOG_WARN("should send msg to %s, but could not (no target found!)\n", aor);
	}
	return 0;
}

static int 
sipp_send_sip_to_ident_async(osip_message_t* sip, char *local_aor, addr_t *from)
{
	int ret = -1;
	void **data_arr = 0;
	osip_message_t* sip_copy = 0;
	
	ASSERT_ZERO(osip_message_clone(sip, &sip_copy), err);
	ASSERT_TRUE(data_arr = mallocz(sizeof(void*) * 4), err);
	ASSERT_TRUE(data_arr[0] = sip_copy, err);
	ASSERT_TRUE(data_arr[1] = strdup(local_aor), err);
	ASSERT_TRUE(data_arr[2] = mallocz(sizeof(addr_t)), err);
	memcpy(data_arr[2], from, sizeof(addr_t));
	
	if (processor_tasks_add(sipp_send_sip_to_ident_do, data_arr,
				sipp_send_sip_to_ident_done)) {
		ret = 0;
		data_arr = 0;
		sip_copy = 0;
	}
 err:
	if (sip_copy)
		osip_message_free(sip_copy);
	if (data_arr) {
		freez(data_arr[1]);
		freez(data_arr[2]);
		free(data_arr);
	}
	return ret;
}

/* Calls to send a reply to the given message */
static int
sipp_send_response(sipp_request_t *req, int code)
{
        int ret = -1;
        osip_message_t* resp = 0;
	
	/* check for already-send terminating responses */
	if (sipp_check_and_mark(req->evt->sip, "resp", code))
		return 0;

	/* if this is a ack, then forget this .. */
	if (MSG_IS_ACK(req->evt->sip)) {
		ret = 0;
	} else if (!sipp_create_sip_response(&resp, code, req->evt->sip)) {
		ret = sipp_send_sip_to_ident_async(resp, req->local_aor, &(req->from_addr));
        }
        
        osip_message_free(resp);
        return ret;
}

/* Calls to send a reply to the given message */
static int
sipp_send_remote_response(osip_message_t* sip, int code, char *sip_aor, ident_t *ident)
{
        int ret = -1;
        osip_message_t* resp = 0;
	char *buf = 0;
	size_t len = 0;

	/* check for responses */
	if (sipp_check_and_mark(sip, "resp", code))
		return 0;
	
	/* dtn: try to establish a 'fast' connection after positive
	   responses to invites? */

        if (!sipp_create_sip_response(&resp, code, sip) &&
	    !osip_message_to_str(resp, &buf, &len) && 
	    !conn_send_slow(sip_aor, ident->sip_aor, 
			    SERVICE_TYPE_SIP,
			    buf, len, NULL, NULL))
		ret = 0;
	
        if (resp)
		osip_message_free(resp);
	freez(buf);
        return ret;
}

/* the sipp register */
static struct processor_module_s processor_module = 
{
	.init = sipp_init,
	.close = sipp_close,
	.name = "sipp",
#ifdef CONFIG_HIP_ENABLED
	.depends = "netio,netio_ff,hipapi,ident,olclient,conn",
#else
	.depends = "netio,netio_ff,ident,olclient,conn",
#endif
};

/* register func */
void
sipp_register() {
	processor_register(&processor_module);
}


/******** call log handling **********/

/* frees it up */
static void
sipp_call_log_free(call_log_entry_t* e)
{
	if (e) {
		freez(e->id);
		freez(e->remote_aor);
		freez(e->local_aor);
		freez(e);
	}
}

/* creates a new one */
static call_log_entry_t*
sipp_call_log_new(char *str, char *local_aor, char *remote_aor, int remote)
{
	call_log_entry_t* ret = 0;
	ASSERT_TRUE(ret = mallocz(sizeof(call_log_entry_t)), err);
	ASSERT_TRUE(ret->id = strdup(str), err);
	ASSERT_TRUE(ret->remote_aor = strdup(remote_aor), err);
	ASSERT_TRUE(ret->local_aor = strdup(local_aor), err);
	ret->remotely_initiated = remote;
	ret->started = time(NULL);
	return ret;
 err:
	sipp_call_log_free(ret);
	return 0;
}

/* tries to find the matching log entry from the 'db' */
static call_log_entry_t*
sipp_call_log_find_or_create(char *str, char *local_aor, char *remote_aor, int remote)
{
	void *ptr = 0, *last = 0;
	call_log_entry_t *e = 0;
	time_t now;
	
	/* hm, this doesn't clear the list if we get lots of MESSAGEs */
	time(&now);
	while (!e && (e = ship_list_next(call_log, &ptr))) {
		if (strcmp(e->id, str)) {
			/* remove old entries */
			if ((now - e->last_seen) > (3600*12)) {
				ship_list_remove(call_log, e);
				sipp_call_log_free(e);
				ptr = last;
			}
			e = 0;
		}
		last = ptr;
	}
	
	if (!e && (e = sipp_call_log_new(str, local_aor, remote_aor, remote)))
		ship_list_push(call_log, e);
	
	return e;
}

#define CONVERSATION_MAX_IDLE (30 * 60)

/* records a call / message / communication attempt */
static void 
sipp_call_log_record(char *local_aor, char *remote_aor, 
		     osip_event_t *evt, int verdict, int remote)
{
	osip_message_t *sip;
	char *str = 0, *tmp = 0, *callid = 0, *local_sip = 0, *remote_sip = 0;
	int size = 0, len = 0;
	call_log_entry_t *e = 0;
	time_t now;

	if (!evt || !(sip = evt->sip) || MSG_IS_RESPONSE(sip))
		return;
	
	/* this shouldn't happen.. */
	if (!local_aor || !remote_aor) {
		LOG_WARN("request to record call log for '%s' and '%s'\n", local_aor, remote_aor);
		return;
	}
	
	ASSERT_ZERO(sipp_get_sip_aors(sip, &local_sip, &remote_sip, remote), err);
	ship_lock(call_log);
	time(&now);

	/* send event when new comes, or the state of an old one changes! */
        if (MSG_IS_INVITE(sip)) {
		
		ASSERT_TRUE(callid = sipp_get_call_id(sip), err);
		ASSERT_TRUE((tmp = append_str("invite,id:", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(callid, str, &size, &len)) && (str = tmp), err);
		
		ASSERT_TRUE(e = sipp_call_log_find_or_create(str, local_sip, remote_sip, remote), err);
	} else if (MSG_IS_MESSAGE(sip)) {
		
		/* check last seen. if idle for > 1 hrs, then consider this a new conversation */
		ASSERT_TRUE(e = sipp_call_log_find_or_create("message", local_sip, remote_sip, remote), err);
		if (e->last_seen && ((now - e->last_seen) > CONVERSATION_MAX_IDLE)) {
			/* change the id of this entry. it is not
			   longer the 'current' conversation. */
			free(e->id);
			e->id = 0;
			e->id = strdup("message_old");

			ASSERT_TRUE(e = sipp_call_log_find_or_create("message", local_sip, remote_sip, remote), err);
		}
	}
	
	/* go quietly to the end */
	if (!e)
		goto err;

	e->last_seen = now;
	if (e->verdict != verdict) {
		reg_package_t *r = 0;
		char *name = remote_aor;
		trustparams_t *params = 0;
		char *status = 0;
		
		/* set the trustparams as they were when the verdict was made.. */
		if ((params = trustman_get_valid_trustparams(remote_aor, local_aor))) {
			e->pathlen = params->pathfinder_len;
			ship_unlock(params->queued_packets);
		} else
			e->pathlen = -1;

		/* get the name of the remove person! */
		if ((r = ident_find_foreign_reg(remote_aor)) && r->name) {
			name = r->name;
		}
		
		if (r && r->status && (status = mallocz(strlen(r->status) + 5))) {
			sprintf(status, " [%s]", r->status);
		}
		
		e->verdict = verdict;
		if (remote) {
			const char *type = NULL;
			if (MSG_IS_INVITE(evt->sip))
				type = TYPE_CALL_STRING;
			else if (MSG_IS_MESSAGE(evt->sip))
				type = TYPE_CHAT_STRING;
			
			if (verdict != AC_VERDICT_ALLOW) {
				if (call_log_show_dropped)
					ui_popup("%s from %s%s dropped!\n", type, name, (status? status : ""));
			} else if (call_log_show_pathinfo) {
				if (e->pathlen > 1) {
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
					/* find the buddies with which
					   this guy has a connection
					   with */
					ident_t *ident = NULL;
					ship_list_t *list = NULL;
					
					if ((list = ship_list_new()) && 
					    (ident = ident_find_by_aor(local_aor)) &&
					    (!ident_data_bb_find_connections_on_level(ident->buddy_list, remote_aor, e->pathlen-2, list)) &&
					    ship_list_first(list)) {
						char *buf = 0;
						int blen = 0, dlen = 0, c = 0;
						void *ptr = 0;
						buddy_t *buddy = 0;

						/* create a 'john, mary, bob + 3 more' string */
						while (c < 3 && (buddy = ship_list_next(list, &ptr))) {
							if (dlen)
								buf = append_str(", ", buf, &blen, &dlen);
							buf = append_str(buddy->name, buf, &blen, &dlen);
							c++;
						}

						if ((c = ship_list_length(list) - c) > 0)
							buf = append_str("+ more", buf, &blen, &dlen);
						
						if (e->pathlen > 2) {
							ui_popup("%s from %s%s, %d hops away (through %s)\n", type, name, (status? status : ""), e->pathlen, buf);
						} else {
							ui_popup("%s from %s%s (friend of %s)\n", type, name, (status? status : ""), buf);
						}
						freez(buf);
					} else {
#endif
						if (e->pathlen > 2) {
							ui_popup("%s from %s%s, %d hops away\n", type, name, (status? status : ""), e->pathlen);
						} else {
							ui_popup("%s from %s%s (a friend's friend)\n", type, name, (status? status : ""));
						}
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
					}
					ship_list_free(list);
					ship_obj_unlockref(ident);
#endif
				} else if (e->pathlen == 1) {
					ui_popup("%s from %s%s (your friend)\n", type, name, (status? status : ""));
				} else {
					ui_popup("%s from %s%s, no trustpath found!\n", type, name, (status? status : ""));
				}
			}
		}
		freez(status);
		ship_unlock(r);
		
		// todo: ship_obj' this!
		/* notify! .. its a bit risky to use the e struct directly, but ..*/
		processor_event_generate("sip_log", e, NULL);
	}
 err:
	freez(remote_sip);
	freez(local_sip);
	freez(callid);
	freez(str);
	ship_unlock(call_log);
}
