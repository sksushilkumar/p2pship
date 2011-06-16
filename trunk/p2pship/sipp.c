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
#ifdef CONFIG_OP_ENABLED
#include <opconn.h>
#endif
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

/* whether to handle the presence logic natively within this module */
#define NATIVE_PRESENCE 1

#ifdef NATIVE_PRESENCE
static int sipp_presence_handler(sipp_request_t *req, const char *remote_aor,
				 int *response_code, void *data);
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
static int sipp_media_proxy_force4;

/* the list of relay configurations */
static ship_list_t *relays = 0;

/* the list of gateways */
static ship_list_t *gateways = 0;

/* prototypes */
static int sipp_handle_remote_message_do(sipp_request_t *req);
static int sipp_handle_local_message_do(sipp_request_t *req);
static int sipp_send_response(sipp_request_t *req, int code);
static int sipp_send_buf(char *buf, int len, sipp_listener_t *lis, addr_t *to);
static int sipp_send_sip_to_ident(osip_message_t *sip, ident_t *ident, addr_t *from, const char *remote_aor);
static int sipp_check_and_mark(osip_message_t *sip, char *prefix, int code);
static int sipp_receive_remote_message(char *msg, int msglen, ident_t *ident, char *sip_aor, service_type_t service);
static char *sipp_real_aor(char *aor);
static int sipp_run_postprocessors(sipp_request_t *req, const char *remote_ident_aor, int *respcode);

static int sipp_send_sip_to_ident_async(osip_message_t* sip, char *local_aor, addr_t *from, char* remote_aor);

/* sipp_requests */
static void sipp_request_free(sipp_request_t *req);
static int sipp_request_init(sipp_request_t *ret, osip_event_t *evt);
static void sipp_cb_data_got(int s, char *data, ssize_t len);

SHIP_DEFINE_TYPE(sipp_request);

/* the list of callids */
static ship_list_t *call_log = 0;

/* frees it up */
static void sipp_call_log_free(call_log_entry_t* e);
static void sipp_call_log_record(sipp_request_t *req, int verdict);

/* call or chat? */
static const char *TYPE_CALL_STRING = "Call";
static const char *TYPE_CHAT_STRING = "Conversation";

/* whether to show the dropped / info popups */
static int call_log_show_dropped = 1;
static int call_log_show_pathinfo = 1;

/* the sip service description / handle */
static struct service_s sipp_service =
{
 	.data_received = sipp_receive_remote_message,
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

/* fetches the address of the proxy that is known to the given SIP
   UA */
void
sipp_get_addr_to_ua_or_default(ident_t *ident, addr_t *addr)
{
	if (sipp_get_addr_to_ua(ident, addr)) {
		strcpy(addr->addr, "127.0.0.1");
		addr->port = sip_proxy_port;
	}
}


#ifndef IGNORE_VIAS
static osip_record_route_t *
sipp_create_own_rr(ident_t *ident)
{
        osip_record_route_t *rr = NULL;
	addr_t addr;

	sipp_get_addr_to_ua_or_default(ident, &addr);
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

	sipp_get_addr_to_ua_or_default(ident, &addr);
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

int
sipp_get_sip_aors(osip_message_t *sip, char **fullfromurl,  char **fulltourl, int remote)
{
	char *from = NULL, *to = NULL;

	ASSERT_TRUE(sip->to && sip->from, err);
        ASSERT_TRUE(to = sipp_url_to_short_str(sip->to->url), err);
        ASSERT_TRUE(from = sipp_url_to_short_str(sip->from->url), err);
        
        if ((MSG_IS_RESPONSE(sip) && !remote) ||
	    (!MSG_IS_RESPONSE(sip) && remote)) {
                ship_swap(from, to);
        }
	
	*fulltourl = to;
	*fullfromurl = from;
	return 0;
 err:
	freez(to);
	freez(from);
	return -1;
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
	freez(req->full_local_aor);
	freez(req->full_remote_aor);
	freez(req->from_addr);
	ship_obj_unref(req->ident);
}

/* creates a request */
static int
sipp_request_init(sipp_request_t *ret, osip_event_t *evt)
{
	ASSERT_TRUE(evt && evt->sip && evt->sip->from && evt->sip->to, err);
	ASSERT_ZERO(sipp_get_sip_aors(evt->sip, &ret->full_local_aor, &ret->full_remote_aor, 0), err);
	ASSERT_TRUE(ret->local_aor = strdup(ret->full_local_aor), err);
	ASSERT_TRUE(ret->remote_aor = strdup(ret->full_remote_aor), err);
	sipp_real_aor(ret->local_aor);
	sipp_real_aor(ret->remote_aor);
	
	/* now we take ownership */
	ret->evt = evt;
        return 0;
 err:
	return -1;
}

/* shorthand for creating a complete request */
static sipp_request_t*
sipp_request_new(ident_t *ident, osip_event_t *evt, const int remote, const int internal)
{
	sipp_request_t *ret = NULL;
	
        ASSERT_TRUE(ret = (sipp_request_t*)ship_obj_new(TYPE_sipp_request, evt), err);
	if (remote) {
		ship_swap(ret->local_aor, ret->remote_aor);
		ship_swap(ret->full_local_aor, ret->full_remote_aor);
		ret->remote_msg = 1;
		if ((ret->ident = ident))
			ship_obj_ref(ret->ident);
	}
	ret->internally_generated = internal;
	return ret;
 err:
	ship_obj_unref(ret);
	return NULL;
}

static void
sipp_cb_packetfilter(sipp_request_t *req, int verdict)
{
        /* put on queue for processing */
	int respcode = -1;
	const char *type = (req->remote_msg? "remote":"local");

	/* record the call / conversation .. */
	LOG_VDEBUG("Hot back from AC for %s, verdict %d\n", type, verdict);

	switch (verdict) {
	case AC_VERDICT_NONE:
	case AC_VERDICT_ALLOW:
		sipp_call_log_record(req, verdict);
		if (req->remote_msg)
			respcode = sipp_handle_remote_message_do(req);
		else
			respcode = sipp_handle_local_message_do(req);
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
	LOG_DEBUG("Processed the %s SIP message with return code %d\n", type, respcode);
	if (respcode && !MSG_IS_RESPONSE(req->evt->sip)) {
		if (respcode < 0)
			respcode = 500;
		
		sipp_send_response(req, respcode);
	}
	
	ship_obj_unref(req);
}

/* processes received messages (datagrams) */
static int
sipp_handle_local_message(char *msg, int len, sipp_listener_t *lis, addr_t *addr, const int filter, const int internal)
{
        osip_event_t *evt = 0;
        sipp_request_t *req = 0;
	int ret = -1;
	int cl, count = 0;
	int pos = 0;

	LOG_DEBUG("got %d bytes of data from %s:%d\n", len, addr->addr, addr->port);
        LOG_VDEBUG("data: %s\n", msg);

        ASSERT_TRUE(evt = osip_parse(msg, len), err);
        ASSERT_TRUE(evt->sip, err);

	/* check that we actually got the whole message! */
	if (evt->sip->content_length && evt->sip->content_length->value) {
		osip_body_t *body;
		cl = atoi(evt->sip->content_length->value);
		while (cl > 0 && (body = (osip_body_t *)osip_list_get(OSIPMSG_PTR(evt->sip->bodies), pos))) {
			count += body->length;
			pos++;
		}
		
		if (count < cl) {
			LOG_DEBUG("incomplete message, expected %d, but got %d bytes\n", cl, count);
			ret = 1;
			goto err;
		}
	}
	
	/* the local identity is resolved in handle_local_message_do() */
	ASSERT_TRUE(req = sipp_request_new(NULL, evt, 0, internal), err);
	evt = NULL;
	req->lis = lis;
	if (addr) {
		ASSERT_TRUE(req->from_addr = mallocz(sizeof(addr_t)), err);
		memcpy(req->from_addr, addr, sizeof(addr_t));
	}
	
	/* take this through the AC module */
	ASSERT_ZERO(ac_packetfilter(req, sipp_cb_packetfilter, filter), err);
        return 0;
 err:
        LOG_VDEBUG("invalid message!\n");
        if (req)
		ship_obj_unref(req);
        if (evt)
                osip_event_free(evt);
	return ret;
}

/* injects local messages */
int 
sipp_inject_local_message(char *msg, int len, const int filter)
{
	addr_t addr;
	bzero(&addr, sizeof(addr));
	return sipp_handle_local_message(msg, len, NULL, &addr, filter, 1);
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

/* extracts all contacts into an array */
static int
sipp_sdp_extract_all_contacts(char *bodystr, int bodystrlen, ship_list_t *list)
{
	addr_t* addr = 0;
	char *p = bodystr;
	while (p) {
		p++;
		if ((p = strstr(p, "c="))) { //, bodystrlen-(p-bodystr)))) {
			ASSERT_TRUE(addr = mallocz(sizeof(*addr)), err);
			if (!sipp_sdp_extract_contact(p, bodystrlen - (int)(p - bodystr), addr))
				ship_list_add(list, addr);
			else
				freez(addr);
		}
	}
 err:
	return ship_list_length(list);
}


static void
sipp_sdp_process_proxy_address(int remotely_got, addr_t *target_addr, const addr_t *original_new_addr, addr_t *new_addr)
{
	memcpy(new_addr, original_new_addr, sizeof(*new_addr));
		
	/* todo gw: if we are in gateway mode, we should not have the
	   mobility hack enabled ever! */
	TODO("check whether we are in proxy mode, disable mobility hack\n");
		
	/* support for mobility: replace it with lo, as that doesn't change during mobility.
	 * Also: this takes care of LSI's (1.0.0.1) */
	if (!remotely_got && (target_addr->family == AF_INET) &&
	    sipp_media_proxy_mobility) {
		LOG_DEBUG("using the mobility hack\n");
		strcpy(target_addr->addr, "127.0.0.1");
	}
				
	/* if we are proxying traffic to the remote, we might end up assigning an ipv6
	   local address even though the remote does ipv4. This can be as our local client
	   for some reason chooses to use ipv6 for signalling. But this can turn out to be
	   a problem if its media generator doesn't support ipv6 after all. */
	/* actually, this should be also for the mobility case; in that case, the address
	   might already by in ipv4, but we might have a public ip here (which could change 
	   due to mobility..) */
	if (remotely_got && (target_addr->family == AF_INET) &&
	    (sipp_media_proxy_mobility || (sipp_media_proxy_force4 && (new_addr->family == AF_INET6)))) {
		LOG_DEBUG("using the mobility / force-ipv4 hack\n");
		strcpy(new_addr->addr, "127.0.0.1");
		new_addr->family = AF_INET;
	}
}


static int
sipp_sdp_replace_addr_create_proxies(char *bodystr, int bodystrlen, char **newmsg, int *newmsglen,
				     char *callid, char *local_aor, char *remote_aor, addr_t *original_new_addr, 
				     int sendby, int remotely_got)
{
	int newbodysize, newbodylen = 0;
        char *newbodystr = NULL;

	char *ls, *de;
	size_t len = bodystrlen;

	char **tokens = NULL;
        int toklen = 0;

        addr_t *target_addr = 0;
        addr_t *new_addr;
 	void *ptr = 0;
	char *tmp = NULL;
	
	int ret = -1, mc = 0, cc = 0;
	ship_list_t *targets = 0, *new_addrs = 0;
	
	newbodysize = len + 512;
	ASSERT_TRUE(newbodystr = (char*)mallocz(newbodysize), err);

	/* Not so elegant, but: We need to find all c lines and
	   process those (turn them into new_addr, possibly changing
	   new_addr AND the c-address along the way.  This so that we
	   have a clear in/out address for the mediaproxies when
	   encountering the m-lines.  c lines MAY come after the m,
	   and we are doing the replacement on-the-fly which is why
	   this has to be done beforehand separately! */
	ASSERT_TRUE(targets = ship_list_new(), err);
	ASSERT_TRUE(new_addrs = ship_list_new(), err);

	/* end if we don't have anything to modify in the body! */
	if (!sipp_sdp_extract_all_contacts(bodystr, bodystrlen, targets)) {
		memcpy(newbodystr, bodystr, bodystrlen);
		newbodylen = bodystrlen;
		goto done;
	}

	while ((target_addr = ship_list_next(targets, &ptr))) {
		ASSERT_TRUE(new_addr = mallocz(sizeof(*new_addr)), err);
		sipp_sdp_process_proxy_address(remotely_got, target_addr, original_new_addr, new_addr);
		ship_list_add(new_addrs, new_addr);
	}
	
	/* find the m='s, start the mediaproxies! */
	ls = bodystr;
	de = bodystr + len;
	do {
		char *le = ls;

		while (le < de && (*le) != '\n') le++;
		if (le < de) le++;
		if (le != ls) {
			int slen = le-ls;
			if (!memcmp(ls, "c=", 2) || !memcmp(ls, "m=", 2)) {
				char prefi[3];
				ASSERT_ZERO(ship_tokenize(ls+2, slen-2, &tokens, &toklen, ' '), err);

				switch (ls[0]) {
				case 'c':
					if (cc >= (ship_list_length(targets)))
						cc = ship_list_length(targets) - 1;
					target_addr = ship_list_get(targets, cc);
					new_addr = ship_list_get(new_addrs, cc);
					cc++;
					
					if (toklen == 3) {
						/* used to parse this, but that's already done! */
						LOG_DEBUG("replacing c's ip of %s to %s\n", target_addr->addr, new_addr->addr);
						
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
					if (mc >= (ship_list_length(targets)))
						mc = ship_list_length(targets) - 1;
					target_addr = ship_list_get(targets, mc);
					new_addr = ship_list_get(new_addrs, mc);
					mc++;
					
					if (toklen > 2) {
						char portstr[10];
						sipp_media_proxy_t *proxy = NULL;
						
						/* if port == 0, then ignore. */
						if (atoi(tokens[1])) {
							/* udp, please .. */
							target_addr->type = IPPROTO_UDP;
							target_addr->port = atoi(tokens[1]);
							
							/* check to find if we already have a proxy for that */
							if (!(proxy = sipp_mp_find(callid, target_addr, sendby))) {

								/* todo: we should check if udp / other from the medialine */
								new_addr->type = IPPROTO_UDP;
								ASSERT_TRUE(proxy = sipp_mp_create_new(callid, local_aor, 
												       remote_aor, tokens[0],
												       new_addr, target_addr, 
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

 done:
	(*newmsg) = newbodystr;
	(*newmsglen) = newbodylen;
	newbodystr = NULL;
	ret = 0;
 err:
	ship_tokens_free(tokens, toklen);
	ship_list_empty_free(targets);
	ship_list_free(targets);
	ship_list_empty_free(new_addrs);
	ship_list_free(new_addrs);

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

				// todo: isn't this the ident->sip_aor and remote_aor??
				ASSERT_ZERO(sipp_get_sip_aors(sip, &local_sip, &remote_sip, remotely_got), err);
				sipp_real_aor(local_sip);
				sipp_real_aor(remote_sip);
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
	
	LOG_DEBUG("call terminated by %s, checking for mediaproxies..\n", (remotely_got? "remote":"local"));
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

/*  */
static int
sipp_handle_remote_message_do(sipp_request_t *req)
{      
        char *tmp = NULL;
	int ret = -1;
	osip_message_t* sip = req->evt->sip;

	/* Use the ident that we received this on! */
	if (req->ident) {
		ship_lock(req->ident);
	} else {
		ASSERT_TRUE(req->ident = ident_find_by_aor(req->local_aor), err);
	}

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
		if (!sipp_get_relay_addr(req->ident, sip)) {
			ASSERT_TRUE(addr = ident_get_service_addr(req->ident, SERVICE_TYPE_SIP), err);
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
                if (!(rr = sipp_create_own_rr(req->ident)))
                        goto err;
                osip_list_add(OSIPMSG_PTR(sip->record_routes), rr, 0);

                if (!(via = sipp_create_own_via(req->ident)))
                        goto err;
                osip_list_add(OSIPMSG_PTR(sip->vias), via, 0);
#endif

		/* note: BYE / CANCEL cleanup is handled in call_log_record */
        }
	
	ret = 1100;

        ASSERT_ZERO(sipp_process_sdp_message_body(sip, req->ident, req->remote_aor, 1), err);
	
	/* add post processors here! */
	sipp_run_postprocessors(req, req->remote_aor, &ret);
	sip = req->evt->sip; // might have changed.

	if (ret > 1000) {
		if (sipp_send_sip_to_ident_async(sip, req->ident->sip_aor, NULL, req->remote_aor))
			ret = 500;
		else
			ret -= 1000;
	}
	goto end;
 err:
	LOG_WARN("Error while processing remotely got message.\n");
 end:
	ship_unlock(req->ident);
	return ret;
}

static int
sipp_handle_remote_message(char *msg, int msglen, ident_t *ident, char *remote_aor, const int filter, const int internal)
{
        int ret = -3;
        osip_event_t *evt = 0;
        sipp_request_t *req = 0;
	
        ASSERT_TRUE(evt = osip_parse(msg, msglen), err);
	ASSERT_TRUE(req = sipp_request_new(ident, evt, 1, internal), err);
	evt = 0;
	ASSERT_ZERO(ac_packetfilter(req, sipp_cb_packetfilter, filter), err);	
	return 0;
 err:
	LOG_WARN("An invalid remote message got, dropping it:\n>>>>>\n%s\n<<<<<\n", msg);
        if (req)
		ship_obj_unref(req);
        if (evt)
                osip_event_free(evt);
        return ret;
}


/* 'injects' a message to the system as if it had come from a remote
   source.  */
int
sipp_inject_remote_message(char *msg, int msglen, ident_t *ident, char *remote_aor, const int filter)
{
	return sipp_handle_remote_message(msg, msglen, ident, remote_aor, filter, 1);
}

/* processes remotely received messages (datagrams), called from
   conn.c, when this is registered as the service for that user..  */
static int
sipp_receive_remote_message(char *msg, int msglen, ident_t *ident, char *sip_aor, service_type_t service)
{
	return sipp_handle_remote_message(msg, msglen, ident, sip_aor, 1, 0);
}


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
		int newlen = 0;
		char *newbuf = 0;
		
		/* piece together the message & camouflage as 'data'.. */
		if (lis->queued_data && (lis->queued_data_len > 0)) {
			ASSERT_TRUE(newbuf = mallocz(lis->queued_data_len + len), err);
			memcpy(newbuf, lis->queued_data, lis->queued_data_len);
			memcpy(newbuf+lis->queued_data_len, data, len);
			data = newbuf;
			newlen = len + lis->queued_data_len;
			len = newlen;
		}

		/* ignore errors and complete, just do the incompletes */
                if (sipp_handle_local_message(data, len, lis, &(lis->addr), 1, 0) == 1) {
			freez(lis->queued_data);
			if (!newbuf) {
				ASSERT_TRUE(newbuf = mallocz(len), err);
				memcpy(newbuf, data, len);
				newlen = len;
			}
			lis->queued_data = newbuf;
			lis->queued_data_len = newlen;
			newbuf = 0;
		}
	err:
		freez(newbuf);
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
                sipp_handle_local_message(data, len, lis, &addr, 1, 0);
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
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY_FORCE4, 
					      &sipp_media_proxy_force4), err);

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
sipp_update_relay_registrations(void *data)
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
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY_FORCE4, sipp_cb_config_update);
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
	processor_tasks_add_periodic(sipp_update_relay_registrations, NULL, (SIPP_RELAY_REGISTRATION_TIME*1000) / 2);

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
#ifdef NATIVE_PRESENCE
	ASSERT_ZERO(sipp_register_hook(NULL, sipp_presence_handler, NULL), err);
#endif
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


/* Extracts and returns the sip aor from the osip structs. Returns a
   newly allocated copy. */
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

/* Shortens the aor, removing any multiparty etc groups, in-place */
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


/* Processes a locally received packet. This is called after the
   filtering and just before (a possible) forward of the message to
   the remote party.

   @return A response code to be sent to the source, < 0 on error, 0
   on nothing.
*/
static int
sipp_handle_local_message_do(sipp_request_t *req)
{
        osip_event_t* evt;
        osip_message_t* sip;
        char *remote_ident_aor = 0, *d1, *d2;
        osip_header_t *h;
        int expire, alreadyseen, ret = -1, same_domain = 0, same_aor = 0;

	/* lock for processing */
	ship_lock(req);
	ship_lock(req->ident);

        ASSERT_TRUE(evt = req->evt, err);
        ASSERT_TRUE(sip = evt->sip, err);

	/* have we seen this request already? */
	alreadyseen = sipp_check_and_mark(req->evt->sip, "req", 0);

	LOG_DEBUG("got a %s %s for %s -> %s\n", 
		  sip->sip_method, (MSG_IS_RESPONSE(sip)? "response":"request"),
		  req->full_local_aor, req->full_remote_aor);
	
	/* do some domain checks .. */
	d1 = strchr(req->full_remote_aor, '@');
	d2 = strchr(req->full_local_aor, '@');
	if (d1 && d2 && !strcmp(d1,d2))
		same_domain = 1;
	if (!strcmp(req->full_remote_aor, req->full_local_aor))
		same_aor = 1;
	
	/* this is for gateway'ing & responses to gateway'd requests */
	/* note: remote_ident_aor is now the p2pship ident aor of the remote
	   where this should be sent!  local_ident_aor is the one in the
	   message header!
	*/
	ASSERT_TRUE(remote_ident_aor = sipp_find_to_ident(req->full_local_aor, req->full_remote_aor), err);

        h = NULL;
        osip_message_get_expires(sip, 0, &h);
        if (h) {
                expire = atoi(h->hvalue);
        } else {
                expire = 3600;
        }

        if (!MSG_IS_REGISTER(sip)) {
		if (!req->ident)
			req->ident = ident_find_by_aor(req->local_aor);
                if (!req->ident || !ident_registration_is_valid(req->ident, SERVICE_TYPE_SIP)) {
			ship_obj_unlockref(req->ident);
			req->ident = NULL;
                }
        }

	/* if we have a gateway identity registered, we should pick that for ident now .. */
	/* note: here we find the gateway ident to use when receiving
	   signalling (responses) from the gateway adaptor that we
	   should route to a client of ours.. */
	if (!req->ident)
		req->ident = sipp_get_gateway_ident(req->full_local_aor, req->full_remote_aor);
	
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
		} else if (req->from_addr) {
			addr.port = req->from_addr->port;
			strcpy(addr.addr, req->from_addr->addr);
		}
		
		/* we should set ip type! */
		if (strchr(addr.addr, ':'))
			addr.family = AF_INET6;
		else
			addr.family = AF_INET;

		LOG_DEBUG("using contact of %s, port %d\n", 
			  addr.addr, addr.port);
		addr.type = req->lis->addr.type;
			
		ret = ident_process_register(req->remote_aor, SERVICE_TYPE_SIP, &sipp_service,
					     (&addr), expire, req->lis);
		
		if (ret == 200) {
#ifdef CONFIG_ABS_ENABLED
			ship_list_t *list = 0;
#endif
			if (expire == 0)
				sipp_mp_clean_by_id(req->full_remote_aor);

			ship_obj_unlockref(req->ident);
			req->ident = ident_find_by_aor(req->remote_aor);
#ifdef CONFIG_ABS_ENABLED
			if (req->ident && (list = ship_list_new())) {
				contact_t *buddy = 0;
				char **subs = 0;
				
				/* this will clear old subscribes, so be careful .. */
				if (!addrbook_retrieve_contacts(list)) {
					if ((subs = (char**)mallocz((ship_list_length(list) + 1) * sizeof(char*)))) {
						void *ptr = 0;
						int p = 0;
						while ((buddy = ship_list_next(list, &ptr)))
							subs[p++] = buddy->sip_aor;
						
						sipp_buddy_handle_subscribes(req->ident, subs, expire, "");
						freez(subs);
					}
					while ((buddy = ship_list_pop(list)))
						ident_contact_free(buddy);
				}
				ship_list_free(list);
			}
#endif
		}
        } else if (!req->ident) {

		/* process only once */
		if (alreadyseen) 
			goto end_noresponse;
                LOG_WARN("request denied as the sender has no valid, registered identity (%s)!\n", 
			 req->local_aor);
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
		if (same_aor) {
			ret = 200;
		} else {
			/* todo: get id & event & to-header 'tag' parameter */
			char *callid;
			if ((callid = sipp_get_call_id(sip))) {
				if (sipp_buddy_handle_subscribe(req->ident, req->full_remote_aor, expire, callid)) {
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
		   ((same_domain && !memcmp("ping", req->remote_aor, strlen("ping"))) ||
		    (same_aor))) {
		
		/* process only once */
		if (alreadyseen) 
			goto end_noresponse;
		
		LOG_DEBUG("detected keep-alive options\n");
		ret = 200;
        } else {
		/* ok, these are all messages that will be forwarded
		   to the other peer */

                /* note: BYE / CANCEL cleanup is handled in call_log_record */
		
		if (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip)) {
			/* mark that we should send trust parameters
			   to this person */
			trustman_mark_send_trust_to(req->ident, remote_ident_aor);	
		}

                /* process vias & body */
#ifndef IGNORE_VIAS
		if (MSG_IS_RESPONSE(sip)) {
			via = (osip_via_t*)osip_list_get(OSIPMSG_PTR(sip->vias), 0);
			if (via)
				osip_list_remove(OSIPMSG_PTR(sip->vias), 0);
			osip_via_free(via);
		} else {
			if (via = sipp_create_own_via(req->ident)) {
				osip_list_add(OSIPMSG_PTR(sip->vias), via, 0);
			}
		}
		
		/* remove any route's (sorry..) */
		while (rt = (osip_route_t*)osip_list_get(OSIPMSG_PTR(sip->routes), 0)) {
			osip_list_remove(OSIPMSG_PTR(sip->routes), 0);
			osip_route_free(rt);
		}
#endif

		if (sipp_process_sdp_message_body(sip, req->ident, remote_ident_aor, 0)) {
			LOG_WARN("Error processing the SIP message\n");
			ret = 400;
		} else {			
                        ret = 1100;
                }
        }

	goto end;
 end_noresponse:
	ret = 0;
 end:	

	/* and finally, run the post processors */
	sipp_run_postprocessors(req, remote_ident_aor, &ret);
	sip = req->evt->sip; // might have changed.
	
	/* .. and then we could run the remote client handlers .. */

	/* and final-final, forward the message if that was the plan */
	if (ret > 1000) {
		char *buf = 0;
		size_t len;
		if (sipp_sip_to_str(sip, &buf, &len) ||
		    conn_send_slow(remote_ident_aor, req->ident->sip_aor, SERVICE_TYPE_SIP, 
				   buf, len, req, 
				   sipp_queued_sent)) {
			ret = 500;
		} else {
			/* add a ref for the callback */
			ship_obj_ref(req);
			ret -= 1000;
		}
		freez(buf);
	}
	
	/* don't send codes on responses */
	if (MSG_IS_RESPONSE(sip))
		ret = 0; 
 err:
	ship_unlock(req->ident);
	ship_unlock(req);
	freez(remote_ident_aor);
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

/* small utility to convert a sip message into a string. this should
   be used */
int
sipp_sip_to_str(osip_message_t *sip, char **buf, size_t *len)
{
	osip_message_force_update(sip);
	return osip_message_to_str(sip, buf, len);
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

static osip_event_t *
sipp_create_sip_event(osip_message_t *msg)
{
	osip_event_t *ret = NULL;
	ASSERT_TRUE(ret = osip_new_outgoing_sipmessage (msg), err);
	return ret;
 err:
	return NULL;
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
	
	ASSERT_TRUE(sipp_all_listeners, err);

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
	} else if (to->type == IPPROTO_UDP) {
		/* find a suitable listener which we can use to send! */
		sipp_listener_t *lis = NULL;
		void *ptr = NULL;

		ship_lock(sipp_all_listeners);
		while ((lis = (sipp_listener_t *)ship_list_next(sipp_all_listeners, &ptr))) {
			if (conn_can_send_to(&(lis->addr), to))
				break;
			lis = NULL;
		}
		ship_unlock(sipp_all_listeners);
		
		if (lis)
			s = lis->socket;
	}
	
	/* default to UDP if no transport is given */
	if (to && to->type != IPPROTO_TCP) {
		if (!ident_addr_addr_to_sa(to, &sa, &salen)) {

			LOG_VDEBUG("Sending %d bytes over UDP %s:%d..\n", len, to->addr, to->port);
			if (s != -1)
				s = netio_packet_send(s, buf, len, sa, salen);
			else
				s = netio_packet_anon_send(buf, len, sa, salen);
			freez(sa);
			if (s != len)
				LOG_WARN("Could not send all %d bytes over UDP, only got %d!\n", len, s);
			return s;
		}
	} else {
		LOG_VDEBUG("Sending %d bytes over TCP..\n", len);
		return netio_send(s, buf, len);
	}
	
	LOG_ERROR("Invalid transport type / sending error for contact %d\n", to->type);
err:
	return -1;
}

#ifdef NATIVE_PRESENCE

static int
sipp_presence_handler(sipp_request_t *req, const char *remote_aor,
		      int *response_code, void *data)
{
	int ret = 1;
	char *callid = NULL;

	ASSERT_TRUE(callid = sipp_get_call_id(req->evt->sip), err);

	//ident_subscribe_for_buddy_by_aor();

	// if presence
	if (0) {
		*response_code = 0;
		ret = 0;
	}
	
 err:
	freez(callid);
	return ret;
}
#endif

					
int
sipp_register_hook(sipp_client_handler handler, 
		   sipp_request_handler req_handler,
		   void *data)
{
	ship_pack_t *ptr = 0;
	int ret = -1;
	
	ASSERT_TRUE(ptr = ship_pack("ppp", handler, req_handler, data), err);
	ship_list_add(sipp_client_handlers, ptr);
	ret = 0;
 err:
	return ret;
}

/* untested .. */
/*
void
sipp_unregister_client_handler(sipp_client_handler handler, 
			       sipp_request_handler req_handler,
			       void *data)
{
	void *ptr = 0;
	ship_pack_t *pack = 0;
	ship_lock(sipp_client_handlers);
	while ((pack = ship_list_next(sipp_client_handlers, &ptr))) {
		sipp_client_handler handler2;
		sipp_request_handler req_handler2;
		void *data2;
		ship_unpack_keep(pack, &handler2, &req_handler2, &data2);
		if (handler2 == handler && data2 == data && req_handler == req_handler2) {
			ship_list_remove(sipp_client_handlers, pack);
			ship_pack_free(pack);
			break;
		}
	}
	ship_unlock(sipp_client_handlers);
}
*/

 /* return 0 if we DONT want this message to get sent! */
static int 
sipp_run_client_handlers(ident_t *ident, const char *remote_aor, addr_t *contact_addr, char **buf, int *len)
{
	void *ptr = 0, *pack = 0;
	int ret = -1;

	ASSERT_TRUE(ident && *buf, err);
	//ship_lock(sipp_client_handlers); // don't lock, as the python module will deadlock
	ret = 1;
	while (ret && *buf && (pack = ship_list_next(sipp_client_handlers, &ptr))) {
		sipp_client_handler handler;
		void *data;
		
		ship_unpack_keep(pack, &handler, NULL, &data);
		if (handler)
			ret = handler(ident, remote_aor, contact_addr, buf, len, data);
	}
	//ship_unlock(sipp_client_handlers);
	if (ret)
		ret = 1;
 err:
	return ret;
}

static int
sipp_run_postprocessors(sipp_request_t *req, const char *remote_ident_aor, int *respcode)
{
	int ret = 1;
	void *ptr = 0, *pack = 0;

	//ship_lock(sipp_client_handlers); // don't lock, as the python module will deadlock
	while (ret && (pack = ship_list_next(sipp_client_handlers, &ptr))) {
		sipp_request_handler req_handler;
		void *data;

		ship_unpack_keep(pack, NULL, &req_handler, &data);
		if (req_handler)
			ret = req_handler(req, remote_ident_aor, respcode, data);
	}
	//ship_unlock(sipp_client_handlers);
	return ret;
}

static int 
sipp_send_sip_to_ident(osip_message_t *sip, ident_t *ident, addr_t *from, const char *remote_aor)
{        
	addr_t *contact_addr = 0;
#ifdef CONFIG_HIP_ENABLED
	addr_t addr;
#endif
	char *buf = 0;
	int len, ret = 0;

	/* create the msg */
	ASSERT_ZERO(sipp_sip_to_str(sip, &buf, (unsigned int*)&len), err); //, "Could not serialize sip message! Message dropped!\n");
	LOG_VDEBUG("Sending message:\n>>>>>\n%s\n<<<<<\n", buf);
	
	/* get the address where to send the packet! */
	if (ident && !(contact_addr = sipp_get_relay_addr(ident, sip)))
		contact_addr = ident_get_service_addr(ident, SERVICE_TYPE_SIP);
	
	/* if no contact, then send to where we got it from! */
	if (!contact_addr && from) {
		LOG_WARN("no contact addr found for %s, sending back to source!\n", (ident? ident->sip_aor:"<unknown>"));
		contact_addr = from;
	}

#ifdef CONFIG_HIP_ENABLED
	/* if the target is a HIT, then change to our public IP, hope
	   that's ok! This is done only for HITs, even through part of
	   the mobility hack, as clients (maemo) tend to bind to
	   specific addresses in this case */
	if (sipp_media_proxy_mobility && contact_addr && hipapi_addr_is_hit(contact_addr) &&
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
	} else {
		LOG_INFO("Dropping SIP packet as a client handler stole it\n");
		ret = 1;
	}
	
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
		freez(data_arr[3]);
		free(data_arr);
	}
}

static int
sipp_send_sip_to_ident_do(void *d, processor_task_t **wait, int wait_for_code)
{
	void **data_arr = (void**)d;
	osip_message_t* sip = data_arr[0];
	char *aor = data_arr[1], *remote_aor = data_arr[3];
	addr_t *addr = data_arr[2];
	ident_t *ident = 0;

	LOG_DEBUG("sending async message to %s..\n", aor);
	if ((ident = ident_find_by_aor(aor)) || addr) {
		sipp_send_sip_to_ident(sip, ident, addr, remote_aor);
		ship_obj_unlockref(ident);
	} else {
		LOG_WARN("should send msg to %s, but could not (no target found!)\n", aor);
	}
	return 0;
}

static int 
sipp_send_sip_to_ident_async(osip_message_t* sip, char *local_aor, addr_t *from, char* remote_aor)
{
	int ret = -1;
	void **data_arr = 0;
	osip_message_t* sip_copy = 0;
	
	ASSERT_ZERO(osip_message_clone(sip, &sip_copy), err);
	ASSERT_TRUE(data_arr = mallocz(sizeof(void*) * 5), err);
	ASSERT_TRUE(data_arr[0] = sip_copy, err);
	ASSERT_TRUE(data_arr[1] = strdup(local_aor), err);
	if (from) {
		ASSERT_TRUE(data_arr[2] = mallocz(sizeof(addr_t)), err);
		memcpy(data_arr[2], from, sizeof(addr_t));
	}
	if (remote_aor) {
		ASSERT_TRUE(data_arr[3] = strdup(remote_aor), err);
	}
	
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
		freez(data_arr[3]);
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
	osip_event_t* evt = 0;
        sipp_request_t *respreq = 0;

	/* check for already-send terminating responses */
	if (sipp_check_and_mark(req->evt->sip, "resp", code))
		return 0;

	/* if this is a ack, then forget this .. */
	if (MSG_IS_ACK(req->evt->sip)) {
		ret = 0;
	} else {
		ASSERT_ZERO(sipp_create_sip_response(&resp, code, req->evt->sip), err);
		/* response .. checker . */
		ASSERT_TRUE(evt = sipp_create_sip_event(resp), err);
		ASSERT_TRUE(evt->sip, err);
		resp = NULL;
		
		ASSERT_TRUE(respreq = sipp_request_new(req->ident, evt, !req->remote_msg, 1), err);
		evt = NULL;

		ASSERT_ZERO(ac_packetfilter(respreq, sipp_cb_packetfilter, 1), err);
		respreq = NULL;
		ret = 0;
        }
        
 err:
        if (respreq)
		ship_obj_unref(respreq);
	if (evt)
		osip_event_free(evt);
	if (resp)
		osip_message_free(resp);
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
sipp_call_log_find(char *str, char *local_aor, char *remote_aor, int remote)
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
	return e;
}

/* tries to find the matching log entry from the 'db' */
static call_log_entry_t*
sipp_call_log_find_or_create(char *str, char *local_aor, char *remote_aor, int remote)
{
	call_log_entry_t *e = 0;
	e = sipp_call_log_find(str, local_aor, remote_aor, remote);
	if (!e && (e = sipp_call_log_new(str, local_aor, remote_aor, remote)))
		ship_list_push(call_log, e);
	return e;
}

#define CONVERSATION_MAX_IDLE (30 * 60)

/* records a call / message / communication attempt */
static void 
sipp_call_log_record(sipp_request_t *req, int verdict)
{
	char *str = 0, *tmp = 0, *callid = 0, *local_sip = 0, *remote_sip = 0;
	osip_message_t *sip = NULL;
	int size = 0, len = 0;
	call_log_entry_t *e = 0;
	time_t now;
#ifdef CONFIG_OP_ENABLED
	char *op_statement = NULL;
#endif

	sip = req->evt->sip;

	// todo: these could be replaced with cached copies..
	/* get the addresses in the header (may differ from the identities) */
	ASSERT_ZERO(sipp_get_sip_aors(sip, &local_sip, &remote_sip, req->remote_msg), err);
	ship_lock(call_log);
	time(&now);

	/* send event when new comes, or the state of an old one changes! */
        if (MSG_IS_INVITE(sip) || MSG_IS_RESPONSE(sip)) {
		ASSERT_TRUE(callid = sipp_get_call_id(sip), err);
		ASSERT_TRUE((tmp = append_str("invite,id:", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE((tmp = append_str(callid, str, &size, &len)) && (str = tmp), err);
		
		e = sipp_call_log_find(str, local_sip, remote_sip, req->remote_msg);
		if (MSG_IS_RESPONSE(sip)) {
			if (e && !e->response_got) {
				e->response_got = 1;

				/* we should record ok / rejects of calls - put into op */
				int code = osip_message_get_status_code(sip);
				char *method = osip_cseq_get_method(sip->cseq);
				if (method && !strcmp("INVITE", method)) {
					code = code / 100;
					switch (code) {
					case 2:
						if (req->remote_msg) { /* the remote person accepted the call */
							CREATE_OP_REPORT(op_statement, "call", "was-accepted", "0", "0", "1");
						} else { /* we accepted */
							CREATE_OP_REPORT(op_statement, "call", "accepted-from", "1", "1", "0");
						}
						break;
					case 4: 
						if (req->remote_msg) { /* the remote person rejected the call */
							CREATE_OP_REPORT(op_statement, "call", "was-rejected", "0", "1", "-1");
						} else { /* we rejected */
							CREATE_OP_REPORT(op_statement, "call", "rejected-from", "-1", "1", "0");
						}
						sipp_call_terminated(sip, req->remote_msg);
						break;
					case 5:
						/* system errors */
						if (req->remote_msg) { /* the remote person had a problem */
							CREATE_OP_REPORT(op_statement, "call", "was-err", "0", "0", "0");
						} else { /* we had a problem */
							CREATE_OP_REPORT(op_statement, "call", "err-from", "0", "-1", "0");
						}
						sipp_call_terminated(sip, req->remote_msg);
						break;
					default:
						/* sip 100, 300 .. no response, just status updates */
						e->response_got = 0;
						break;
					}
				}
			}
		} else if (!e) {
			if (req->remote_msg) {
				CREATE_OP_REPORT(op_statement, "call", "placed-from", "0", "1", "1");
			} else {
				CREATE_OP_REPORT(op_statement, "call", "was-placed", "1", "1", "0");
			}
			ASSERT_TRUE(e = sipp_call_log_find_or_create(str, local_sip, remote_sip, req->remote_msg), err);
		}
	} else if (MSG_IS_MESSAGE(sip) && !MSG_IS_RESPONSE(sip)) {
		/* check last seen. if idle for > 1 hrs, then consider this a new conversation */
		ASSERT_TRUE(e = sipp_call_log_find_or_create("message", local_sip, remote_sip, req->remote_msg), err);
		if (e->last_seen && ((now - e->last_seen) > CONVERSATION_MAX_IDLE)) {
			/* change the id of this entry. it is not
			   longer the 'current' conversation. */
			free(e->id);
			e->id = 0;
			e->id = strdup("message_old");

			ASSERT_TRUE(e = sipp_call_log_find_or_create("message", local_sip, remote_sip, req->remote_msg), err);
		}
		
		if (e->started >= now) {
			/* this is a new conversation .. record into op */
			if (req->remote_msg) {
				CREATE_OP_REPORT(op_statement, "chat", "started-from", "0", "1", "1");
			} else {
				CREATE_OP_REPORT(op_statement, "chat", "was-started", "1", "1", "0");
			}
		} else if (!e->response_got) {
			e->response_got = 1;
			if (req->remote_msg && !e->remotely_initiated) {
				CREATE_OP_REPORT(op_statement, "chat", "response-from", "0", "1", "1");
			} else if (!req->remote_msg && e->remotely_initiated) {
				CREATE_OP_REPORT(op_statement, "chat", "responded-to", "1", "1", "0");
			} else 
				e->response_got = 0;
		}
	} else if (MSG_IS_BYE(sip) || MSG_IS_CANCEL(sip)) {

		/* we should record the call duration here, put into op */

		/* clean up proxies */
		sipp_call_terminated(sip, req->remote_msg);
	}

#ifdef CONFIG_OP_ENABLED
	if (op_statement) {
		char* key = 0;
		reg_package_t *reg = 0;

		/* .. add to the database .. */
		if ((reg = ident_find_foreign_reg(remote_sip))) {
			key = ident_data_get_pkey_base64(reg->cert);
			if (key) 
				opconn_add(key, op_statement);
			freez(key);
			ship_unlock(reg);
		}
	}
	op_statement = NULL;
#endif

	/* go quietly to the end */
	if (!e)
		goto err;

	e->last_seen = now;
	if (e->verdict != verdict) {
		reg_package_t *r = 0;
		char *name = req->remote_aor;
		char *status = 0;
		
		/* todo op: we should get a 'statement' from the op
		   system as well.. */
		
		/* set the trustparams as they were when the verdict was made.. */
		e->pathlen = trustman_get_pathlen(req->remote_aor, req->local_aor);

		/* get the name of the remove person! */
		if ((r = ident_find_foreign_reg(req->remote_aor)) && r->name) {
			name = r->name;
		}
		
		if (r && r->status && (status = mallocz(strlen(r->status) + 5))) {
			sprintf(status, " [%s]", r->status);
		}
		
		e->verdict = verdict;
		if (req->remote_msg) {

			const char *type = NULL;
			if (MSG_IS_INVITE(sip))
				type = TYPE_CALL_STRING;
			else if (MSG_IS_MESSAGE(sip))
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
					    (ident = ident_find_by_aor(req->local_aor)) &&
					    (!ident_data_bb_find_connections_on_level(ident->buddy_list, req->remote_aor, e->pathlen-2, list)) &&
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
		} else {
			/* locally generated stuff. add the key! */

			/* also would want to know whether we answered
			   a call or not. for that I guess we need to
			   examine the response messages as well! */

		}
		freez(status);
		ship_unlock(r);
		
		// todo: ship_obj' this!
		/* notify! .. its a bit risky to use the e struct directly, but ..*/
		processor_event_generate_pack("sip_log", "p", e);
	}
 err:
	freez(remote_sip);
	freez(local_sip);
	freez(callid);
	freez(str);
	ship_unlock(call_log);
}
