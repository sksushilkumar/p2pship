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
#include "processor_config.h"
#include "netio.h"
#include "ship_debug.h"
#include "ship_utils.h"
#include <sys/stat.h>
#include "processor.h"
#include "ident.h"
#include "netio_http.h"
#include "ext_api.h"
#include "conn.h"
#include "p2pship_version.h"

/* activate when testing the web-cache. this will make it do p2p when
it has the content in its own cache. */
//  #define TESTING_WEBCACHE

/* the http server socket */
static int extapi_ss = -1;

#ifdef CONFIG_HTTPPROXY_ENABLED
/* the http proxy server socket */
static int httpproxy_ss = -1;

/* whether to reveal the origianl request url + host */
static int reveal_original_request = 1;

static ship_ht_t *p2phttp_handlers = NULL;
static ship_ht_t *extapi_http_reqs = NULL;
#endif

static int extapi_handle_forward_with_auth(netio_http_conn_t *conn, char *to, int port);
static void extapi_return_and_record(netio_http_conn_t *conn, char *url, char *data, int datalen);
static void extapi_http_proxy_response(netio_http_conn_t *conn, int code, char *code_str, char *msg);

/* returns true if a username was found in this */
static int
http_unescape_aor_at(char *tmp)
{
	char *tmp2 = 0;
	int l = 0, i;

	if (tmp2 = strstr(tmp, ".at.")) {
		l = 4;
	} else if (tmp2 = strstr(tmp, "..")) {
		l = 2;
	}
	
	if (l) {
		tmp = tmp2+l;
		*(tmp2++) = '@';
		while (*tmp) 
			*(tmp2++) = *(tmp++);
		
		*tmp2 = 0;
	}
	return l;
}

static void 
__extapi_get_cb(char *key, char *data, char *signer, void *param, int status)
{
	netio_http_conn_t *conn = 0;
	if (conn = netio_http_get_conn_by_socket((int)param)) {
		char buf[32], *curr, *entry; 
		int ce = 0; 

		if (curr = netio_http_get_attr(conn, "current_entry")) { 
			ce = atoi(curr); 
		}
		sprintf(buf, "%d", ce+1);
		netio_http_set_attr(conn, "current_entry", buf); 
		
		if (entry = netio_http_conn_get_param(conn, "entry")) {	
			if ((ce == atoi(entry)) &&
			    data) {
				status = 0;
				netio_http_respond(conn, 200, "OK", 
						   "application/octet-stream",
						   data, strlen(data));
				netio_http_set_attr(conn, "w", "ok"); 
			}
		} else if (status > -1 && data) {
			char *format = netio_http_conn_get_param(conn, "mode");
			
			/* if we are using multipart, then if this is the
			   first part, create & send the header, unless we
			   didn't find anything (this is the last call) */
			if (format && !strcmp(format, "multipart")) {
				netio_http_respond_multipart(conn,
							     "application/octet-stream",
							     data, strlen(data));
			} else {
				/* one-by-one body format */
				netio_http_respond(conn, 200, "OK", 
						   "application/octet-stream",
						   data, strlen(data));
			}
			netio_http_set_attr(conn, "w", "ok"); 
		}
		
		if (status < 1) {
			if (!netio_http_get_attr(conn, "w")) {
				netio_http_respond(conn, 200, "OK", 
						   "application/octet-stream",
						   0, 0);
			}
			netio_http_conn_close(conn);
		} else {
			ship_unlock(conn);
		}
	}
}



void 
extapi_service_closed_raw(service_type_t service_type, ident_t *ident, void *pkg)
{
	LOG_DEBUG("Closed ext-raw service %d for %s\n", service_type, ident->sip_aor);
}

int 
extapi_data_received_raw(char *data, int data_len, ident_t *ident, 
			 char *source, service_type_t service_type)
{
	addr_t *contact_addr = ident_get_service_addr(ident, service_type);
	struct sockaddr *sa = 0;
	socklen_t salen = 0;
	int ret = -1;
	
	LOG_DEBUG("Got %d bytes data on ext-raw service %d from %s to %s\n", 
		  data_len, service_type, source, ident->sip_aor);
	
	if (contact_addr && !ident_addr_addr_to_sa(contact_addr, &sa, &salen)) {
		if (netio_packet_anon_send(data, data_len, sa, salen) == data_len)
			ret = 0;
	}
	
	freez(sa);
	return 0;
}

static struct service_s extapi_raw_service =
{
 	.data_received = extapi_data_received_raw,
	.service_closed = extapi_service_closed_raw,
	.service_handler_id = "extapi_raw"
};


void 
extapi_service_closed_http(service_type_t service_type, ident_t *ident, void *pkg)
{
	LOG_DEBUG("Closed ext-http service %d for %s\n", service_type, ident->sip_aor);
}

static void
extapi_free_http_req(extapi_http_req_t *req)
{
	if (req) {
		ship_ht_remove(extapi_http_reqs, req->id);
		freez(req->request);
		freez(req->tracking_id);
		freez(req->request);
		freez(req->to_aor);
		freez(req->from_aor);
		freez(req->buf);
		freez(req);
	}
}

void 
extapi_http_conn_cb(int s, void *obj)
{
	extapi_http_req_t *req = obj;

	/* write out request .. */
	netio_send(s, req->request, req->request_len);
	STATS_LOG("made http request\n");
}


void 
extapi_http_data_return(extapi_http_req_t *req, char *data, int odatalen)
{
	char *tmp = 0;
	int strl = 0, datalen = odatalen;
	
	/* send the data immediately */
	LOG_DEBUG("We got data from http request, %d bytes\n", datalen);
	if (datalen < 0)
		datalen = 0;
	
	strl = strlen(req->tracking_id);
	strl++;
	ASSERT_TRUE(tmp = malloc(strl + datalen + 10), err);
	strcpy(tmp, req->tracking_id);
	strcat(tmp, "\n");

	/* add the piece number also .. */
	ship_inroll(req->piece_number, (tmp+strl), 4);
	req->piece_number++;
	strl += 4;
	
	STATS_LOG("http_receive_data;%s;%s;%d;%d;%d;%d\n",
		  req->to_aor, req->from_aor, 0, odatalen, strl+datalen, 0);

	memcpy(tmp + strl, data, datalen);
	ASSERT_ZERO(conn_queue_to_peer(req->from_aor, req->to_aor,
				       SERVICE_TYPE_HTTPRESPONSE,
				       tmp, strl + datalen, NULL, NULL),
		    err);
 err:
	freez(tmp);
	if (odatalen < 1) {
		extapi_free_http_req(req);
	}
}

void 
extapi_http_data_cb(int s, void *obj, char *data, int odatalen)
{
	extapi_http_data_return((extapi_http_req_t *)obj, data, odatalen);
}

extapi_http_req_t*
extapi_get_http_req(const char *id)
{
	return ship_ht_get_string(extapi_http_reqs, id);
}

int 
extapi_data_received_http(char *data, int data_len, ident_t *ident, 
			  char *source, service_type_t service_type)
{
	char *tracking_id, *content, *tmp = 0;
	netio_http_conn_t* conn = 0;
	int port = service_subid(service_type);
	int len = 0, s = -1;
	addr_t *addr = ident_get_service_addr(ident, service_type);
	void *ptrarr = ident_get_service_data(ident, service_type);
	struct sockaddr *sa = 0;
	socklen_t salen = 0;
	extapi_http_req_t *req = 0;
	
	LOG_VDEBUG("Got data for HTTP, port %d, %d bytes from %s to %s\n", port, data_len, source, ident->sip_aor);

	/* extract the tracking id & package */
	tracking_id = data;
	ASSERT_TRUE(content = strchr(data, '\n'), err);
	content[0] = 0;
	content++;

	STATS_LOG("http_receive1;%s;%s;%d;%d;%d;%d\n",
		  ident->sip_aor, source, service_type, data_len, data_len-(content-data), 0);
	
	/* forward it to the url given in the registration .. */
	if (ptrarr ||
	    (addr && !ident_addr_addr_to_sa(addr, &sa, &salen))) {
		/* parse request */
		ASSERT_TRUE(conn = netio_http_parse_data(content, data_len - (content-data)), err);
		
		/* replace hostname & to/from */
		netio_http_set_header(conn, "X-P2P-From", source);
		netio_http_set_header(conn, "X-P2P-To", ident->sip_aor);

		if (addr) {
			ASSERT_TRUE(tmp = mallocz(128), err);
			sprintf(tmp, "%s:%d", addr->hostname, addr->port);
			netio_http_set_header(conn, "Host", tmp);
			freez(tmp);
		}

		//httpproxy_process_req(netio_http_conn_t *conn, void *pkg)

		/* create the request holder */
		ASSERT_TRUE(req = mallocz(sizeof(extapi_http_req_t)), err); // arr.. these are just passed around
		sprintf(req->id, "%08x%08x", req, ship_systemtimemillis());
		ship_ht_put_string(extapi_http_reqs, req->id, req);
		ASSERT_ZERO(netio_http_serialize(conn, &req->request, &req->request_len), err);
		ASSERT_TRUE(req->tracking_id = strdup(tracking_id), err);
		ASSERT_TRUE(req->from_aor = strdup(source), err);
		ASSERT_TRUE(req->to_aor = strdup(ident->sip_aor), err);
			
		if (ptrarr) {
			int (*func) (netio_http_conn_t *conn, void *pkg, extapi_http_req_t* req) = NULL;
			void *pkg = NULL;
			void **ptrs = (void**)ship_ht_get_ptr(p2phttp_handlers, ptrarr);
			
			/* pass it to some other module.. ? */
			ASSERT_TRUE(ptrs, err);
			func = (void *)ptrs[0];
			pkg = (void*)ptrs[1];
			if (func(conn, pkg, req) > -1)
				req = NULL;
		} else {
			STATS_LOG("http_receive2;%s;%s;%d;%d;%d;%d\n",
				  ident->sip_aor, source, service_type, data_len-(content-data), req->request_len, 0);
			
			s = netio_man_connto(sa, salen, req, extapi_http_conn_cb, extapi_http_data_cb);
			ASSERT_TRUE(s != -1, err);
			req = 0;
		}
	}
	
	goto end;
 err:
	/* repond with something .. */
	ASSERT_TRUE(tmp = mallocz(128 + strlen(tracking_id)), end);
	strcpy(tmp, tracking_id);
	strcat(tmp, "\nHTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<h1>Not found, sorry!</h1>\r\n");
	conn_queue_to_peer(source, ident->sip_aor, 
			   SERVICE_TYPE_HTTPRESPONSE,
			   tmp, strlen(tmp), NULL, NULL);	
 end:
	extapi_free_http_req(req);
	netio_http_conn_close(conn);
	freez(tmp);
	freez(sa);
	return 0;
}

static struct service_s extapi_http_service =
{
 	.data_received = extapi_data_received_http,
	.service_closed = extapi_service_closed_http,
	.service_handler_id = "extapi_http"
};

static void 
extapi_service_closed_httpresponse(service_type_t service_type, ident_t *ident, void *pkg)
{
	LOG_DEBUG("Closed ext-httpresponse service %d for %s\n", service_type, ident->sip_aor);

}

static int 
extapi_data_received_httpresponse(char *data, int data_len, ident_t *ident, 
				  char *source, service_type_t service_type)
{
	char *tracking_id, *content = 0, *msg = 0;
	netio_http_conn_t *oldconn = 0;
	int len = 0, piece = 0;
	
	ASSERT_TRUE(ident, err);
	LOG_DEBUG("Got data for http response %d bytes! from %s to %s\n", data_len, source, ident->sip_aor);
	STATS_LOG("got data for http response\n");

       	/* extract the tracking id & package */
	tracking_id = data;
	ASSERT_TRUE(content = strchr(data, '\n'), err);
	content[0] = 0;
	content++;
	
	/* extract the piece number */
	ASSERT_TRUE(data_len >= (content-data-4), err);
	ship_unroll(piece, content, 4);
	content += 4;
	
	len = data_len - (content-data);
 err:
	/* do something like this .. */
	netio_http_packet_orderer_put(tracking_id, piece, content, len);
	len = 1; /* so we dont close it yet */
	if (oldconn = netio_http_get_conn_by_id(tracking_id)) {
		while (!netio_http_packet_orderer_pop_next(tracking_id, &piece, &content, &len)) {
			extapi_return_and_record(oldconn, NULL, content, len);
			freez(content);
		}
	}

	if (oldconn) {
		if (len < 1) {
			netio_http_conn_close(oldconn);
		} else {
			ship_unlock(oldconn);
		}
	}
	return 0;
}

static struct service_s extapi_httpresponse_service =
{
 	.data_received = extapi_data_received_httpresponse,
	.service_closed = extapi_service_closed_httpresponse,
	.service_handler_id = 0
};

static void 
extapi_http_sent(char *to, char *from, service_type_t service,
		 char *data, int data_len, void *ptr,
		 int code)
{
	char *tid = ptr;
	
	/* if error, then return error to the client as well .. */
	if (code) {
		netio_http_conn_t *conn = netio_http_get_conn_by_id(ptr);
		if (conn) {
			extapi_http_proxy_response(conn, 404, "Not Found", "Not found\n");
			netio_http_conn_close(conn);
		}
	}
	freez(ptr);
}


/* func that sends some data that was requested to the requestor, and
   records it into the cache at the same time */
static void
extapi_return_and_record(netio_http_conn_t *conn, char *url, char *data, int datalen)
{	
	if (data && datalen > -1) {
		netio_send(conn->socket, data, datalen);
#ifdef CONFIG_WEBCACHE_ENABLED
		webcache_record(conn->tracking_id, url, data, datalen);
#endif
	}
}

static void
extapi_http_proxy_response(netio_http_conn_t *conn, int code, char *code_str, char *msg)
{
	char *tmp = mallocz(strlen(msg) + 100);
	if (tmp) {
		sprintf(tmp, "<h3>P2PSHIP proxy:</h3><i>%s</i>", msg);
		netio_http_respond_html(conn, code, code_str, tmp);
		freez(tmp);
	} else
		netio_http_respond_html(conn, code, code_str, msg);
}

#ifdef CONFIG_HTTPPROXY_ENABLED

/* for storing forwarding requests */
typedef struct extapi_http_forward_req_s {
	
	char *tracking_id;
	char *data;
	int len;

	char *url;
	int pkg_nr;
} extapi_http_forward_req_t;


/* the callback for the p2p cache lookup */
static void
extapi_p2p_cache_data_cb(char *url, void *obj, char *data, int datalen)
{
	extapi_http_forward_req_t *ptr = obj;
	netio_http_conn_t *conn = 0;
	
	LOG_DEBUG("got P2P data callback for url %s, datalen %d\n", url, datalen);
	ASSERT_TRUE(conn = netio_http_get_conn_by_id(ptr->tracking_id), err);
	
	/* why would we send zero byte data? */
	extapi_return_and_record(conn, ptr->url, data, datalen);
 err:
	if (conn) {
		if (datalen < 1) {
			extapi_http_proxy_response(conn, 400, "Error", "Could not access resource or unknown host.");
		}
		netio_http_conn_close(conn);
	} 
	
	if (ptr) {
		freez(ptr->tracking_id);
		freez(ptr->data);
		freez(ptr->url);
		freez(ptr);
	}
}

static void 
extapi_handle_http_forward_data_cb(int s, void *obj, char *data, int datalen)
{
	extapi_http_forward_req_t *ptr = obj;
	netio_http_conn_t *conn = 0;
	
	if (datalen < 0) {
		if (!ptr->len 
#ifdef CONFIG_WEBCACHE_ENABLED
		    && !webcache_p2p_lookup(ptr->url, ptr, extapi_p2p_cache_data_cb)
#endif
		    ) {
			return;
		}
	} else
		ptr->len = 1;

	ASSERT_TRUE(conn = netio_http_get_conn_by_id(ptr->tracking_id), err);
	extapi_return_and_record(conn, ptr->url, data, datalen);
 err:
	if (conn) {
		if (datalen < 1) {
			if (!ptr->len) {
				extapi_http_proxy_response(conn, 400, "Error", "Could not connect");
			}
			netio_http_conn_close(conn);
			conn = 0;
		} else
			ship_unlock(conn);
	} 
	
	if (datalen < 1 && ptr) {
		freez(ptr->tracking_id);
		freez(ptr->data);
		freez(ptr->url);
		freez(ptr);
	}

	if (!conn)
		netio_man_close_socket(s);	
}

static void 
extapi_handle_http_forward_conn_cb(int s, void *obj)
{
	extapi_http_forward_req_t *ptr = obj;

	/* create the packet & send! */
	netio_send(s, ptr->data, ptr->len);
	freez(ptr->data);
	ptr->len = 0;
}

static int
extapi_handle_http_forward(netio_http_conn_t *conn, char *user, int port)
{
	int ret = -1;
	addr_t addr;
	struct sockaddr *sa = 0;
	socklen_t sa_len;
	extapi_http_forward_req_t *ptr = 0;
	char *tmp;
	char *buf = 0;
	int len;
	
	ASSERT_TRUE(ptr = mallocz(sizeof(extapi_http_forward_req_t)), err);
	ASSERT_ZERO(netio_http_serialize(conn, &ptr->data, &ptr->len), err);
	ASSERT_TRUE(ptr->tracking_id = strdup(conn->tracking_id), err);
	
	/* create the request url */
	ASSERT_TRUE(ptr->url = mallocz(zstrlen(conn->url_extras) + strlen(conn->url) + strlen(user) + 32), err);
	if (conn->url_extras)
		sprintf(ptr->url, "http://%s:%d%s?%s", user, port, conn->url, conn->url_extras);
	else
		sprintf(ptr->url, "http://%s:%d%s", user, port, conn->url);
	
	/* check the local cache? */
	/*
	if (tmp = netio_http_get_header(conn, "Cache-Control")) {
		// printf("request says cache: %s\n", tmp);
	}
	*/
	
#ifdef CONFIG_WEBCACHE_ENABLED
#ifndef TESTING_WEBCACHE
	if (!webcache_get_resource(ptr->url, &buf, &len)) {
		LOG_DEBUG("found %s in cache, returning..\n", ptr->url);
		netio_send(conn->socket, buf, len);
		ret = 0;
		goto err;
	}
#endif
#endif
	
	/* hm, how should this go? currently, if dns lookup fails, we
	   fall back on the p2p system. but shouldn't we do that also
	   if the connection fails? */
	if (ident_addr_str_to_addr_lookup(user, &addr)
#ifdef TESTING_WEBCACHE
	    || !webcache_get_resource(ptr->url, &buf, &len)
#endif
	    ) {

#ifdef CONFIG_WEBCACHE_ENABLED
		if (!webcache_p2p_lookup(ptr->url, ptr, extapi_p2p_cache_data_cb)) {
			ptr = 0;
			ret = 1;
			goto err;
		}
#endif
		extapi_http_proxy_response(conn, 400, "Error", "Unknown host");
		ret = 0;
		goto err;
	}
	
	addr.port = port;
	ASSERT_ZERO(ident_addr_addr_to_sa(&addr, &sa, &sa_len), err);
	ASSERT_TRUE(netio_man_connto(sa, sa_len, ptr, extapi_handle_http_forward_conn_cb,
				     extapi_handle_http_forward_data_cb) != -1, err);
	
	ptr = 0;
	ret = 1;
 err:
	if (ptr) {
		freez(ptr->tracking_id);
		freez(ptr->data);
		freez(ptr->url);
		freez(ptr);
	}
	freez(sa);
	freez(buf);
	
	if (ret < 0) {
		extapi_http_proxy_response(conn, 500, "Error", "Proxy error while processing the request");
	}
	return ret;
}

void
_httpproxy_tunnel_cb(int s, void *obj)
{
	char *id = obj;
	netio_http_conn_t *conn = netio_http_get_conn_by_id(id);
	
	/* highjack the socket! */
	if (conn && !netio_http_redirect_data(conn, s)) {
		netio_http_respond_str(conn, 200, "Connection established", "");
	} else {
		extapi_http_proxy_response(conn, 400, "Could not connect", "");
		freez(id);
	}
	ship_unlock(conn);
}

void 
_httpproxy_tunnel_data_cb(int s, void *obj, char *data, int datalen)
{
	char *id = obj;
	netio_http_conn_t *conn = netio_http_get_conn_by_id(id);
	
	/* check that the conn is still valid, do some sort of .. */
	if (conn && data > 0 && conn->socket != -1) {
		netio_send(conn->socket, data, datalen);
	} else {
		LOG_DEBUG("closing conn after eof\n");
		netio_http_conn_close(conn);
		netio_man_close_socket(s);
		freez(id);
	}
	ship_unlock(conn);
}
     

static int
httpproxy_process_req(netio_http_conn_t *conn, void *pkg)
{
	int ret = -1;
	char *tmp = 0, *path = 0, *user = 0, *tmp2 = 0;
	int port = 80;
	
	LOG_DEBUG("got req for %s\n", conn->url);
		
	/* hm, if method == CONNECT, what then? highjack the socket,
	   put it into a forwarder */
	if (!strcmp(conn->method, "CONNECT")) {
		struct sockaddr *sa = 0;
		socklen_t sa_len = 0;
		int s = -1;
		char *id = 0;
		
		LOG_DEBUG("should establish tunnel to %s\n", conn->url);

		/* conn to the host! */
		ASSERT_ZERO(ident_addr_str_to_sa(conn->url,
						 &sa, &sa_len), err);
		if (id = strdup(conn->tracking_id))
			s = netio_man_connto(sa, sa_len, id,
					     _httpproxy_tunnel_cb,
					     _httpproxy_tunnel_data_cb);
		if (s != -1)
			ret = 1;
		else
			freez(id);
		freez(sa);
		goto err;
	}

	/* parse the url, check protocol == http .. or something else we support */
	if (!str_startswith(conn->url, "http://") &&
	    !str_startswith(conn->url, "https://")) {
		extapi_http_proxy_response(conn, 400, "Bad request", "Bad request. Proxy does not support the requested protocol.");
		ASSERT_TRUE(ret = 0, err);
	}

	tmp = strstr(conn->original_url, "://") + 3;
	tmp2 = strchr(tmp, '/');
	if (tmp2) {
		ASSERT_TRUE(path = strdup(tmp2), err);
		tmp2[0] = 0;
	} else {
		ASSERT_TRUE(path = strdup("/"), err);
	}
	
	/* parse possible port number */
	if (tmp2 = strchr(tmp, ':')) {
		port = atoi(tmp2+1);
		tmp2[0] = 0;
	}
	
	/* parse the hostname for the user! */
	ASSERT_TRUE(user = strdup(tmp), err);
	ship_urldecode(user);
	freez(conn->original_url);
	conn->original_url = path;
	freez(conn->url);
	ASSERT_TRUE(conn->url = strdup(conn->original_url), err);
	ship_urldecode(conn->url);
	path = 0;

	/* check if this is a normal HTTP request or a request for a p2psip peer */
	if (http_unescape_aor_at(user)) {
		ret = extapi_handle_forward_with_auth(conn, user, port);
	} else {
		/* this was a normal http request */
		ret = extapi_handle_http_forward(conn, user, port);
	}
 err:
	freez(user);
	freez(path);
	if (ret < 0) {
		extapi_http_proxy_response(conn, 400, "Bad request", "Bad request. Did the domain indicate the remote peer?\n");
	}
	return ret;
}
#endif

static int
extapi_handle_forward(netio_http_conn_t *conn, char *to, int port, char *from, char *passwd)
{
	int len, l2, ret = -1;
	char *tmp = 0, *newbuf = 0;

	LOG_DEBUG("Got http forward %s (:%s) => %s port %d, path %s\n", from, passwd, to, port, conn->url);

	/* if we want to process the message, do it here .. */
	netio_http_set_header(conn, "Proxy-Authorization", NULL);
	netio_http_set_header(conn, "Proxy-Connection", NULL);

	/* end processing */

	ASSERT_ZERO(netio_http_serialize(conn, &tmp, &len), err);
	STATS_LOG("http_forward1;%s;%s;%d;%d;%d;%d\n",
		  to, from, 0, conn->content_len, len, 0);

	/* add tracking id to buffer */
	l2 = len + strlen(conn->tracking_id)+1;
	ASSERT_TRUE(newbuf = mallocz(l2), err);
	strcpy(newbuf, conn->tracking_id);
	strcat(newbuf, "\n");
			
	memcpy(newbuf+strlen(newbuf), tmp, len);
	freez(tmp);
	
	STATS_LOG("http_forward2;%s;%s;%d;%d;%d;%d\n",
		  to, from, 0, len, l2, 0);

	ASSERT_TRUE(tmp = strdup(conn->tracking_id), err);
	ASSERT_ZERO(conn_queue_to_peer(to, from, 
				       service_create_id(SERVICE_TYPE_HTTP, port),
				       newbuf, l2, tmp, extapi_http_sent), 
		    err);

	/* create the response queueing mechanism */
	netio_http_packet_orderer_create(conn->tracking_id);
	tmp = 0;
	ret = 1;
 err:
	freez(newbuf);
	freez(tmp);

	return ret;
}


static int
extapi_handle_forward_with_auth(netio_http_conn_t *conn, char *to, int port)
{
	char *auth = 0;
	int ret = -1;

	if (auth = netio_http_get_header(conn, "Proxy-Authorization")) {
		int len = 0;
		
		/* skip the 'Basic ' */
		auth = strchr(auth, ' ');
		if (auth) auth++;
					
		auth = ship_decode_base64(auth, strlen(auth), &len);
		if (auth && len > 0) {
			char *passwd = 0;
						
			auth[len] = 0;
			if (passwd = strchr(auth, ':')) {
				passwd[0] = 0;
				passwd++;
			}
					
			if (!strlen(auth) || ident_has_ident(auth, passwd)) {
				ret = extapi_handle_forward(conn, to, port, auth, passwd);
			}
		}
		freez(auth);
	}
				
	if (ret < 0) {
		netio_http_respond_auth(conn, 
					"HIIT P2PSIP Proxy",
					"text/html",
					"Authorization required");
		ret = 0;
	}

	return ret;
}

#ifdef CONFIG_HTTPPROXY_ENABLED
int
extapi_register_p2phttp_handler(char *aor, const int dport, addr_t *addr, const int expire, 
				int (*func) (netio_http_conn_t *conn, void *pkg, extapi_http_req_t* req), void *pkg)
{
	void **arr = NULL;
	LOG_DEBUG("Registering p2p http handler for %s port %d\n", aor, dport);
	if (func) {
		ASSERT_TRUE(arr = malloc(sizeof(void*) * 2), err);
		arr[0] = func;
		arr[1] = pkg;
		ship_ht_put_ptr(p2phttp_handlers, arr, arr);
	}
	return ident_process_register(aor, service_create_id(SERVICE_TYPE_HTTP, dport), 
				      &extapi_http_service, addr, expire, arr);
 err:
	return 500;
}
#endif

static int
extapi_process_req(netio_http_conn_t *conn, void *pkg)
{
	int ret = 0;
	LOG_DEBUG("got req for %s\n", conn->url);
	
	/**
	 * part 1: basic DHT
	 */
	if (str_startswith(conn->url, "/get")) {
		char *key = netio_http_conn_get_param(conn, "key");
		
		if (!key) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request");
		} else {
			ASSERT_ZERO(olclient_get(key, conn->socket, __extapi_get_cb), err);
			ret = 1;
		}
	} else if (str_startswith(conn->url, "/put")) {
		char *key = netio_http_conn_get_param(conn, "key");
		char *data = netio_http_conn_get_param(conn, "data");
		char *to = netio_http_conn_get_param(conn, "ttl");
		char *secret = netio_http_conn_get_param(conn, "secret");

		if (!key || !data || !to || !secret) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request");
		} else {
			int timeout = atoi(to);
			ASSERT_ZERO(olclient_put(key, data, timeout, secret), err);
			netio_http_respond_str(conn, 202, 
					       "Accepted", "The data was accepted");
		}
	} else if (str_startswith(conn->url, "/rm")) {
		char *key = netio_http_conn_get_param(conn, "key");
		char *secret = netio_http_conn_get_param(conn, "secret");

		if (!key || !secret) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request");
		} else {
			ASSERT_ZERO(olclient_remove(key, secret), err);
			netio_http_respond_str(conn, 202, 
					       "Accepted", "The remove was accepted");
		}
		
	/**
	 * part 2: raw service packet forwarding
	 */
	} else if (str_startswith(conn->url, "/register")) {
		char *aor = netio_http_conn_get_param(conn, "aor");
		char *ttl = netio_http_conn_get_param(conn, "ttl");
		char *url = netio_http_conn_get_param(conn, "url");
		char *service = netio_http_conn_get_param(conn, "service");
		service_type_t service_type = service_str_to_type(service);
		int expire = 0;

		if (ttl)
			expire = atoi(ttl);

		if (!aor || !ttl || !url || !service) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request");
		} else {
			addr_t host;
			int retcode = 500;
			
			if (!ident_addr_str_to_addr_lookup(url, &host)) {

				retcode = ident_process_register(aor, service_type, &extapi_raw_service,
								 &host, expire, NULL);
				switch (retcode / 100) {
				case 2:
					netio_http_respond_str(conn, retcode, 
							       "Ok", "Request accepted");
				case 4:
					netio_http_respond_str(conn, retcode, 
							       "Error", "Error processing request");
					break;
				case 5:
					netio_http_respond_str(conn, retcode, 
							       "Server error", "Server error while processing request");
					break;
				default:
					netio_http_respond_str(conn, retcode,
							       "Bad request", "Bad request");
					break;
				}
			} else {
				netio_http_respond_str(conn, 500, 
						       "Server error", "Server error while processing request");
			}
                }
		
	} else if (str_startswith(conn->url, "/send")) {
		char *to = netio_http_conn_get_param(conn, "to");
		char *from = netio_http_conn_get_param(conn, "from");
		char *service = netio_http_conn_get_param(conn, "service");
		netio_http_param_t *data = ship_ht_get_string(conn->params, "data");
		service_type_t service_type = service_str_to_type(service);
		
		if (!to || !from || !data || !service) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request");
		} else {
			if (conn_queue_to_peer(to, from, service_type,
					       data->data, data->data_len,
					       NULL, NULL)) {
				LOG_WARN("Sending raw packet, service %d failed\n", service_type);
				netio_http_respond_str(conn, 500, "Server Error", "Server error, could not send");
			} else {
				netio_http_respond_str(conn, 200, "OK", "Sent");
			}
		}

#ifdef CONFIG_HTTPPROXY_ENABLED
	/**
	 * part 3: http forwarding
	 */
	} else if (str_startswith(conn->url, "/http_register")) {
		char *aor = netio_http_conn_get_param(conn, "aor");
		char *ttl = netio_http_conn_get_param(conn, "ttl");
		char *url = netio_http_conn_get_param(conn, "url");
		char *dports = netio_http_conn_get_param(conn, "dport");
		int expire = 0, dport = 80;

		if (ttl)
			expire = atoi(ttl);
		if (dports)
			dport = atoi(dports);

		/* if we dont have aor, use, again, the 'default' */
		if (!aor || !strlen(aor)) {
			ship_wait("http_register");
			ident_t *def = ident_get_default_ident();
			if (def) {
				aor = strdup(def->sip_aor);
				ship_obj_unlockref(def);
			}
			ship_complete();
		} else
			aor = strdup(aor);

		if (!aor || !ttl || !url) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request");
		} else {
			ident_t *ident = 0;
			addr_t addr;
			int ret;
			
			ASSERT_ZERO(ident_addr_str_to_addr_lookup(url, &addr), httpr_err);			
			ret = extapi_register_p2phttp_handler(aor, dport, &addr, expire, NULL, NULL);			
			ASSERT_TRUE(ret/100 == 2, httpr_err);
			ret = 0;

		httpr_err:
			if (ret) {
				netio_http_respond_str(conn, 500, "Server Error", "Error processing request");
			} else {
				netio_http_respond_str(conn, 200, "OK", "HTTP service registered");
			}
		}
		freez(aor);

	} else if (str_startswith(conn->url, "/http")) {
		char **tokens = 0;
		int toklen = 0;
		char *url = conn->url;
		ret = -1;
		
		/* this is the simples - /http/<to>/<path> */

		if (!ship_tokenize_trim(url, strlen(url), &tokens, &toklen, '/') && toklen >= 2) {
			char *to = tokens[2], *from = 0;
			char *path = 0;
			char **t = &tokens[3];
			
			if (toklen > 2) 
				path = ship_untokenize(t, toklen-3, "/", "/");
			else
				path = strdup("/");
			if (path) {
				ident_t *def = 0;
				
				if (reveal_original_request) {
					/* add some additional stuff, best effort.. */
					char *path_pre = ship_untokenize(tokens, 3, "/", "");
					netio_http_set_header(conn, "X-P2PSIP-Host", netio_http_get_header(conn, "Host"));
					netio_http_set_header(conn, "X-P2PSIP-Prefix", path_pre);
					freez(path_pre);
				}

				freez(conn->original_url);
				conn->original_url = path;

				http_unescape_aor_at(to);
				ship_wait("http");
				def = ident_get_default_ident();
				ship_complete();
				if (def) {
					from = strdup(def->sip_aor);
					ship_obj_unlockref(def);
				}
				
				if (from) {
					/* ok, this is to make the interface super-easy. if the domain is missing from the 
					   target, then add the same domain as your ident has! */
					if (!strchr(to, '@') && strchr(from, '@')) {
						int nlen = strlen(to) + strlen(strchr(from, '@')) + 5;
						char *tmp = mallocz(nlen);
						if (tmp) {
							strcpy(tmp, to);
							strcat(tmp, strchr(from, '@'));
							free(to);
							tokens[2] = tmp;
							to = tmp;
						}
					}
					
					ret = extapi_handle_forward(conn, to, 80, from, NULL);
					freez(from);
				}
			}
		}
		
		if (ret < 0) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request\n");
		}
		ship_tokens_free(tokens, toklen);
	} else if (str_startswith(conn->url, "/http_forward")) {
		char **tokens = 0;
		int toklen = 0;
		char *url = conn->url;
		ret = -1;
		
		// /http_forward/from/to/port/...
		if (!ship_tokenize_trim(url, strlen(url), &tokens, &toklen, '/') && toklen >= 4) {
			char *from = tokens[2], *to = tokens[3];
			int port = atoi(tokens[4]);
			char *path = 0;
			char **t = &tokens[5];
			
			if (toklen > 4) 
				path = ship_untokenize(t, toklen-5, "/", "/");
			else
				path = strdup("/");
			if (path) {
				if (reveal_original_request) {
					/* add some additional stuff, best effort.. */
					char *path_pre = ship_untokenize(tokens, 5, "/", "");
					netio_http_set_header(conn, "X-P2PSIP-Host", netio_http_get_header(conn, "Host"));
					netio_http_set_header(conn, "X-P2PSIP-Prefix", path_pre);
					freez(path_pre);
				}

				freez(conn->original_url);
				conn->original_url = path;

				http_unescape_aor_at(from);
				http_unescape_aor_at(to);
				if (!strlen(from)) {
					ship_wait("http_forward");
					ident_t *def = ident_get_default_ident();
					ship_complete();
					if (def) {
						tokens[2] = strdup(def->sip_aor);
						if (tokens[2]) {
							freez(from);
							from = tokens[2];
						}
						ship_obj_unlockref(def);
					}
				}
				ret = extapi_handle_forward(conn, to, port, from, NULL);
			}
		}
		
		if (ret < 0) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request\n");
		}
		ship_tokens_free(tokens, toklen);
	} else if (str_startswith(conn->url, "/http_auth_forward")) {
		char **tokens = 0;
		int toklen = 0;
		char *url = conn->url;
		ret = -1;
		
		if (!ship_tokenize_trim(url, strlen(url), &tokens, &toklen, '/') && toklen >= 3) {
			char *to = tokens[2];
			int port = atoi(tokens[3]);
			char *path = 0;
			char **t = &tokens[4];
			
			if (toklen > 3) 
				path = ship_untokenize(t, toklen-4, "/", "/");
			else
				path = strdup("/");
			if (path) {
				if (reveal_original_request) {
					/* add some additional stuff, best effort.. */
					char *path_pre = ship_untokenize(tokens, 4, "/", "");
					netio_http_set_header(conn, "X-P2PSIP-Host", netio_http_get_header(conn, "Host"));
					netio_http_set_header(conn, "X-P2PSIP-Prefix", path_pre);
					freez(path_pre);
				}
				
				http_unescape_aor_at(to);
				free(conn->url);
				conn->url = path;
				ret = extapi_handle_forward_with_auth(conn, to, port);
			}
		}
		
		if (ret < 0) {
			netio_http_respond_str(conn, 400, "Bad request", "Bad request\n");
		}
		ship_tokens_free(tokens, toklen);
#endif
	} else {
		netio_http_respond_str(conn, 404, "Not found", 
				       "The resource you were looking for could not be found.");
	}

	return ret;
 err:
	netio_http_respond_str(conn, 500, 
			       "Server error", "Error while processing request");
	return ret;
}



/* this gets called when an config has been updated */
static int
extapi_cb_config_update(processor_config_t *config, char *k, char *v)
{
	int ret = -1;

	if (!strcmp(k, P2PSHIP_CONF_EXTAPI_SS)) {
		char *ss_addr;
		ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_EXTAPI_SS, &ss_addr), err);

		if (extapi_ss == -1) {
			ASSERT_TRUE((extapi_ss = netio_http_server_create(ss_addr, 
									  extapi_process_req, NULL)) != -1, err);
		} else {
			ASSERT_ZERO((ret = netio_http_server_modif(extapi_ss, ss_addr)) != -1, err);
			extapi_ss = ret;
		}
	}
#ifdef CONFIG_HTTPPROXY_ENABLED
	else if (!strcmp(k, P2PSHIP_CONF_HTTPPROXY_ADDR)) {
		char *ss_addr;
		ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_HTTPPROXY_ADDR, &ss_addr), err);

		if (httpproxy_ss == -1) {
			ASSERT_TRUE((httpproxy_ss = netio_http_server_create(ss_addr, 
									     httpproxy_process_req, NULL)) != -1, err);
		} else {
			ASSERT_ZERO((ret = netio_http_server_modif(httpproxy_ss, ss_addr)) != -1, err);
			httpproxy_ss = ret;
		}
	} else if (!strcmp(k, P2PSHIP_CONF_HTTPPROXY_REVEAL_ORIGINAL)) {
		ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_HTTPPROXY_REVEAL_ORIGINAL, &reveal_original_request), err);
	}
#endif
		ret = 0;
	err:
		return ret;
	}

/* starts up the extapi interface */
int
extapi_init(processor_config_t *config)
{
	int ret = -1;
	extapi_cb_config_update(config, P2PSHIP_CONF_EXTAPI_SS, processor_config_string(config, P2PSHIP_CONF_EXTAPI_SS));
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_EXTAPI_SS, extapi_cb_config_update);

	/* register the services */
	ASSERT_ZERO(ident_service_register(&extapi_raw_service), err);
	ASSERT_ZERO(ident_service_register(&extapi_http_service), err);

#ifdef CONFIG_HTTPPROXY_ENABLED
	extapi_cb_config_update(config, P2PSHIP_CONF_HTTPPROXY_ADDR, processor_config_string(config, P2PSHIP_CONF_HTTPPROXY_ADDR));
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_HTTPPROXY_ADDR, extapi_cb_config_update);

	extapi_cb_config_update(config, P2PSHIP_CONF_HTTPPROXY_REVEAL_ORIGINAL, processor_config_string(config, P2PSHIP_CONF_HTTPPROXY_ADDR));
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_HTTPPROXY_REVEAL_ORIGINAL, extapi_cb_config_update);

	ASSERT_TRUE(p2phttp_handlers = ship_ht_new(), err);
	ASSERT_TRUE(extapi_http_reqs = ship_ht_new(), err);
#endif
 	ident_register_default_service(SERVICE_TYPE_HTTPRESPONSE, &extapi_httpresponse_service); 
	ret = 0;
 err:
	return ret;
}

/* closes up the module */
void
extapi_close()
{
	netio_http_server_close(extapi_ss);
#ifdef CONFIG_HTTPPROXY_ENABLED
	if (p2phttp_handlers) {
		ship_ht_empty_free(p2phttp_handlers);
		ship_ht_free(p2phttp_handlers);
	}
	p2phttp_handlers = NULL;

	if (extapi_http_reqs) {
		extapi_http_req_t *req = NULL;
		while (req = ship_ht_pop(extapi_http_reqs))
			extapi_free_http_req(req);
	}
#endif
}

/* the extapi register */
static struct processor_module_s processor_module = 
{
	.init = extapi_init,
	.close = extapi_close,
	.name = "extapi",
#ifdef CONFIG_WEBCACHE_ENABLED
	.depends = "netio,netio_http,ident,conn,olclient,webcache",
#else
	.depends = "netio,netio_http,ident,conn,olclient",
#endif
};

/* register func */
void
extapi_register() {
	processor_register(&processor_module);
}

