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
#define _GNU_SOURCE /* memmem */
#include "ident.h"
#include "ship_debug.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "netio_http.h"
#include "processor.h"
#include "netio.h"
#ifdef CONFIG_WEBCACHE_ENABLED
#include "webcache.h"
#endif

/* the list of servers */
static ship_ht_t *http_servers = 0;

/* the list of connections */
static ship_list_t *conns = 0;
static ship_ht_t *conns_ht = 0;

/* the post / get headers */
static const char *post_header = "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HIIT P2PSIP\r\nAccept: *\r\nContent-Length: %d\r\nContent-Type: %s\r\nConnection: close\r\n\r\n";
static const char *get_header = "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: HIIT P2PSIP\r\nAccept: *\r\nConnection: close\r\n\r\n";

static netio_http_conn_t *netio_http_get_conn_by_socket(int s, const int must_own);


/* some packet ordering funcs. these are a bit quick&dirty, yes.*/

/* where all the orderer states go */
static ship_ht_t *orderer = 0;

/* creates */
void
netio_http_packet_orderer_create(char *tracking_id)
{
	ship_ht_t *l = 0;
	ship_lock(orderer);
	if ((l = ship_ht_new())) {
		/* this is really ugly, using the ht to keep
		   netio_httptrack of the next element .. */
		ship_ht_put_string(l, "next", 0);
		ship_ht_put_string(orderer, tracking_id, l);
	}
	ship_unlock(orderer);
}

/* removes the orderer state for the given id */
void
netio_http_packet_orderer_close(char *tracking_id)
{
	ship_ht_t *l = 0;
	ship_lock(orderer);
	if ((l = ship_ht_remove_string(orderer, tracking_id))) {
		/* free up the stuff */
		ship_ht_remove_string(l, "next");
		ship_ht_empty_free_with(l, (void (*) (void *))ship_lenbuf_free);
		ship_ht_free(l);
	}
	ship_unlock(orderer);
}

/* puts another piece into the orderer */
void
netio_http_packet_orderer_put(char *tracking_id, int piece, char *content, int len)
{
	ship_ht_t *l = 0;
	ship_lock(orderer);
	if ((l = ship_ht_get_string(orderer, tracking_id))) {
		ship_ht_put_int(l, piece, ship_lenbuf_create_copy(content, len));
	}
	ship_unlock(orderer);
}

/* gets teh next piece, IF available. returns 0 if all ok (piece
   available & returned) */
int
netio_http_packet_orderer_pop_next(char *tracking_id, int *piece, char **content, int *len)
{
	int ret = -1;
	ship_ht_t *l = 0;
	ship_lock(orderer);
	if ((l = ship_ht_get_string(orderer, tracking_id))) {
		ship_lenbuf_t *val = 0;
		int next = (int)ship_ht_get_string(l, "next");
		if ((val = ship_ht_remove_int(l, next))) {
			(*content) = val->data;
			(*len) = val->len;
			val->data = 0;
			if (*content)
				ret = 0;
			ship_lenbuf_free(val);
			ship_ht_put_string(l, "next", (void*)(next+1));
		}
	}
	ship_unlock(orderer);
	return ret;
}

void
netio_conn_reset(netio_http_conn_t *conn)
{
	netio_http_param_t *param = 0;
	while ((param = ship_ht_pop(conn->params))) {
		freez(param->data);
		freez(param->name);
		freez(param);
	}
	
	ship_ht_empty_free(conn->headers);
	
	freez(conn->buf);
	freez(conn->content_type);
	freez(conn->http_version);
	freez(conn->host);
	freez(conn->url);
	freez(conn->original_url);
	freez(conn->url_extras);
	freez(conn->fullurl);		
	freez(conn->method);		
	freez(conn->resp_code_line);		
		
	conn->data_len = 0;
	conn->buf_len = 0;

	/* the html heads */
	conn->content_len = 0;
	conn->header_got = 0;
	conn->header_len = 0;
}


static netio_http_conn_t *
netio_http_conn_lock(netio_http_conn_t *conn)
{
	if (conns && conn) {
		ship_lock(conns);
		conn = ship_list_find(conns, conn);
		if (conn) {
			ship_lock(conn);
			ship_restrict_locks(conn, conns);
		}
		ship_unlock(conns);
		return conn;
	}
	return NULL;
}

void
netio_http_conn_close(netio_http_conn_t *conn)
{
	if (conn && conns && conn->added) {
		ship_unlock(conn);
		ship_lock(conns);
		conn = netio_http_conn_lock(conn);
	
		if (conn) {
			conn->added = 0;
			ship_ht_remove_string(conns_ht, conn->tracking_id);
			netio_http_packet_orderer_close(conn->tracking_id);
			conn = _ship_list_remove(0, conns, conn);
			ship_unlock(conn);
		}
		ship_unlock(conns);
	}

	if (conn) {
#ifdef CONFIG_WEBCACHE_ENABLED
		webcache_close_trackers(conn->tracking_id);
#endif

		// todo: if we don't OWN the socket, do not close it!!!
		// -> the ownership might have been moved to some other http_conn!
		if (conn->owns_socket && conn->socket != -1) {
			netio_man_close_socket(conn->socket);
			conn->socket = -1;
		}

		if (conn->forward_socket != -1) {
			netio_man_close_socket(conn->forward_socket);
			conn->forward_socket = -1;
		}

		if (conn->func) {
			conn->func(conn->fullurl, -1, NULL, -1, conn->pkg);
			conn->func = 0;
		}

		netio_conn_reset(conn);
		ship_ht_free(conn->params);
		ship_ht_free(conn->headers);		
		ship_lock_free(&conn->lock);
		freez(conn);
	}
}

static void
netio_http_track_conn(netio_http_conn_t *ret, int socket)
{
	if (socket != -1) {
		ship_lock(conns); {
			ship_list_add(conns, ret);
			ret->added = 1;
			netio_http_conn_lock(ret);
			
			/* create some sort of unique id for this connection */
			do {
				sprintf(ret->tracking_id, "http_conn:%d", rand());
			} while (ship_ht_get_string(conns_ht, ret->tracking_id));
			
			ship_ht_put_string(conns_ht, ret->tracking_id, ret);
		}
		ship_unlock(conns);
	}
}

/* makes all received data go directly to the given socket */	
int
netio_http_redirect_data(netio_http_conn_t *conn, int s) 
{
	conn->forward_socket = s;
	return 0;
}

/* closes all netio_conn's for the given socket */
static void
netio_http_conn_close_all(const int socket)
{
	netio_http_conn_t *ret = 0;

	while ((ret = netio_http_get_conn_by_socket(socket, 0))) {
		ret->owns_socket = 0;
		netio_http_conn_close(ret);
	}
}

static netio_http_conn_t *
netio_http_conn_new(int socket)
{
	netio_http_conn_t *ret = 0;

	if (socket != -1)
		while ((ret = netio_http_get_conn_by_socket(socket, 1))) {
			ret->owns_socket = 0;
			ship_unlock(ret);
		}

	ASSERT_TRUE(ret = mallocz(sizeof(netio_http_conn_t)), err);
	ret->socket = socket;
	ret->forward_socket = -1;
	ASSERT_ZERO(ship_lock_new(&ret->lock), err);
	netio_http_track_conn(ret, socket);
	ASSERT_TRUE(ret->params = ship_ht_new(), err);
	ASSERT_TRUE(ret->headers = ship_ht_new(), err);

	/* this last! */
	ret->owns_socket = 1;
	return ret;
err:
	netio_http_conn_close(ret);
	return 0;
}

static netio_http_conn_t*
netio_http_wait_new(addr_t *addr, char *fullurl, char *host, char *url, char *content_type, char *data, int data_len,
		    void (*func) (char *url, int respcode, char *data, int data_len, void *pkg),
		    void *pkg)
{
	netio_http_conn_t* ret = NULL;
	
	ASSERT_TRUE(ret = netio_http_conn_new(-1), err);
	ret->content_len = -1;
	ret->pkg = pkg;
	ret->func = func;
	memcpy(&(ret->addr), addr, sizeof(addr_t));

	if (data) {
		ASSERT_TRUE(ret->buf = mallocz(data_len+1), err);
		memcpy(ret->buf, data, data_len);
		ret->data_len = data_len;
		ret->buf_len = data_len;
	}
	if (content_type)
		ASSERT_TRUE(ret->content_type = strdup(content_type), err);
	ASSERT_TRUE(ret->url = strdup(url), err);
	ASSERT_TRUE(ret->host = strdup(host), err);
	ASSERT_TRUE(ret->fullurl = strdup(fullurl), err);
	return ret;
 err:
	netio_http_conn_close(ret);
	return NULL;
}

/* callback on tcp connections */
static void 
__netio_http_cb_conn(int s, void *obj)
{
	netio_http_conn_t *h = (netio_http_conn_t*)obj;
	char *buf;

	if (!netio_http_conn_lock(h))
		return;
	
	/* write the data! */
	if ((buf = mallocz(strlen(post_header) + strlen(h->url) + 
			   zstrlen(h->content_type) + strlen(h->host) + 64 + h->data_len))) {
		int len = 0;
		if (h->buf) {
			sprintf(buf, post_header, h->url, h->host, h->data_len, h->content_type);
			len = strlen(buf);
			memcpy(buf + len, h->buf, h->data_len);
		} else {
			sprintf(buf, get_header, h->url, h->host);
			len = strlen(buf);
		}
		netio_send(s, buf, len + h->data_len);
		freez(buf);
		h->data_len = 0;
		ship_unlock(h);
	} else {
		netio_http_conn_close(h);
	}
}

/* converts a netio_http connection data object into a char * of the
   request. might replace the headers and URL. */
int
netio_http_serialize(netio_http_conn_t* conn, char **ret, int *retlen)
{
	int len = 0, size = 0;
	char *buf = 0, *tmp = 0, *key, *val;
	void *ptr = 0;
	ship_list_t *list = 0;

	if (conn->method) {
		ASSERT_TRUE((tmp = append_str(conn->method, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str(" ", buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str(conn->original_url, buf, &size, &len)) && (buf = tmp), err);
		if (conn->url_extras) {
			ASSERT_TRUE((tmp = append_str("?", buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(conn->url_extras, buf, &size, &len)) && (buf = tmp), err);
		}
		if (conn->http_version) {
			ASSERT_TRUE((tmp = append_str(" ", buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(conn->http_version, buf, &size, &len)) && (buf = tmp), err);
		}
		ASSERT_TRUE((tmp = append_str("\r\n", buf, &size, &len)) && (buf = tmp), err);
	} else if (conn->resp_code_line) {
		ASSERT_TRUE((tmp = append_str(conn->resp_code_line, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str("\r\n", buf, &size, &len)) && (buf = tmp), err);
	}

	ASSERT_TRUE(list = ship_ht_keys(conn->headers), err);
	while ((key = ship_list_next(list, &ptr))) {
		val = ship_ht_get_string(conn->headers, key);
		ASSERT_TRUE((tmp = append_str(key, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str(": ", buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str(val, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str("\r\n", buf, &size, &len)) && (buf = tmp), err);
	}
	ASSERT_TRUE((tmp = append_str("\r\n", buf, &size, &len)) && (buf = tmp), err);
	
	/* add data */
	if ((conn->data_len - conn->header_len) > (size - len)) {
		size = len + (conn->data_len - conn->header_len) + 1;
		ASSERT_TRUE(tmp = mallocz(size), err);
		memcpy(tmp, buf, len);
		freez(buf);
		buf = tmp;
	}

	memcpy(buf+len, conn->buf + conn->header_len, conn->data_len - conn->header_len);
	len += conn->data_len - conn->header_len;
	buf[len] = 0;
	*ret = buf;
	*retlen = len;
	ship_list_empty_free(list);
	ship_list_free(list);
	return 0;
 err:
	ship_list_empty_free(list);
	ship_list_free(list);
	freez(buf);
	return -1;
}


/* cuts off overrun data that doesn't belong to the given request at
   all. e.g. for proxy connections where a bunch of requests might
   come at once. this function just returns a pointer to the starting
   location of the overrun data + the len of it */
void
netio_http_cut_overrun(netio_http_conn_t* conn, char **data, int *datalen)
{
	*datalen = 0;
	if ((conn->content_len + conn->header_len) < conn->data_len) {
		*datalen = conn->data_len - conn->header_len - conn->content_len;
		*data = &conn->buf[conn->header_len + conn->content_len];
	}
}


/* returns 0 = done, ok. 1 = not done yet, -1 = error */
static int 
__netio_http_parse_data(netio_http_conn_t* conn, char *data, int datalen)
{
	/* collect data. */
	if (!conn->buf || (conn->buf_len - conn->data_len < datalen)) {
		int ns = conn->buf_len + datalen + 1024;
		char *tmp = 0;
		ASSERT_TRUE(tmp = mallocz(ns+1), err);
		if (conn->buf)
			memcpy(tmp, conn->buf, conn->data_len);
		freez(conn->buf);
		conn->buf = tmp;
		conn->buf_len = ns;
	}
	
	if (datalen > 0) {
		memcpy(conn->buf + conn->data_len, data, datalen);
		conn->data_len += datalen;
	}

	/* check if we have the header, parse url & datalen (if present) */
	if (!conn->header_got && strstr(conn->buf, "\r\n\r\n")) {
		char *line = conn->buf, *le;
		
		conn->header_got = 1;
		conn->header_len = strstr(conn->buf, "\r\n\r\n") - conn->buf + 4;
		do {
			le = strstr(line, "\r\n");
			if (le == line)
				break;

			if (str_startswith(line, "POST") || 
			    str_startswith(line, "GET") ||  
			    str_startswith(line, "OPTIONS") ||  
			    str_startswith(line, "HEAD") ||  
			    str_startswith(line, "PUT") ||  
			    str_startswith(line, "DELETE") ||  
			    str_startswith(line, "TRACE") ||  
			    str_startswith(line, "CONNECT")) {
				/* requests! */
				char *tmple;
				
				/* store method */
				if ((tmple = strchr(line, ' '))) {
					char *t2;
					tmple++;
					
					freez(conn->url); freez(conn->http_version);
					if (le) {
						t2 = le;
						while ((t2 > tmple) && *t2 != ' ')
							t2--;
					} else 
						t2 = strrchr(tmple, ' ');
					if (t2) {
						conn->url = strndup(tmple, t2-tmple);
						conn->http_version = trim(strndup(t2, le-t2));
					} else {
						conn->url = strndup(tmple, le-tmple);
					}
					freez(conn->method);
					conn->method = strndup(line, tmple-line);
					trim(conn->method);
					trim(conn->url);
				}
			} else if (str_startswith(line, "HTTP")) {
				/* for responses! */
				freez(conn->resp_code_line);
				conn->resp_code_line = trim(strndup(line, le-line));
				if (strchr(line, ' '))
					conn->resp_code = atoi(strchr(line, ' ')+1);
			} else {
				/* generic parameter */
				char *tmple = strchr(line, ':');

				if (str_startswith(line, "Content-Length: ")) {
					conn->content_len = atoi(strchr(line, ' ') + 1);
				}

				if (tmple) {
					char *val = strndup(tmple+1, le-tmple+1);
					char *key = strndup(line, tmple-line);
					
					netio_http_set_header(conn, key, val);
					freez(val);
					freez(key);
				}
			}
			if (le)
				line = le+2;
		} while (le);
	}

	/* process data.. */
	if (conn->header_got && 
	    ((conn->content_len == -1 && datalen < 1) || 
	     (conn->content_len != -1 && (conn->content_len <= (conn->data_len - conn->header_len))))) {

		if (conn->content_len == -1) {
			conn->content_len = conn->data_len - conn->header_len;
		}
		
		if (conn->method) {
			LOG_DEBUG("Got total %d bytes, %d bytes data for %s on http\n",
				  conn->data_len, conn->content_len, conn->url);
			
			/* treat multipart & 'normal' posts differently */
			if (!strcmp(conn->method, "POST") && 
			    str_startswith(netio_http_get_header(conn, "Content-Type"), "multipart")) {
				char *bound, *ps, *pe;
				bound = strstr_after(netio_http_get_header(conn, "Content-Type"), "boundary=");

				/* go through parts one-by-one, parsing name & data */
				if (bound) {
					ps = memmem_after(&conn->buf[conn->header_len], conn->data_len - conn->header_len, bound, strlen(bound));
					while (ps) {
						char *tmp, *name, *tmp2 = 0;
						pe = (char*)memmem(ps, conn->data_len - (ps-conn->buf), bound, strlen(bound));
						if (!pe) {
							pe = conn->buf + conn->data_len;
							tmp = 0;
						} else
							tmp = pe + strlen(bound);

						if ((name = strstr(ps, "Content-Disposition: ")))
							tmp2 = strstr(name, "\r\n");
						ps = strstr_after(ps, "\r\n\r\n");
						if (ps && name && tmp2) {
							tmp2[0] = 0;
							if ((name = strstr_after(name, "name=\"")) &&
							    (tmp2 = strchr(name, '"'))) {
								int datalen = pe-ps-4;
								ASSERT_ZERO(netio_http_conn_set_param(conn, name, tmp2-name, ps, datalen), err);
							}
						}
						ps = tmp;
					}
				}
			} else {
				int parsedata = conn->header_len;
				char *ns;

				ns = &(conn->buf[parsedata]);
				
				/* if get, set parsedata to the url's first ?-char */
				if (!strcmp(conn->method, "GET")) {
					char *params = strchr(conn->url, '?');
					if (params) {
						params[0] = 0;
						ns = params+1;
						conn->url_extras = strdup(ns);
					}
				}

				while (ns) {
					char *tmp = 0, *pe = 0;
					char *ps = strchr(ns, '=');
					if (ps) {
						pe = strchr(ps, '&');
						if (!pe) {
							pe = ps + strlen(ps);
							tmp = 0;
						} else
							tmp = pe+1;
					}
					if (ps) {
						char *k = strndup(ns, ps-ns);
						char *v = strndup(ps+1, pe-ps-1);
						if (k && v) {
							ship_urldecode(k);
							ship_urldecode(v);
							ASSERT_ZERO(netio_http_conn_set_param(conn, k, strlen(k), v, strlen(v)), err);
						}
						freez(k); 
						freez(v);
					}
					ns = tmp;
				}
			}
		}
		
		/* ..and we're done! */
		if (conn->url) {
			conn->original_url = conn->url;
			conn->url = strdup(conn->original_url);
			ship_urldecode(conn->url);
		}
		return 0;
	} else if (datalen < 1)
		goto err;
	
	return 1;
 err:
	return -1;
}

/*  */
netio_http_conn_t*
netio_http_parse_data(char *data, int datalen)
{
	netio_http_conn_t *ret = 0;
	ASSERT_TRUE(ret = netio_http_conn_new(-1), err);
	ASSERT_ZERO(__netio_http_parse_data(ret, data, datalen), err);
	return ret;
 err:
	netio_http_conn_close(ret);
	return 0;
}

/*  */
netio_http_conn_t*
netio_http_parse_header(char *data, int datalen)
{
	netio_http_conn_t *ret = 0;
	int r = 0;
	ASSERT_TRUE(ret = netio_http_conn_new(-1), err);
	r = __netio_http_parse_data(ret, data, datalen);
	if ((r == 1) && ret->url)
		ship_urldecode(ret->url);
	if (ret->header_got)
		return ret;
 err:
	netio_http_conn_close(ret);
	return 0;
}

/* decodes encodings (currently only transfer-encoding: chunked) to
   'plain' format */
int
netio_http_decode_encoding(netio_http_conn_t *conn)
{
	char *newdata = 0;
	int datalen = 0;
	
	char *header = netio_http_get_header(conn, "Transfer-Encoding");
	if (header && !strcmp(header, "chunked")) {
		char *olddata = &(conn->buf[conn->header_len]);
		char *eol = 0;
		
		ASSERT_TRUE(newdata = mallocz(conn->content_len), err);
		while ((eol = strstr(olddata, "\r\n"))) {
			int chunklen = 0;

			/* decode the hex digits .. */
			while (*olddata != '\r') {
				chunklen <<= 4;
				if (*olddata >= '0' && *olddata <= '9')
					chunklen += *olddata - '0';
				else if (*olddata >= 'a' && *olddata <= 'f')
					chunklen += 10 + *olddata - 'a';
				else if (*olddata >= 'A' && *olddata <= 'F')
					chunklen += 10 + *olddata - 'A';
				olddata++;
			}

			/* 'the '\r\n' */
			olddata += 2;
			if (strlen(olddata) < chunklen)
				chunklen = strlen(olddata);

			memcpy(&(newdata[datalen]), olddata, chunklen);
			olddata += chunklen;
			datalen += chunklen;
		}
		netio_http_set_header(conn, "Transfer-Encoding", NULL);
	}
	
	if (newdata) {
		conn->content_len = datalen;
		memcpy(&(conn->buf[conn->header_len]), newdata, datalen);
		conn->buf[conn->header_len + datalen] = 0;
	}
 err:
	freez(newdata);
	return 0;
}


/* 
   this is called when new data has arrived or the socket has been closed 
   datalen < 1:
     socket closed!
*/
static void 
__netio_http_cb_data(int s, void *obj, char *data, int datalen)
{
	netio_http_conn_t *conn = (netio_http_conn_t*)obj;
	int ret = -1;

	if (!netio_http_conn_lock(conn))
		return;

	if (conn->forward_socket == -1)
		ret = __netio_http_parse_data(conn, data, datalen);
	else if (datalen > 0) {
		netio_send(conn->forward_socket, data, datalen);
		ret = 1;
	}
		
	if (ret > 0) {
		ship_unlock(conn);
		return;
	}

	if (!ret) {
		LOG_DEBUG("Got total %d bytes, %d data, code %d for request to %s\n",
			  conn->data_len, conn->content_len, conn->resp_code, conn->fullurl);
		
		/* done doing a GET / POST */
		if (conn->func) {
			
			netio_http_decode_encoding(conn);
			conn->func(conn->fullurl, conn->resp_code, &(conn->buf[conn->header_len]), conn->content_len, conn->pkg);
			conn->func = 0;
		}
	}
	netio_http_conn_close(conn);
}
	

/* performs an HTTP post to the given URL, with callback */
int
netio_http_post_host(char *host, char *path, char *urlstr, char *content_type, char *data, int data_len,
		     void (*func) (char *url, int respcode, char *data, int data_len, void *pkg),
		     void *pkg) 
{
	addr_t addr;
	int ret = -1;
	struct sockaddr *sa = NULL;
	socklen_t sa_len;
	netio_http_conn_t *http_conn = NULL;

	ASSERT_ZERO(ident_addr_str_to_addr_lookup(host, &addr), err);
	addr.type = IPPROTO_TCP;
	if (addr.port < 1)
		addr.port = 80;
	
	ASSERT_ZERO(ident_addr_addr_to_sa(&addr, &sa, &sa_len), err);
	
	/* new managed api: */
	if ((http_conn = netio_http_wait_new(&addr, urlstr, host, path, content_type, data, data_len, func, pkg))) {
		ship_lock(conns);
		http_conn->socket = netio_man_connto(sa, sa_len, http_conn, __netio_http_cb_conn, __netio_http_cb_data);
		if (http_conn->socket != -1) {
			netio_http_track_conn(http_conn, http_conn->socket);
			ret = 0;
			ship_unlock(http_conn);
		}
		ship_unlock(conns);
	}
err:
	freez(sa);
	return ret;
}

/* performs an HTTP post to the given URL, with callback */
int
netio_http_post(char *url, char *content_type, char *data, int data_len,
		void (*func) (char *url, int respcode, char *data, int data_len, void *pkg),
		void *pkg) 
{
	char *host = 0, *path = 0;
	int hostlen, ret = -1;

	/* parse url */
	ASSERT_TRUE(str_startswith(url, "http://"), err);
	
	url += 7;
	path = strchr(url, '/');
	if (!path) {
		hostlen = strlen(url);
		path = strdup("/");
	} else {
		hostlen = path - url;
		path = strdup(path);
	}
	
	ASSERT_TRUE(host = strndup((const char*)url, (size_t)hostlen), err);
	ret = netio_http_post_host(host, path, url-7, content_type, data, data_len, func, pkg);
err:
	freez(host);
	freez(path);
	return ret;
}

/* performs an HTTP post to the given URL, with callback */
int
netio_http_get(char *url,
	       void (*func) (char *url, int respcode, char *data, int data_len, void *pkg),
	       void *pkg) 
{
	return netio_http_post(url, NULL, NULL, 0, func, pkg);
}


/********************** server functions ****************************/


char *
netio_http_get_header(netio_http_conn_t* conn, char *key)
{
	return ship_ht_get_string(conn->headers, key);
}

int
netio_http_set_header(netio_http_conn_t* conn, char *key, char *data)
{
	char *old = 0;
	if (!key)
		return 0;
	
	if ((old = ship_ht_remove_string(conn->headers, key)))
		free(old);
	
	if (data && (old = strdup(data))) {
		trim(old);
		ship_ht_put_string(conn->headers, key, old);
		return 0;
	}
	return -1;
}

ship_list_t *
netio_http_conn_get_header_keys(netio_http_conn_t *conn)
{
	return ship_ht_keys(conn->headers);
}

char *
netio_http_conn_get_param(netio_http_conn_t *conn, char *name)
{
	netio_http_param_t *param = 0;
	if ((param = ship_ht_get_string(conn->params, name)))
		return param->data;
	return NULL;
}

int
netio_http_conn_set_param(netio_http_conn_t *conn, char *name, int namelen, char *value, int len)
{
	int ret = -1;
	netio_http_param_t *param = 0;

	ASSERT_TRUE(param = mallocz(sizeof(netio_http_param_t)), err);
	ASSERT_TRUE(param->data = mallocz(len+1), err);
	ASSERT_TRUE(param->name = mallocz(namelen+1), err);
	param->data_len = len;
	memcpy(param->name, name, namelen);
	memcpy(param->data, value, len);
	ship_ht_put_string(conn->params, param->name, param);
	ret = 0;
 err:
	return ret;
}

ship_list_t *
netio_http_conn_get_param_keys(netio_http_conn_t *conn)
{
	return ship_ht_keys(conn->params);
}

void
netio_http_respond_multipart_header(netio_http_conn_t *conn, 
				    int code, char *code_str)
{
	const char *templ = "HTTP/1.1 %d %s\r\nServer: P2PSHIP proxy\r\nConnection: close\r\nContent-Type: multipart/mixed;\r\n  boundary=\"%s\"\r\n\r\n";
	char *msg = mallocz(strlen(templ) + strlen(code_str) + 128);
	int i = 0;
	char boundary[32];
	if (!msg)
		return;

	for (i = 0; i < sizeof(boundary)-1; i++) {
		if (i < 5)
			boundary[i] = '-';
		else
			boundary[i] = 'a' + (rand() % 20);
	}
	boundary[sizeof(boundary)-1] = 0;

	netio_http_set_attr(conn, "boundary", boundary);
	sprintf(msg, templ, code, code_str, boundary);
	netio_send(conn->socket, msg, strlen(msg));
	freez(msg);
}

void
netio_http_respond_multipart(netio_http_conn_t *conn, 
			     char *content_type, 
			     char *data, int data_len)
{
	const char *templ = "%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: binary\r\n\r\n";
	char *msg = mallocz(strlen(templ) + strlen(content_type) + 128);
	char *boundary = 0;

	/* if no header set yet, create one */
	if (!(boundary = netio_http_get_attr(conn, "boundary"))) {
		netio_http_respond_multipart_header(conn, 200, "OK");
		boundary = netio_http_get_attr(conn, "boundary");
	}
	    
	sprintf(msg, templ, boundary, content_type);
	netio_send(conn->socket, msg, strlen(msg));
	netio_send(conn->socket, data, data_len);
	freez(msg);
}

int
netio_http_create_response(int code, char *code_str, 
			   char *content_type,
			   char *data, int data_len,
			   char **ret, int *retlen)
{
	const char *templ = "HTTP/1.1 %d %s\r\nServer: P2PSHIP proxy\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: %s\r\n\r\n";
	char *msg = mallocz(strlen(templ) + strlen(code_str) + data_len + strlen(content_type) + 128);
	int len = 0;
	if (!msg) {
		LOG_WARN("Could not create http response!\n");
		return -1;
	}
	sprintf(msg, templ, code, code_str, data_len, content_type);
	len = strlen(msg);
	memcpy(msg+len, data, data_len);
	len += data_len;

	*ret = msg;
	*retlen = len;
	return 0;
}

void
netio_http_respond(netio_http_conn_t *conn, 
		   int code, char *code_str, 
		   char *content_type,
		   char *data, int data_len)
{
	char *msg = 0;
	int len = 0;
	if (!netio_http_create_response(code, code_str, content_type, data, data_len,
				       &msg, &len)) {
		netio_send(conn->socket, msg, len);
		freez(msg);
	}
}

void
netio_http_respond_auth(netio_http_conn_t *conn, 
			char *realm,
			char *content_type,
			char *data)
{
	const char *templ = "HTTP/1.1 407 Proxy Authorization Required\r\nServer: P2PSHIP proxy\r\nProxy-Authenticate: Basic realm=\"%s\"\r\nContent-Length: %d\r\nConnection: close\r\nContent-Type: %s\r\n\r\n";
	char *msg = mallocz(strlen(templ) + strlen(realm) + strlen(data) + strlen(content_type) + 128);
	if (!msg)
		return;
	sprintf(msg, templ, realm, strlen(data), content_type);
	strcat(msg, data);
	netio_send(conn->socket, msg, strlen(msg));
	freez(msg);
}


void
netio_http_respond_str(netio_http_conn_t *conn, 
		       int code, char *code_str, 
		       char *data)
{
	netio_http_respond(conn, 
			   code, code_str, 
			   "text/plain",
			   data, strlen(data));
}

void
netio_http_respond_html(netio_http_conn_t *conn, 
		       int code, char *code_str, 
		       char *data)
{
	netio_http_respond(conn, 
			   code, code_str, 
			   "text/html",
			   data, strlen(data));
}

void
netio_http_redirect(netio_http_conn_t *conn, 
		    char *url)
{
	const char *templ = "HTTP/1.1 302 Found\r\nServer: P2PSHIP proxy\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	char *msg = mallocz(strlen(templ) + strlen(url) + 128);
	if (!msg)
		return;
	sprintf(msg, templ, url);
	netio_send(conn->socket, msg, strlen(msg));
	freez(msg);
}

/* create */
netio_http_server_t *
netio_http_server_new()
{
	netio_http_server_t *server = mallocz(sizeof(netio_http_server_t));
	if (server) {
		server->s = -1;
	}
	return server;
}

/* free */
void
netio_http_server_free(netio_http_server_t *server)
{
	if (server && server->s != -1) {
		netio_close_socket(server->s);
	}
	freez(server);
}

static netio_http_conn_t *
netio_http_get_conn_by_socket(int s, const int must_own)
{
	netio_http_conn_t *conn = 0;
	void *ptr = 0;
	if (!conns)
		return NULL;
	ship_lock(conns); {
		while (!conn && (conn = ship_list_next(conns, &ptr))) {
			// todo: check that it also owns the socket!
			if ((must_own && !conn->owns_socket) || conn->socket != s)
				conn = 0;
			else {
				conn = netio_http_conn_lock(conn);
			}
		}
	} ship_unlock(conns);
	return conn;
}

netio_http_conn_t *
netio_http_get_conn_by_id(const char *id)
{
	netio_http_conn_t *conn = 0;
	if (!conns)
		return NULL;
	ship_lock(conns); {
		if ((conn = ship_ht_get_string(conns_ht, id))) {
			conn = netio_http_conn_lock(conn);
		}
	} ship_unlock(conns);
	return conn;
}

static int
__netio_http_process_req(netio_http_conn_t *conn)
{
	netio_http_server_t *server = 0;

	if ((server = ship_ht_get_int(http_servers, conn->ss)) && server->func) {
		return server->func(conn, server->pkg);
	} else {
		return 0;
	}
}

/* callback when data is got */
static void 
__netio_http_conn_read_cb(int s, char *data, ssize_t datalen) 
{
	netio_http_conn_t *conn = 0;
	int ret = -1;

	ASSERT_TRUE(conn = netio_http_get_conn_by_socket(s, 1), err);
	if (datalen < 1) {
		goto err;
	}

	if (conn->forward_socket == -1) {
		ret = __netio_http_parse_data(conn, data, datalen);
	} else if (datalen > 0) {
		netio_send(conn->forward_socket, data, datalen);
		ret = 1;
	}

	/* process.. */
	while (!ret) {
		netio_http_conn_t *new_conn = 0;

		ret = __netio_http_process_req(conn); // should ret be checked??
		if (!strcmp(conn->method, "CONNECT"))
			break;

		if (!strcmp(conn->http_version, "HTTP/1.0")) {
			ret = -1;
			goto err;
		}

		/* we create a new conn for this socket as there might
		   be another request coming. This instead of clearing
		   the one as .. the http proxy will close the http_conn if
		   after responding to just one request.
		*/
		netio_http_cut_overrun(conn, &data, &datalen);
		ship_unlock(conn);
		
		ASSERT_TRUE(new_conn = netio_http_conn_new(s), err);
		memcpy(&(new_conn->addr), &(conn->addr), sizeof(addr_t));
		new_conn->ss = conn->ss;
		conn->owns_socket = 0;

		/* ..parse the data at this point, it IS pointing at
		   the buffer in the old conn! */
		if (datalen > 0)
			ret = __netio_http_parse_data(new_conn, data, datalen);
		else
			ret = 1;
		ship_unlock(new_conn);

		netio_http_conn_lock(conn);
		if (ret < 1) {
			netio_http_conn_close(conn);
		} else {
			ship_unlock(conn);
		}
		netio_http_conn_lock(new_conn);
		conn = new_conn;
	}
 err:
	if (ret < 1) {
		netio_http_conn_close(conn);
	} else if (conn) {
		ship_unlock(conn);
	}
}

/* callback for new connections */
static void 
__netio_http_conn_cb(int s, struct sockaddr *sa, socklen_t addrlen, int ss)
{
	netio_http_conn_t *conn = 0;
	LOG_DEBUG("Got connection on netio_http, socket %d (ss: %d)\n", s, ss);

	netio_http_conn_close_all(s);
	ASSERT_TRUE(conn = netio_http_conn_new(s), err);
	ASSERT_ZERO(ident_addr_sa_to_addr(sa, addrlen, &(conn->addr)), err);
	conn->ss = ss;
	ship_unlock(conn);
	ASSERT_ZERO(netio_read(s, __netio_http_conn_read_cb), err);
	return;
 err:
	netio_http_conn_close(conn);
}


/* modifies the port / host the server is listening to */
static int
__netio_http_server_listen(char *new_address)
{
	struct sockaddr *sa = 0;
	socklen_t salen;
	int ret = -1;
	char buf[1024];

	ASSERT_ZERO(ident_addr_str_to_sa(new_address, &sa, &salen), err);
	ASSERT_ZERO(ident_addr_sa_to_str(sa, salen, buf), err);
	LOG_INFO("Using %s for HTTP server\n", buf);
	
	ASSERT_TRUE((ret = netio_new_listener(sa, salen, __netio_http_conn_cb)) != -1, err);
	freez(sa);
 err:
	freez(sa);
	return ret;
}

/* register a http accepter for some address.
 *
 * @return -1 if not successful, otherwise the socket */
int
netio_http_server_create(char *address, 
			 int (*func) (netio_http_conn_t *conn, void *pkg),
			 void *pkg)
{
	netio_http_server_t *server = 0;
	int ret = -1;
	
	/* lock me */
	ASSERT_TRUE(server = netio_http_server_new(), err);
	ASSERT_TRUE((ret = __netio_http_server_listen(address)) != -1, err);
	server->s = ret;
	server->pkg = pkg;
	server->func = func;

	ship_ht_put_int(http_servers, ret, server);
	server = 0;
 err:
	netio_http_server_free(server);
	return ret;
}


/* modifies the port / host the server is listening to */
int
netio_http_server_modif(int ss, char *new_address)
{
	netio_http_server_t *server = 0;
	int ret = -1;
	
	/* lock me */
	ASSERT_TRUE((ret = __netio_http_server_listen(new_address)) != -1, err);	
	ASSERT_TRUE(server = ship_ht_remove_int(http_servers, ss), err);
	netio_close_socket(ss);
	
	server->s = ret;
	ship_ht_put_int(http_servers, ret, server);

	goto end;
 err:
	if (ret != -1) {
		netio_close_socket(ret);
		ret = -1;
	}
 end:
	return ret;
}

/* closes a http server */
void
netio_http_server_close(int ss)
{
	netio_http_server_t *server = 0;
	if ((server = ship_ht_remove_int(http_servers, ss))) {
		netio_http_server_free(server);
	}
}

int
netio_http_init(processor_config_t *config)
{
	int ret = -1;
	ASSERT_TRUE(orderer = ship_ht_new(), err);
	ASSERT_TRUE(conns = ship_list_new(), err);
	ASSERT_TRUE(conns_ht = ship_ht_new(), err);
	ASSERT_TRUE(http_servers = ship_ht_new(), err);
	srand(time(0));
	ret = 0;
 err:
	return ret;
}

void
netio_http_close()
{
	netio_http_conn_t *conn;
	netio_http_server_t *server;
	
	while (conns && (conn = ship_list_first(conns))) {
		netio_http_conn_close(conn);
	}
	ship_list_free(conns);
	conns = 0;
	
	ship_ht_free(conns_ht);
	ship_ht_free(orderer);

	/* free the servers */
	while (http_servers && (server = ship_ht_pop(http_servers))) {
		netio_http_server_free(server);
	}
	ship_ht_free(http_servers);
}

/* the netio_man register */
static struct processor_module_s processor_module = 
{
	.init = netio_http_init,
	.close = netio_http_close,
	.name = "netio_http",
#ifdef CONFIG_WEBCACHE_ENABLED
	.depends = "ident_addr,netio_man,webcache",
#else
	.depends = "ident_addr,netio_man",
#endif
};

/* register func */
void
netio_http_register() {
	processor_register(&processor_module);
}
