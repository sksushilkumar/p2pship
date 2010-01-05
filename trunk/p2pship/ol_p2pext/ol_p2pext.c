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
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <pthread.h>

#include "ship_utils.h"
#include "ship_debug.h"
#include "ol_p2pext.h"
#include "ident.h"

/* the name of this module */
static const char *ol_p2pext_name_str = "p2pext";
static struct olclient_module ol_p2pext_module;
static char *ol_p2pext_proxy = 0;

typedef struct ol_p2pext_s {
	void *param;
	void (*callback) (char *val, int status, olclient_lookup_t *lookup, struct olclient_module* mod);
	olclient_lookup_t *lookup;
} ol_p2pext_t;

ol_p2pext_t *
ol_p2pext_new(void *param, void (*callback) (char *val, int status, olclient_lookup_t *lookup, struct olclient_module* mod),
	      olclient_lookup_t *lookup)
{
	ol_p2pext_t *ret = mallocz(sizeof(ol_p2pext_t));
	if (ret) {
		ret->param = param;
		ret->callback = callback;
		ret->lookup = lookup;
	}
	return ret;
}

void
ol_p2pext_free(ol_p2pext_t *l)
{
	freez(l);
}

const char* 
ol_p2pext_name()
{
	return ol_p2pext_name_str;
}

static void 
ol_p2pext_get_cb(char *url, int respcode, char *data, 
		 int datalen, void *pkg)
{
	ol_p2pext_t *l = pkg;
	char *d2 = 0;

	LOG_DEBUG("Got P2PSHIP EXT callback code %d, data: %d\n", respcode, datalen);
	if (pkg) {
		if ((respcode / 100) == 2) {
			d2 = mallocz(datalen+1);
		}
		if (d2) {
			memcpy(d2, data, datalen);
			l->callback(d2, 0, l->lookup, &ol_p2pext_module);
		} else
			l->callback(0, 0, l->lookup, &ol_p2pext_module);
		ol_p2pext_free(l);
	}
}

static int 
ol_p2pext_get(char *key, void *param, 
	      void (*callback) (char *val, int status, olclient_lookup_t *lookup, struct olclient_module* mod),
	      olclient_lookup_t *lookup)
{
	char *data = 0, *tmp = 0;
	int len = 0, size = 0;
	ol_p2pext_t *l = 0;
	int ret = -1;
	
	LOG_DEBUG("Performing get for key %s\n", key);
	
	/* create a nice post param packet from this */
	ASSERT_TRUE(l = ol_p2pext_new(param, callback, lookup), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("key", key, data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("entry", "0", data, &size, &len)) && (data = tmp), err);
	
	if (ol_p2pext_proxy && !netio_http_post_host(ol_p2pext_proxy,
						     "/get", "",
						     "application/x-www-form-urlencoded", 
						     data, len, ol_p2pext_get_cb, l)) {
		l = 0;
		ret = 0;
	}
 err:
	ol_p2pext_free(l);
	freez(data);
	return ret;
}

static int 
ol_p2pext_remove(char *key, char* secret)
{	
	char *data = 0, *tmp = 0;
	int len = 0, size = 0;
	int ret = -1;

	LOG_DEBUG("Performing rm for key %s\n", key);
	
	/* create a nice post param packet from this */
	ASSERT_TRUE((tmp = ship_addparam_urlencode("key", key, data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("secret", (secret? secret: ""), data, &size, &len)) && (data = tmp), err);

	if (ol_p2pext_proxy && !netio_http_post_host(ol_p2pext_proxy,
						     "/rm", "",
						     "application/x-www-form-urlencoded", 
						     data, len, ol_p2pext_get_cb, NULL)) {	
		ret = 0;
	}
 err:
	freez(data);
	return ret;
}

static int 
ol_p2pext_put(char *key, char *pdata, int timeout, char *secret, int cached)
{
	char *data = 0, *tmp = 0;
	int len = 0, size = 0;
	int ret = -1;
	char ttl[32];

	LOG_DEBUG("Performing put for key %s\n", key);
	
	if (cached)
		return 0;

	/* create a nice post param packet from this */
	sprintf(ttl, "%d", timeout);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("key", key, data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("data", pdata, data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("secret", (secret? secret: ""), data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("ttl", ttl, data, &size, &len)) && (data = tmp), err);

	if (ol_p2pext_proxy && !netio_http_post_host(ol_p2pext_proxy,
						     "/put", "",
						     "application/x-www-form-urlencoded", 
						     data, len, ol_p2pext_get_cb, NULL)) {	
		ret = 0;
	}
 err:
	freez(data);
	return ret;
}

static int
ol_p2pext_cb_config_update(processor_config_t *config, char *k, char *v)
{
	char *proxy = 0, *tmp;
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_P2PEXT_PROXY,
						&proxy), err);
	tmp = ol_p2pext_proxy;
	ol_p2pext_proxy = strdup(proxy);
	freez(tmp);
	return 0;
 err:
	return -1;
}

int 
ol_p2pext_init(processor_config_t *config)
{
#ifdef CONFIG_P2PEXT_ENABLED
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_P2PEXT_PROXY, ol_p2pext_cb_config_update);
	ol_p2pext_cb_config_update(config, NULL, NULL);
	return olclient_register_module(&ol_p2pext_module);
 err:
#endif
	return -1;
}

void 
static ol_p2pext_close(void)
{
	freez(ol_p2pext_proxy);
}


/* the struct, things needed for the interface */
static struct olclient_module ol_p2pext_module = {
	.get = ol_p2pext_get,
	.remove = ol_p2pext_remove,
	.put = ol_p2pext_put,
	.put_signed = 0,
	.get_signed = 0,
	.close = ol_p2pext_close,
	.name = ol_p2pext_name,
};
