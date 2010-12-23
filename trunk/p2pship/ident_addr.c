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
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ident.h"
#include "ship_debug.h"
#include "processor.h"
#ifdef CONFIG_HIP_ENABLED
#include "hipapi.h"
#endif

/* dummy to lock getaddrinfo calls */
static ship_list_t *getaddrinfolock = 0;
static void *addrinfo_thread = 0;
static ship_ht_t *getaddrinfo_cache = 0;

/* small struct for cached entries for getaddrinfo lookup */
typedef struct getaddrinfo_cache_s {
	
	time_t valid;
	struct sockaddr *sa;
	socklen_t sa_len;
} getaddrinfo_cache_t;

typedef struct ident_addr_lookup_s {
	ship_obj_t parent;
	
	int valid;
	struct sockaddr **sa;
	socklen_t *sa_len;
	addr_t *addr;
} ident_addr_lookup_t;

static void ident_addr_lookup_free(ident_addr_lookup_t *obj);
static int ident_addr_lookup_init(ident_addr_lookup_t *obj, void *param);
SHIP_DEFINE_TYPE(ident_addr_lookup);

#define len_memcmp(str, memloc, memlen) ((memlen - strlen(str)) || memcmp(str, memloc, memlen))

int 
ident_addr_init(processor_config_t *config)
{
	int ret = -1;
	ASSERT_TRUE(getaddrinfolock = ship_list_new(), err);
	ASSERT_TRUE(addrinfo_thread = processor_to_init("getaddrinfo"), err);
	ASSERT_TRUE(getaddrinfo_cache = ship_ht_new(), err);
	ret = 0;
 err:
	return ret;
}


void 
ident_addr_close()
{
	ship_list_free(getaddrinfolock);
	getaddrinfolock = 0;
	if (getaddrinfo_cache) {
		getaddrinfo_cache_t *e = 0;
		while ((e = ship_ht_pop(getaddrinfo_cache))) {
			freez(e->sa);
			freez(e);
		}
		ship_ht_free(getaddrinfo_cache);
	}
}

/* converts a string to an addr_t */
int 
ident_addr_str_to_addr_dup(char *str, addr_t** addr)
{
        (*addr) = (addr_t*)mallocz(sizeof(addr_t));
        if (*addr) 
                return ident_addr_str_to_addr(str, *addr);
        else
                return -4;
}


/* converts a string to an addr_t, dns lookupping any hostnames */
int 
ident_addr_str_to_addr_lookup(char *str, addr_t* addr)
{
	int ret = -1;
	struct sockaddr *sa = 0;
	socklen_t sa_len = 0;
	addr_t tmpaddr;

	ASSERT_ZERO(ret = ident_addr_str_to_addr(str, addr), err);
	ASSERT_ZERO(ret = ident_addr_addr_to_sa(addr, &sa, &sa_len), err);
	ASSERT_ZERO(ident_addr_sa_to_addr(sa, sa_len, &tmpaddr), err);
	memcpy(addr->addr, tmpaddr.addr, sizeof(tmpaddr.addr));
	ret = 0;
 err:
 	freez(sa);
	return ret;
}

/* converts a string to an addr_t */
int 
ident_addr_str_to_addr(char *str, addr_t* addr)
{
        /* separate host, port, parameters */
        char *params;
        char *port;
        char *e;
        int len;
        
	bzero(addr, sizeof(*addr));
        /* parse host - addr & type */
        addr->family = AF_UNSPEC;
        e = str;
        if ((*str) == '[') {
                if (!(e = strchr(str, ']')))
                        return -1;
                addr->family = AF_INET6;
                str++;
        } else {
		/* check if we have > 1 colon, then let it be a ipv6, no port though */
		for (len = 0; strchr(e, ':'); len++) e = strchr(e, ':')+1;
		if (len > 1) {
			addr->family = AF_INET6;
			e = strchr(e, ';');
			if (!e)
				e = str + strlen(str);
		} else
			e = str;
	}

        if ((port = strchr(e, ':')) > (params = strchr(e, ';')) && params) 
                port = NULL;
        
        /* see that there's no extra chars on ipv6 addrs */
        if (addr->family == AF_INET6) {
                if (*(e) != 0 && *(e+1) != 0 && (e+1) != port && (e+1) != params)
                        return -1;
        } else {
                e = (port? port : (params? params : str+strlen(str)));                
                if (e != str)
                        addr->family = AF_INET;
        }
        len = (e-str > IDENT_ADDR_MAX_LEN? IDENT_ADDR_MAX_LEN : e-str);
        strncpy(addr->addr, str, len);
	addr->addr[len] = 0;

	/* trim spaces & other non-printables from end (newlines mainly) */
	while ((len > 0) && (addr->addr[len-1] < 33))
		addr->addr[--len] = 0;

        /* parse port */
        /* ends in either ; or null. anyway, both ok */
        if (port)
                addr->port = atoi(port+1);
        else
                addr->port = 0;

	/* copy over to hostname */
	strcpy(addr->hostname, addr->addr);

        /* check params one by one - ok? */
        addr->type = IPPROTO_NONE;
        if (params) {
                do {
                        char *k, *v, *ke, *ve;
                        
                        e = strchr(++params, '&');
                        if (!e) ve = str+strlen(str);
                        else ve = e;
                        
                        if (ve == params)
                                continue;

                        k = params;
                        if ((ke = strchr(k, '=')) > ve || !ke) {
                                ke = ve;
                                v = ve;
                        } else
                                v = ke+1;
                        
                        if (!len_memcmp("type", k, ke-k)) {
                                if (!len_memcmp("udp", v, ve-v)) {
                                        addr->type = IPPROTO_UDP;
                                } else if (!len_memcmp("tcp", v, ve-v)) {
                                        addr->type = IPPROTO_TCP;
                                } else
                                        return -1;
			} else if (!len_memcmp("hostname", k, ke-k)) {
				strncpy(addr->hostname, v, ve-v);
                        } else
                                return -1; /* invalid parameter! */
                        
                        params = e;
                } while (e);
        }
        
        return 0;
}

int 
ident_addr_addr_to_str(addr_t* addr, char **str)
{
	int hasparam = 0;
        char *ret = (char*)mallocz((2 * IDENT_ADDR_MAX_LEN) + 50);
        if (!ret)
                return -4;

        if (addr->family == AF_INET6)
                strcat(ret, "[");

        strncat(ret, addr->addr, IDENT_ADDR_MAX_LEN);

        if (addr->family == AF_INET6)
                strcat(ret, "]");

        if (addr->port > 0) {
                sprintf(ret+strlen(ret), ":%d", addr->port);

                /* no type without port! */
                switch (addr->type) {
                case IPPROTO_TCP:
                        strcat(ret, ";type=tcp");
                        hasparam = 1;
			break;
                case IPPROTO_UDP:
                        strcat(ret, ";type=udp");
                        hasparam = 1;
                        break;
                case IPPROTO_NONE:
                default:
                        break;
                }
        }
	
	if (strcmp(addr->addr, addr->hostname) && strlen(addr->hostname)) {
		strcat(ret, (hasparam? "&" : ";"));
		strcat(ret, "hostname=");
		strcat(ret, addr->hostname);
	}

        (*str) = ret;
        return 0;
}

static int
ident_addr_addr_to_sa_to(void *data)
{
	ident_addr_lookup_t *lookup = (ident_addr_lookup_t *)data;
        int ret = -1;
        struct sockaddr *sat = 0;
	socklen_t sat_len = 0;
	struct addrinfo hints4, hints6;
	getaddrinfo_cache_t *e = 0;
	struct addrinfo *res = 0;
	addr_t addr;

	ship_lock(lookup);
	memcpy(&addr, lookup->addr, sizeof(addr));
	ship_unlock(lookup);
	
	/* check cache first. */
#define CACHE_GETADDR
#ifdef CACHE_GETADDR
	e = ship_ht_get_string(getaddrinfo_cache, addr.addr);
	if (e) {
		if (e->valid >= time(0)) {
			sat = e->sa;
			sat_len = e->sa_len;
			goto copy;			
		} else {
			ship_ht_remove(getaddrinfo_cache, e);
			freez(e->sa);
			freez(e);
		}
	}

	/* if not, then put there an entry NULL with validity of .. secs */
	if ((e = mallocz(sizeof(getaddrinfo_cache_t)))) {
		e->valid = time(0) + 30; /* 30 secs */
		ship_ht_put_string(getaddrinfo_cache, addr.addr, e);
	}
#endif
	bzero(&hints4, sizeof(hints4));
	bzero(&hints6, sizeof(hints6));
	hints4.ai_family = AF_INET;
	hints6.ai_family = AF_INET6;

	/* todo: if we do not kill this thread when getting stuck, we
	   need to make a thread-local copy of addr->addr and use
	   that */

#ifdef CONFIG_HIP_ENABLED
	/* we do not want to do any hit lookups here! */
	getaddrinfo_disable_hit_lookup();
#endif
	/* try ipv4 first, then ipv6 */
	if (!getaddrinfo(addr.addr, NULL, &hints4, &res) ||
	    !getaddrinfo(addr.addr, NULL, &hints6, &res)) {
                sat = res->ai_addr;
		sat_len = res->ai_addrlen;
		sat->sa_family = res->ai_family;
#ifdef CACHE_GETADDR
		if (e) {
			if ((e->sa = mallocz(sat_len))) {
				e->sa_len = sat_len;
				memcpy(e->sa, sat, sat_len);
				e->valid = time(0) + 3600; /* 1 hrs */
			}
		}
#endif
	}
	
 copy:
	/* check first if we are valid before doing any copying! */
	ship_lock(lookup);
	if (lookup->valid && sat && (*(lookup->sa) = mallocz(sat_len))) {
		memcpy(*(lookup->sa), sat, sat_len);
		*(lookup->sa_len) = sat_len;
		
		switch (sat->sa_family) {
		case AF_INET:
			((struct sockaddr_in*)(*(lookup->sa)))->sin_port = htons(addr.port);
			break;
		case AF_INET6:
			((struct sockaddr_in6*)(*(lookup->sa)))->sin6_port = htons(addr.port);
			break;
		}
		ret = 0;
	}
	ship_unlock(lookup);
	
	if (res) {
                freeaddrinfo(res);
		res = 0;
	}
	
	ship_obj_unref(lookup);
        return ret;
}

static void
ident_addr_lookup_free(ident_addr_lookup_t *obj)
{
	/* doesn't own any of the data! */
	obj->valid = 0;
}

static int 
ident_addr_lookup_init(ident_addr_lookup_t *obj, void *param)
{
	obj->valid = 1;
	obj->addr = (addr_t*)param;
	return 0;
}

int 
ident_addr_addr_to_sa(addr_t *addr, struct sockaddr **sa, socklen_t *sa_len)
{
	int fret = 0;
	int ret = -1;
	ident_addr_lookup_t *lookup = 0;

	ASSERT_TRUE(lookup = (ident_addr_lookup_t *)ship_obj_new(TYPE_ident_addr_lookup, addr), err);
	lookup->sa = sa;
	lookup->sa_len = sa_len;
	*sa = 0;

	ship_obj_ref(lookup); // add extra ref here already.
	ret = processor_to(addrinfo_thread, ident_addr_addr_to_sa_to, NULL, lookup, &fret, 2000);
	switch (ret) {
	case PROCESSOR_TO_ERROR:
		ship_obj_unref(lookup);
		break;
	case PROCESSOR_TO_STUCK:
		ship_lock(lookup);
		lookup->valid = 0;
		ship_unlock(lookup);
		break;
	case PROCESSOR_TO_DONE:
		ret = fret;
		break;
	}
 err:
	ship_obj_unref(lookup);
	return ret;
}

int 
ident_addr_socket_to_addr(int s, addr_t *addr)
{
	struct sockaddr_in6 sa; // use the biggest we'll ever encounter..
	socklen_t salen = sizeof(sa);
	
	if (!getpeername(s, (struct sockaddr*)&sa, &salen))
		return ident_addr_sa_to_addr((struct sockaddr*)&sa, salen, addr);
	return -1;
}

int 
ident_addr_sa_to_addr(struct sockaddr *sa, socklen_t sa_len, addr_t *addr)
{
	bzero(addr, sizeof(*addr));
	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		if (!inet_ntop(sa->sa_family, &(sin->sin_addr), (char*)&(addr->addr), sizeof(addr->addr)))
			return -1;
		addr->port = ntohs(sin->sin_port);
                addr->family = AF_INET;
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
		ident_addr_in6_to_addr(&sin->sin6_addr, addr);
		addr->port = ntohs(sin->sin6_port);
                addr->family = AF_INET6;
		break;
	}
	default:
		return -2;
	}
	addr->type = IPPROTO_NONE;
	
	return 0;
}


int 
ident_addr_sa_to_str(struct sockaddr *sa, socklen_t sa_len, char *str)
{
	addr_t addr;
	if (ident_addr_sa_to_addr(sa, sa_len, &addr))
		return -1;
	
	switch (sa->sa_family) {
	case AF_INET: {
		sprintf(str, "%s:%d", addr.addr, addr.port);
		break;
	}
	case AF_INET6: {
		sprintf(str, "[%s]:%d\n", addr.addr, addr.port);
		break;
	}
	default:
		return -2;
	}
	
	return 0;
}

int 
ident_addr_str_to_sa(char *str, struct sockaddr **sa, socklen_t *sa_len)
{
        addr_t addr;
        if (ident_addr_str_to_addr(str, &addr))
                return -1;

        return ident_addr_addr_to_sa(&addr, sa, sa_len);
}

int 
ident_addr_str_to_sa_lookup(char *str, struct sockaddr **sa, socklen_t *sa_len)
{
        addr_t addr;
        if (ident_addr_str_to_addr_lookup(str, &addr))
                return -1;

        return ident_addr_addr_to_sa(&addr, sa, sa_len);
}


void
ident_addr_in6_to_addr(struct in6_addr* in6, addr_t* addr)
{
	addr->family = AF_INET6;
	addr->port = 0;
	addr->type = IPPROTO_NONE;
	sprintf(addr->addr, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
		ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
		ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
		ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
		ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
}

int 
ident_addr_cmp(addr_t *addr1, addr_t *addr2)
{
	if ((addr1->family == addr2->family) &&
	    (addr1->port == addr2->port) &&
	    (addr1->type == addr2->type))
		return strcmp(addr1->addr, addr2->addr);
	else
		return -1;
}

/* the ident register */
static struct processor_module_s processor_module = 
{
	.init = ident_addr_init,
	.close = ident_addr_close,
	.name = "ident_addr",
	.depends = "",
};

/* register func */
void
ident_addr_register() {
	processor_register(&processor_module);
}
