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
#include "netio.h"
#include <string.h>
#include <netinet/in.h>
#include "ship_debug.h"
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "ident.h"
#include <netinet/in.h>
#include "hipapi.h"

/* whether to bind the outbound hip sockets to our default hip */
#define BIND_HIP_TO_DEFAULT_HIT 1

static ship_list_t *netio_sock_list;
//static ship_list_t *netio_sock_remove_list;
static int netio_alive;

STATIC_THREAD_DECL(netio_thread);
static int netio_l_pipe[2];

/* the pipe used for notifying the ff thread */
STATIC_THREAD_DECL(netio_ff_thread);
static int netio_ff_l_pipe[2];

/* some prototypes */
static void *netio_loop(void *data);
void netio_ff_close();
int netio_ff_init();

/* some generic sockets used for anonymous udp data transmission */
static int generic_ipv4_socket = -1;
static int generic_ipv6_socket = -1;


/*
  for the record, the fragmentation logic:

  - when creating a new mediaproxy for incoming packets, send a
    message (via the p2psip tunnel) saying that you support
    fragmentation + a magic string the other should send to signal
    that he will use it.

  - the otherone sends the magic, which turns on 'fragmentation mode'
    for the receiver.

  - packets are sent with the last bytes set to 'f' and the number
    (0-64) of this packet. These should be sent in reverse, so that
    the first packet arrives last!  E.g. 3-packet fragmentation would
    first send a packet with the last bytes f2, then f1, then f0. The
    receiver should combine these until it receives the zero. If the
    receiver receives something else than a fX-ending packet, it
    should be forwarded untouched.

  - having the last byte as a mark is probably better than the first,
    as if the receiver does not process the packet, video / voice does
    not get as messed up. 

  - having the f and requiring the val to be between 0 and 64 makes
    (in average) only 1/(255*4) chance that a random packet would look
    like a fragmented one (in case the sender accidentally sends the
    magic string in its data)

*/


#define FRAGMENT_MAGIC_PACKET "p2pship_fragment:start"
#define FRAGMENT_MAGIC_PACKET_LEN 22

static int 
SET_SOCK_TO(int s, int secs)
{
	struct timeval timer;
	int ret;
	
	timer.tv_sec = secs;
	timer.tv_usec = 0;
	ret = setsockopt(s, SOL_SOCKET, SO_SNDTIMEO,
			 &timer, sizeof(timer));
	ret = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
			 &timer, sizeof(timer));
	return ret;
}

static void
netio_sock_free(netio_sock_t *s)
{
        if (s) {
                if (s->send_queue) {
			ship_lock(s->send_queue); {
                        while (ship_list_first(s->send_queue)) {
				void **e = ship_list_pop(s->send_queue);
				freez(e[0]);
				freez(e[1]);
				freez(e[2]);
				freez(e);
                        }} ship_unlock(s->send_queue);
                        ship_list_free(s->send_queue);
                }

                if (s->sa)
                        free(s->sa);
                free(s);
        }
}


static netio_sock_t *
netio_sock_new(int type, struct sockaddr *sa, socklen_t salen)
{
        netio_sock_t *ret;        
        ASSERT_TRUE(ret = (netio_sock_t*)mallocz(sizeof(netio_sock_t)), err);
        ret->active = 1;
        ret->type = type;
	ASSERT_TRUE(ret->send_queue = ship_list_new(), err);
	
        if (sa) {
                ASSERT_TRUE(ret->sa = (struct sockaddr*)malloc(salen), err);
                memcpy(ret->sa, sa, salen);
                ret->addrlen = salen;
        }
        return ret;
err:
        netio_sock_free(ret);
        return NULL;
}

void 
netio_close()
{
        LOG_INFO("closing netio..\n");

        netio_alive = 0;

        /* notify the listener */
	ship_lock(netio_sock_list); {
		write(netio_l_pipe[1], "0", 1);
	} ship_unlock(netio_sock_list);
	
        if (netio_thread) {
                THREAD_JOIN(netio_thread);
                THREAD_FREE(netio_thread);
        }

        /* clean up the list */
        if (netio_sock_list) {
                ship_lock(netio_sock_list); {
                        while (ship_list_first(netio_sock_list)) {
                                netio_sock_free((netio_sock_t *)ship_list_pop(netio_sock_list));
                        }
                } ship_unlock(netio_sock_list);
        }
        
        ship_list_free(netio_sock_list);

	if (generic_ipv4_socket != -1)
		close(generic_ipv4_socket);
	if (generic_ipv6_socket != -1)
		close(generic_ipv6_socket);
}

int 
netio_init(processor_config_t *config)
{
        if (!(netio_sock_list = ship_list_new()))
                goto err;

        if (pipe(netio_l_pipe))
                goto err;

        MAKE_NONBLOCK(netio_l_pipe[0]);
        MAKE_NONBLOCK(netio_l_pipe[1]);

        /* start the thread */
        netio_alive = 1;
        if ((THREAD_INIT(netio_thread)) == 0 ||
            (THREAD_RUN(netio_thread, netio_loop, NULL)) != 0) {
                freez(netio_thread);
                goto err;
        }
	
        return 0;
 err:
        netio_close();
        return -1;
}


static void
netio_sock_add(netio_sock_t *s)
{
        ship_lock(netio_sock_list); {
                ship_list_add(netio_sock_list, s);
                write(netio_l_pipe[1], "0", 1);
        } ship_unlock(netio_sock_list);
}


void
netio_set_active(int socket, int active)
{
        netio_sock_t *e;
        void *ptr = NULL;
        ship_lock(netio_sock_list); {
                while (socket != -1 && (e = ship_list_next(netio_sock_list, &ptr))) {
                        if (e->s == socket) {
                                e->active = active;
                                socket = -1;
                                write(netio_l_pipe[1], "0", 1);
                        }
                }
        } ship_unlock(netio_sock_list);
}

#define MAX(a, b) (a > b ? a : b)

/* closes a socket */
void
netio_close_socket(int s)
{
	netio_sock_t *e = 0;
	void *ptr = 0, *last = 0;
	int closeit = 1;

	if (s == -1)
		return;

	/* if we have this one on our read-list, then just mark for
	   flushing */
	ship_lock(netio_sock_list); {
                while ((e = ship_list_next(netio_sock_list, &ptr))) {
                        if (e->s != s)
				continue;
			
			ship_lock(e->send_queue);
			if (e->type == NETIO_SOCK_WRITE) {
				if (e->flush || ship_list_first(e->send_queue)) {
					e->flush = 1;
					closeit = 0;
				}
			}

			if (!e->flush) {
				e->remove = 1;
			}
			ship_unlock(e->send_queue);
			last = ptr;
                }
	} ship_unlock(netio_sock_list);

	if (closeit) {
		shutdown(s, SHUT_RDWR);
		close(s);
	}
}

int
netio_remove_read(int s)
{
        int ret = -1;
	void *ptr;
        ship_lock(netio_sock_list); {
		netio_sock_t *e = NULL;
		ptr = 0;
		while ((e = ship_list_next(netio_sock_list, &ptr))) {
			ship_lock(e->send_queue);
			if (e->s == s && 
			    e->type !=  NETIO_SOCK_WRITE) {
				e->remove = 1;
				ret = 0;
			}
			ship_unlock(e->send_queue);
		}
	} ship_unlock(netio_sock_list);
        return ret;
}

int 
netio_new_packet_socket(struct sockaddr *sa, socklen_t size)
{
        int ret = -1;
        int option;
	
	switch (sa->sa_family) {
	case AF_INET:
		ret = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		break;
	case AF_INET6:
		ret = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		break;
	default:
		ret = -1;
		break;
	}
	
        if (ret == -1)
                goto err;

        /* set reuse so we don't need to wait for the socket reset time */
        option = 1;
        ASSERT_ZERO(setsockopt(ret, SOL_SOCKET, SO_REUSEADDR,
                               (const void*) &option, sizeof option), err);

        MAKE_NONBLOCK(ret);
        ASSERT_ZERO(bind(ret, sa, size), err);

        return ret;
 err:
        if (ret != -1)
                close(ret);
        ret = -1;
        return ret;
}

int 
netio_packet_read(int s,
		  void (*callback) (int s, char *data, size_t len,
				    struct sockaddr *sa, socklen_t addrlen))
{
        netio_sock_t *e = NULL;
	struct sockaddr *sa = 0;
	socklen_t size;
	
	size = MAX(sizeof(struct sockaddr_in), sizeof(struct sockaddr_in6));
	ASSERT_TRUE(sa = mallocz(size), err);
	ASSERT_ZERO(getsockname(s, sa, &size), err);
	
        /* make entry */
        ASSERT_TRUE(e = netio_sock_new(NETIO_SOCK_PACKET_READ, sa, size), err);

        e->s = s;
        e->packet_read_callback = callback;
        netio_sock_add(e);
        freez(sa);
	return 0;
 err:
        freez(sa);
        netio_sock_free(e);
        return -1;
}

int 
netio_new_packet_reader(struct sockaddr *sa, socklen_t size, 
                        void (*callback) (int s, char *data, size_t len,
                                          struct sockaddr *sa, socklen_t addrlen))
{

        int ret = -1;

        /* make entry */
	ret = netio_new_packet_socket(sa, size);
	ASSERT_TRUE(ret != -1, err);
        ASSERT_ZERO(netio_packet_read(ret, callback), err);
        return ret;
 err:
        if (ret != -1)
                close(ret);
        ret = -1;
        return ret;
}

int 
netio_new_multicast_reader(char *mc_addr, 
			   struct sockaddr *sa, socklen_t size,			   
			   void (*callback) (int s, char *data, size_t len,
					     struct sockaddr *sa, socklen_t addrlen))
{
	struct ip_mreq mreq;
        int ret = -2;
        netio_sock_t *e = NULL;
        int option;
	struct sockaddr* sa2 = 0;
	u_char ttl;
    
	/* we assume ipv4 */
	if (sa->sa_family != AF_INET)
		return -1;

        ASSERT_TRUE((ret = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) != -1, err);

	/* join the multicast group.. */
	ASSERT_TRUE(inet_aton(mc_addr, &mreq.imr_multiaddr), err);
	mreq.imr_interface.s_addr = ((struct sockaddr_in*)sa)->sin_addr.s_addr;
	ASSERT_ZERO(setsockopt(ret, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)),
		    err);

        /* set reuse so we don't need to wait for the socket reset time */
        option = 1;
        ASSERT_ZERO(setsockopt(ret, SOL_SOCKET, SO_REUSEADDR,
                               (const void*) &option, sizeof option), err);

        MAKE_NONBLOCK(ret);	

	ASSERT_TRUE(sa2 = mallocz(size), err);
	memcpy(sa2, sa, size);
	((struct sockaddr_in*)sa2)->sin_addr.s_addr = INADDR_ANY;
	ASSERT_ZERO(bind(ret, sa2, size), err);
	freez(sa2);

	/* whadda? */
	setsockopt(ret, IPPROTO_IP, IP_MULTICAST_IF, &mreq.imr_interface.s_addr, 
		   sizeof(mreq.imr_interface.s_addr));

	ttl = 2;
	setsockopt(ret, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

        /* make entry */
        ASSERT_TRUE(e = netio_sock_new(NETIO_SOCK_PACKET_READ, sa, size), err);

        e->s = ret;
        e->packet_read_callback = callback;
        netio_sock_add(e);
        return ret;
 err:
	freez(sa2);
        if (ret != -1)
                close(ret);
        ret = -1;
        netio_sock_free(e);
        return ret;
}

int 
netio_new_listener(struct sockaddr *sa, socklen_t size, 
                   void (*callback) (int s, struct sockaddr *sa, socklen_t addrlen, int ss))
{
        int ret = -1;
        netio_sock_t *e = NULL;
        int option;

	switch (sa->sa_family) {
	case AF_INET:
		ret = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		break;
	case AF_INET6:
		ret = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
		break;
	}
        if (ret == -1)
                goto err;

        /* set reuse so we don't need to wait for the socket reset time */
        option = 1;
        ASSERT_ZERO(setsockopt(ret, SOL_SOCKET, SO_REUSEADDR,
                               (const void*) &option, sizeof option), err);

        MAKE_NONBLOCK(ret);
        ASSERT_ZERO(bind(ret, sa, size), err);
	
	/* fetch socket address in case we had a port 0 .. */
	ASSERT_ZERO(getsockname(ret, sa, &size), err);

        /* make entry */
        ASSERT_TRUE(e = netio_sock_new(NETIO_SOCK_ACCEPT, sa, size), err);
        e->s = ret;
        e->accept_callback = callback;
        ASSERT_ZERO(listen(ret, 10), err);
        netio_sock_add(e);
        return ret;

 err:
        if (ret != -1)
                close(ret);
        ret = -1;
        netio_sock_free(e);
        return ret;
}

int 
netio_new_unix_socket(char *unix_socket, mode_t mode,
		      void (*callback) (int, struct sockaddr *, socklen_t, int))
{
	struct sockaddr_un sa;
	int ret = -1, size;
        netio_sock_t *e = NULL;
        int option;

	ret = socket(AF_UNIX, SOCK_STREAM, 0);
        if (ret == -1)
                goto err;

        /* set reuse so we don't need to wait for the socket reset time */
        option = 1;
        ASSERT_ZERO(setsockopt(ret, SOL_SOCKET, SO_REUSEADDR,
                               (const void*) &option, sizeof option), err);
        MAKE_NONBLOCK(ret);

	sa.sun_family = AF_UNIX;
	strcpy(sa.sun_path, unix_socket);
	unlink(sa.sun_path);
	size = sizeof(sa);
	ASSERT_ZERO(bind(ret, (struct sockaddr *)&sa, size), err);
	ASSERT_ZERO(chmod(unix_socket, mode), err);

        /* make entry */
        ASSERT_TRUE(e = netio_sock_new(NETIO_SOCK_ACCEPT, (struct sockaddr*)&sa, size), err);
        e->s = ret;
        e->accept_callback = callback;
        ASSERT_ZERO(listen(ret, 10), err);
        netio_sock_add(e);
        return ret;

 err:
        if (ret != -1)
                close(ret);
        ret = -1;
        netio_sock_free(e);
        return ret;
}

int 
netio_connto(struct sockaddr *sa, socklen_t size, 
	     void (*callback) (int s, struct sockaddr *sa, socklen_t addrlen))
{
        int ret = -1;
        netio_sock_t *e = NULL;
	addr_t addr;
	
	ASSERT_ZERO(ident_addr_sa_to_addr(sa, size, &addr), err);
	switch (sa->sa_family) {
	case AF_INET6: {
		LOG_INFO("connecting to %s, port %d\n", addr.addr, addr.port);
		ret = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);

#ifdef CONFIG_HIP_ENABLED
#ifdef BIND_HIP_TO_DEFAULT_HIT
		if (hipapi_addr_is_hit(&addr)) {
			struct sockaddr *bsin = 0;
			socklen_t bsin_len = 0;
			ASSERT_ZERO(hipapi_gethit(&addr), err);
			ASSERT_ZERO(ident_addr_addr_to_sa(&addr, &bsin, &bsin_len), err);
			ASSERT_ZERO(bind(ret, bsin, bsin_len), err);
			freez(bsin);
		}
#endif
#endif
		break;
	}
	case AF_INET: {
		LOG_INFO("connecting to %s, port %d\n", addr.addr, addr.port);
		ret = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
		break;
	}
	default:
		break;
	}

        ASSERT_TRUE(ret != -1, err);
        MAKE_NONBLOCK(ret);
	MAKE_TCP_NODELAY(ret);
	ASSERT_ZERO(SET_SOCK_TO(ret, 3), err);

        /* make entry */
        ASSERT_TRUE(e = netio_sock_new(NETIO_SOCK_CONNTO, sa, size), err);
        e->s = ret;
        e->connto_callback = callback;
 
	/* this might hang, freezing up the system! */
	ship_wait("netio connect");
	connect(e->s, e->sa, e->addrlen);
        netio_sock_add(e);
	ship_complete();
        return ret;
 err:
        if (ret != -1)
                close(ret);
        ret = -1;
        netio_sock_free(e);
        return ret;
}

int 
netio_packet_connto(struct sockaddr *sa, socklen_t size)
{
        int ret = -1;
	addr_t addr;

	ASSERT_ZERO(ident_addr_sa_to_addr(sa, size, &addr), err);
	switch (sa->sa_family) {
	case AF_INET6: {
		LOG_INFO("connecting to %s, port %d\n", addr.addr, addr.port);
		ret = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
		break;
	}
	case AF_INET: {
		LOG_INFO("connecting to %s, port %d\n", addr.addr, addr.port);
		ret = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		break;
	}
	default:
		break;
	}

        ASSERT_TRUE(ret != -1, err);
	ASSERT_ZERO(connect(ret, sa, size), err);
        MAKE_NONBLOCK(ret);
        return ret;
 err:
        if (ret != -1)
                close(ret);
        ret = -1;
        return ret;
}

int 
netio_send(int s, const char *data, int datalen)
{
        /* nio */
        int ret = -1;
	netio_sock_t *e = NULL;		
	void *ptr = 0;

	ship_lock(netio_sock_list);
	while (!e && (e = ship_list_next(netio_sock_list, &ptr))) {
		if (e->s != s || e->type != NETIO_SOCK_WRITE)
			e = 0;
	}
	
	if (!e) {
		struct sockaddr *addr = 0;
		socklen_t addrlen = 0;
		
		/* check the status of this connection (slow..) */
		if (!getpeername(s, addr, &addrlen)) {
			if ((e = netio_sock_new(NETIO_SOCK_WRITE, 0, 0)))
				netio_sock_add(e);
			e->s = s;
		}
	} else
		write(netio_l_pipe[1], "0", 1);
	
	if (e)
		ship_lock(e->send_queue);

	ship_unlock(netio_sock_list);

	if (!e)
		return -1;
	
	void **arr = mallocz(sizeof(void*) * 3);
	if ((arr[0] = mallocz(sizeof(int))) &&
	    (arr[1] = (void*)malloc(datalen)) &&
	    (arr[2] = mallocz(sizeof(int)))) {
		
		/* put the socket on the send-list */
		memcpy(arr[0], &datalen, sizeof(int));
		memcpy(arr[1], data, datalen);
		bzero(arr[2], sizeof(int));
		
		ship_list_add(e->send_queue, arr);
		ret = datalen;
	}
	ship_unlock(e->send_queue);
	return ret;
#if 0
	struct sockaddr *addr = 0;
	socklen_t addrlen = 0;

	/* check the status of this connection (slow..) */
	if (getpeername(s, addr, &addrlen))
		return -1;
	
        return write(s, data, datalen);
#endif
}

int 
netio_packet_send(int s, char *data, int datalen, struct sockaddr* sa, socklen_t salen)
{
        /* todo: nio */
        int ret = 0;
        ret = sendto(s, data, datalen, 0, sa, salen);
        return ret;
}


static int
netio_get_generic_packet_socket(struct sockaddr *sa, int cache)
{
	int s = -1;
	struct sockaddr *bsin = 0;

	/* sync this? */
	switch (sa->sa_family) {
	case AF_INET:
		if (!cache || generic_ipv4_socket == -1) {
			s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
			MAKE_NONBLOCK(s);
			if (cache)
				generic_ipv4_socket = s;
		} else
			s = generic_ipv4_socket;
		break;
	case AF_INET6:
		if (!cache || generic_ipv6_socket == -1) {
			s = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
			ASSERT_TRUE(s != -1, err);
			
			/* get hit & bind the socket to that .. */
			/* 2.1.2008 jk: commented this out as sento
			   blocked if the socket was bound to a
			   hit :( */
#ifdef CONFIG_HIP_ENABLED	
#ifdef BIND_HIP_TO_DEFAULT_HIT
			/* bind only the non-cached sockets to hit */
			if (!cache) {
				socklen_t bsin_len = 0;
				addr_t addr;
				struct sockaddr_in6 *sin = (struct sockaddr_in6 *)sa;
				ident_addr_in6_to_addr(&sin->sin6_addr, &addr);
				if (hipapi_addr_is_hit(&addr)) {
					ASSERT_ZERO(hipapi_gethit(&addr), err);
					ASSERT_ZERO(ident_addr_addr_to_sa(&addr, &bsin, &bsin_len), err);
					ASSERT_ZERO(bind(s, bsin, bsin_len), err);
				}
			}
#endif
#endif
			MAKE_NONBLOCK(s);
			/* set timeout */
			//SET_SOCK_SENDTO(generic_ipv6_socket, 2); /* 2 seconds */
			
			if (cache)
				generic_ipv6_socket = s;
		} else
			s = generic_ipv6_socket;
		break;
	}
	
 err:
	freez(bsin);
	return s;
}

int 
netio_packet_anon_send(char *data, int datalen, struct sockaddr* sa, socklen_t salen)
{
        /* todo: nio */
	int s = -1, ret = -1;
	struct sockaddr *sin = 0;
	
	s = netio_get_generic_packet_socket(sa, 1);
        if (s == -1)
                return -1;

	/* this blocks sometimes (when bound to hit (or not?) .. */
	ret = sendto(s, data, datalen, 0, sa, salen);
 
	freez(sin);
	return ret;
}

int 
netio_read(int s, void (*callback) (int s, char *data, ssize_t datalen))
{
        netio_sock_t *e = NULL;

        MAKE_NONBLOCK(s);
        
        /* make entry */
        ASSERT_TRUE(e = netio_sock_new(NETIO_SOCK_READ, NULL, 0), err);
        e->s = s;
        e->read_callback = callback;
        netio_sock_add(e);
        return 0;

 err:
        netio_sock_free(e);
        return -1;
}


#define NETIO_MAX_RECV_SIZE (1024*64)

/* sender / receiver loop for the ship server. this is where the ship
   server sends and receives data packets from other ship proxies */
static void *
netio_loop(void *data)
{
        int retval;
        struct sockaddr *sa = NULL;
        socklen_t addrlen = 0;
	ship_list_t *nl = ship_list_new();
	fd_set *fd_read, *fd_ex, *fd_write;

	fd_read = mallocz(sizeof(fd_set));
	fd_ex = mallocz(sizeof(fd_set));
	fd_write = mallocz(sizeof(fd_set));
	if (!fd_read || !fd_write || !fd_ex)
		PANIC("could not allocate fd sets\n");

        LOG_INFO("the nio loop has started\n");
        while (nl && netio_alive) {
                /* the read / write fd_set */
                int max;
                char buf[NETIO_MAX_RECV_SIZE+1];
                ssize_t r;
                void *ptr;
		netio_sock_t *e = 0;

                FD_ZERO(fd_read);
                FD_ZERO(fd_write);
                FD_ZERO(fd_ex);
                
                FD_SET(netio_l_pipe[0], fd_read);
                max = netio_l_pipe[0]+1;

                ship_lock(netio_sock_list);
		ptr = 0;
		while ((e = ship_list_next(netio_sock_list, &ptr))) {
			if (!e->active || e->remove)
				continue;

			switch (e->type) {
			case NETIO_SOCK_READ:
				FD_SET(e->s, fd_read);
				break;
			case NETIO_SOCK_WRITE:
				ship_lock(e->send_queue);
				if (ship_list_first(e->send_queue)) {
					FD_SET(e->s, fd_write);
					ship_unlock(e->send_queue);
				} else if (e->flush) {
					e->remove = 1;
					shutdown(e->s, SHUT_RDWR);
					close(e->s);
					ship_unlock(e->send_queue);
					e = 0;
				} else {
					ship_unlock(e->send_queue);
					e = 0;
				}
				break;
			case NETIO_SOCK_ACCEPT:
				FD_SET(e->s, fd_read);
				break;
			case NETIO_SOCK_CONNTO:
				FD_SET(e->s, fd_write);
				break;
			case NETIO_SOCK_PACKET_READ:
				FD_SET(e->s, fd_read); 
				break;
			default:
				break;
			}
				
			if (e && e->s+1 > max)
				max = e->s+1;
		}
		ship_unlock(netio_sock_list);
		
                retval = select(max, fd_read, fd_write, fd_ex, NULL);
		if (retval == -1) {
			LOG_WARN("got nio error: %d, %s\n", errno, strerror(errno));
			/*
			ship_lock(netio_sock_list);
			ptr = 0; last = 0;
			while (e = ship_list_next(netio_sock_list, &ptr)) {
				struct sockaddr *addr = 0;
				socklen_t addrlen = 0;
				
				if (!e->active || e->remove)
					continue;

				if (getpeername(e->s, addr, &addrlen))
					LOG_HL("STUFF. NOT OK! %d\n", e->s);

				switch (e->type) {
				case NETIO_SOCK_READ:
					LOG_WARN("had %d for read, closing %d, %08x\n", e->s, e->closing, e);
					break;
				case NETIO_SOCK_WRITE:
					ship_lock(e->send_queue);
					if (ship_list_first(e->send_queue))
						LOG_WARN("had %d for write, closing %d, %08x\n", e->s, e->closing, e);
					ship_unlock(e->send_queue);
					break;
				case NETIO_SOCK_ACCEPT:
					LOG_WARN("had %d for accept, closing %d, %08x\n", e->s, e->closing, e);
					break;
				case NETIO_SOCK_CONNTO:
					LOG_WARN("had %d for connto, closing %d, %08x\n", e->s, e->closing, e);
					break;
				case NETIO_SOCK_PACKET_READ:
					LOG_WARN("had %d for packet read, closing %d, %08x\n", e->s, e->closing, e);
					break;
				}

			}

			ship_unlock(netio_sock_list);
			// segfault
			raise(SIGSEGV);
			*/
		}

                if (retval > 0) {
                        void *ptr = NULL, *d = 0;
                        netio_sock_t *e = NULL;

                        if (FD_ISSET(netio_l_pipe[0], fd_read)) {
                                r = read(netio_l_pipe[0], buf, NETIO_MAX_RECV_SIZE);
                                retval--;
                        }
                        
                        /* loop through all unsynched, check which are selected */
                        ship_lock(netio_sock_list); {                                
                                while ((d = ship_list_next(netio_sock_list, &ptr))) {
					ship_list_add(nl, d);
                                }
                        }
			ship_unlock(netio_sock_list);

                        while ((e = ship_list_pop(nl))) {
                                switch (e->type) {
                                case NETIO_SOCK_READ:
                                        if (FD_ISSET(e->s, fd_read)) {
                                                r = read(e->s, buf, NETIO_MAX_RECV_SIZE);
                                                if (r > -1)
                                                        buf[r] = 0;
                                                if (e->read_callback) {
							/* todo: make the worker threads do this */
							e->read_callback(e->s, buf, r);
							ship_check_restricts();
						}
                                                retval--;
                                        }
                                        break;
                                case NETIO_SOCK_WRITE:
                                        if (FD_ISSET(e->s, fd_write)) {
                                                void **arr = 0;
						ship_lock(e->send_queue);
						if ((arr = ship_list_first(e->send_queue))) {
							int *datalen = arr[0];
							int *datastart = arr[2];
							char *data = arr[1];
							
							struct sockaddr *addr = 0;
							socklen_t addrlen = 0;
							
							/* check the status of this connection (slow..) */
							if (!getpeername(e->s, addr, &addrlen)) {
								int w = write(e->s, data+(*datastart), (*datalen) - (*datastart));
								if (w > 0 && (w < ((*datalen) - (*datastart)))) {
									/* send again! */
									(*datastart) += w;									
									datastart = 0;
								}
							}
							
							if (datastart) {
								ship_list_pop(e->send_queue);
								free(arr[0]);
								free(arr[1]);
								free(arr[2]);
								free(arr);
							}
						} else if (e->flush) {
							netio_close_socket(e->s);
						}
						ship_unlock(e->send_queue);
                                                retval--;
                                        }
                                        break;
                                case NETIO_SOCK_ACCEPT:                                        
                                        if (FD_ISSET(e->s, fd_read)) {
                                                int s;
                                                addrlen = e->addrlen+10;
						sa = (struct sockaddr*)mallocz(addrlen);
                                                if (sa) {
							s = accept(e->s, sa, &addrlen);
							MAKE_TCP_NODELAY(s);
							if (e->accept_callback) {
								/* todo: make the worker threads do this! */
								e->accept_callback(s, sa, addrlen, e->s);
								ship_check_restricts();
							}
							freez(sa);
						}
                                                retval--;
                                        }
                                        
                                        FD_SET(e->s, fd_read);
                                        break;
                                case NETIO_SOCK_CONNTO:                                        
                                        if (FD_ISSET(e->s, fd_write)) {
						netio_remove_read(e->s);
						
						if (e->connto_callback) {
							/* todo: make the worker threads do this! */
							e->connto_callback(e->s, e->sa, e->addrlen);
						} else {
							LOG_WARN("No callback defined for connto\n");
						}
                                        }
                                        break;
                                case NETIO_SOCK_PACKET_READ:
					/* this sometimes crashes (segfault).. dunno why */
                                        if (FD_ISSET(e->s, fd_read)) {
                                                addrlen = e->addrlen;    
                                                
						sa = (struct sockaddr*)mallocz(addrlen);
                                                if (sa) {
							r = recvfrom(e->s, buf, NETIO_MAX_RECV_SIZE, 0,
								     sa, &addrlen);
							if (r > -1)
								buf[r] = 0;
							if (e->packet_read_callback) {
								/* todo: for the worker threads! */
								e->packet_read_callback(e->s, buf, r, sa, addrlen);
							}
							ship_check_restricts();
							retval--;
							freez(sa);
						}
                                        }
                                        break;
                                default:
                                        break;
                                }
                        }
                }   

                ship_lock(netio_sock_list); {
                        netio_sock_t *e = 0;
                        void *ptr = 0, *last = 0;
			
                        while ((e = (netio_sock_t *)ship_list_next(netio_sock_list, &ptr))) {
				if (e->remove) {
					ship_list_remove(netio_sock_list, e);
					netio_sock_free(e);
					ptr = last;
				}
				last = ptr;
                        }

                } ship_unlock(netio_sock_list);
        }
        
	freez(fd_read);
	freez(fd_write);
	freez(fd_ex);
	ship_list_free(nl);
        LOG_INFO("the nio loop ends\n");
	return NULL;
}


/* the netio register */
static struct processor_module_s processor_module = 
{
	.init = netio_init,
	.close = netio_close,
	.name = "netio",
	.depends = "",
};

/* register func */
void
netio_register() {
	processor_register(&processor_module);
}


/**************************************/
/**************************************/
/****          netio ff            ****/
/**************************************/
/**************************************/

static int netio_ff_update = 0;
#define NETIO_FF_MAX_RECV_SIZE (1024*64)
static ship_list_t *netio_ff_entries = 0;
static int netio_ff_alive = 0;

static void *netio_ff_loop(void *data);

/* whether to use anon or dedicated socket for sending ff */
/* the dedik mode tilts the whole device .. ::( */
#define FF_ANON 1
//#define FF_DEDIK_ANON 1

/* whether to buffer the output also. this isn't really needed.. */
//#define BUFFER_OUTPUT 1


/* some struct for holding info related to the mp's */
typedef struct netio_ff_s {
	int r_sock;
	int w_sock;

	/* add stats etc.. */
	int *counter;
	
	/* remove-flag */
	int remove;

	/* whether to fragment the output */
	int fragment_output;
	
	/* whether to re-assemble the input */
	int defragment_input;

#if FF_ANON || FF_DEDIK_ANON
	struct sockaddr *sa;
	socklen_t size;
#endif

#ifdef BUFFER_OUTPUT
	ship_list_t *output;
#endif

	/* input fragmentation buffer */
	ship_list_t *input;


} netio_ff_t;

static inline int netio_ff_send(netio_ff_t *e, char *buf, int len);


/* closes one entry */
static void
netio_ff_close_entry(netio_ff_t *ff)
{
	void **outs;

	close(ff->r_sock);
#if FF_ANON || FF_DEDIK_ANON
	freez(ff->sa);
#endif
#ifndef FF_DEDIK_ANON
	close(ff->w_sock);
#endif

	while ((outs = ship_list_pop(ff->input))) {
		freez(outs[1]);
		freez(outs[2]);
		freez(outs);
	}
	ship_list_free(ff->input);
	
#ifdef BUFFER_OUTPUT
	while (outs = ship_list_pop(ff->output)) {
		freez(outs[1]);
		freez(outs[2]);
		freez(outs);
	}
	ship_list_free(ff->output);
#endif
	freez(ff);
}

/* inits the ff system */
int
netio_ff_init()
{
	int ret = -1;
	
	ASSERT_TRUE(netio_ff_entries = ship_list_new(), err);
        if (pipe(netio_ff_l_pipe))
                goto err;
        MAKE_NONBLOCK(netio_ff_l_pipe[0]);
        MAKE_NONBLOCK(netio_ff_l_pipe[1]);

        /* start the thread */
	netio_ff_alive = 1;
        if ((THREAD_INIT(netio_ff_thread)) == 0 ||
            (THREAD_RUN(netio_ff_thread, netio_ff_loop, NULL)) != 0) {
                freez(netio_ff_thread);
                goto err;
        }
	
	ret = 0;
 err:
	return ret;
}

/* closes the ff system */
void
netio_ff_close()
{
	netio_ff_alive = 0;
	write(netio_ff_l_pipe[1], "0", 1);

	/* free the entries */
	if (netio_ff_entries) {
		netio_ff_t *ff = 0;
		ship_lock(netio_ff_entries); {
			while ((ff = ship_list_pop(netio_ff_entries)))
				netio_ff_close_entry(ff);
		} ship_unlock(netio_ff_entries);
		ship_list_free(netio_ff_entries);
	}
	
	if (netio_ff_thread) {
                THREAD_JOIN(netio_ff_thread);
		THREAD_FREE(netio_ff_thread);
	}
}

/* adds a fast-forwarding socket. udp / tcp */
int
netio_ff_add(int rec_socket, addr_t *addr, int *counter, int fragment_output)
{
	netio_ff_t *ff = 0;
	int send_socket = -1;
	struct sockaddr *sa = 0;
	socklen_t size = 0;
	int ret = -1;
	
	/* create new socket */
	if (ident_addr_addr_to_sa(addr, &sa, &size))
		goto err;
	
#if FF_ANON
	send_socket = netio_get_generic_packet_socket(sa, 0);
#elif FF_DEDIK_ANON
	send_socket = netio_get_generic_packet_socket(sa, 1);
#else
	send_socket = netio_packet_connto(sa, size);
#endif
	if (send_socket == -1)
		goto err;
	
	/* create a new entry, add to the list. mark as we need to
	   update now */
	if ((ff = mallocz(sizeof(netio_ff_t)))) {
#ifdef BUFFER_OUTPUT
		ASSERT_TRUE(ff->output = ship_list_new(), err);
#endif
		ASSERT_TRUE(ff->input = ship_list_new(), err);
		ff->fragment_output = fragment_output;
		ff->r_sock = rec_socket;
		ff->w_sock = send_socket;
		ff->counter = counter;
#if FF_ANON || FF_DEDIK_ANON
		ff->sa = sa;
		ff->size = size;
		sa = 0;
#endif
		/* send the magic IF this is fragmentable .. */
		if (ff->fragment_output) {
			ff->fragment_output = 0;
			netio_ff_send(ff, FRAGMENT_MAGIC_PACKET, FRAGMENT_MAGIC_PACKET_LEN);
			ff->fragment_output = 1;
		}
		
		ship_lock(netio_ff_entries);		
		ship_list_add(netio_ff_entries, ff);
		netio_ff_update = 1;
		write(netio_ff_l_pipe[1], "0", 1);
		ship_unlock(netio_ff_entries);

		ret = 0;
		send_socket = -1;
		ff = 0;
	}
 err:
	freez(ff);
	freez(sa);
	if (send_socket != -1)
		close(send_socket);
	return ret;
}

/* removes a fast-forwarding socket. udp / tcp.
 * closes the receiving socket! */
void
netio_ff_remove(int rec_socket)
{
	netio_ff_t *ff = 0;
	void *ptr = 0;
	
	ship_lock(netio_ff_entries);
	
	/* mark this only for removal */
	while ((ff = ship_list_next(netio_ff_entries, &ptr))) {
		if (ff->r_sock == rec_socket)
			ff->remove = 1;
	}
	netio_ff_update = 1;
	write(netio_ff_l_pipe[1], "0", 1);
	
	ship_unlock(netio_ff_entries);
}

static inline int
netio_ff_send(netio_ff_t *e, char *buf, int len)
{
	int sval = 0, ret = -1, frag = 1;
	int lim = 1024;
	
	if (!len)
		return 0;

	if (e->fragment_output && len > lim) {
		frag = (len / lim) + ((len % lim)? 1:0);
	} else
		lim = len;
	
	do {
		int slen = lim;
		int bss = len - lim;
		if (bss < 0) {
			slen = len;
			bss = 0;
		}
		frag--;
		
		/* we should always have a little space to spare at
		   the end of the data buffer! */
		if (e->fragment_output) {
			/* this destroys the next fragment, but doesn't
			   matter as we've already sent it! */
			buf[len] = 'f';
			buf[len+1] = (char)frag;
			slen += 2;
		}
		
#if FF_ANON || FF_DEDIK_ANON
		ret = sendto(e->w_sock, buf+bss, slen, 0, 
			     e->sa, e->size);
#else					
		ret = send(e->w_sock, buf+bss, slen, 0);
#endif

		if (e->fragment_output)
			slen -= 2;

		if (ret < 0)
			sval = -1;
		else
			sval += ret;
		
		len -= slen;
	} while (sval > -1 && frag);
	
	return sval;
}

/* the netio fastforward select loop */
static void *
netio_ff_loop(void *data)
{
	netio_ff_t **sockarr = 0;
	fd_set fd_read, fd_read_cp;
#ifdef BUFFER_OUTPUT
	fd_set fd_write, fd_write_cp;
#endif
	int max = 0;
	char *buf = 0;
		
	/* make the buffer a bit bigger so we can store fragments there .. */
	netio_ff_update = 1;
	if (!(buf = mallocz(NETIO_FF_MAX_RECV_SIZE+10)))
		return NULL;
	
        LOG_INFO("the nio FF loop has started\n");
        while (netio_ff_alive) {
		int retval, i;

		/* update the lists of sockets to process */
		if (netio_ff_update) {
			void *ptr = 0, *last = 0;
			netio_ff_t *ff = 0;

			ship_lock(netio_ff_entries); /* this crashes sometimes .. */
			LOG_DEBUG("Modifying the FF nio select..\n");

			/* remove those that need removing */
			while ((ff = ship_list_next(netio_ff_entries, &ptr))) {
				if (ff->remove) {
					ship_list_remove(netio_ff_entries, ff);
					netio_ff_close_entry(ff);
					ptr = last;
				} else
					last = ptr;
			}

			FD_ZERO(&fd_read);
			FD_SET(netio_ff_l_pipe[0], &fd_read);
			max = netio_ff_l_pipe[0]+1;
			
#ifdef BUFFER_OUTPUT
			FD_ZERO(&fd_write);
#endif

			freez(sockarr);
			sockarr = mallocz((ship_list_length(netio_ff_entries) + 1) * sizeof(netio_ff_t*));
			
			/* for i in each, loop throgh & add to the array */
			i = 0;
			ptr = 0;
			while ((sockarr[i] = ship_list_next(netio_ff_entries, &ptr))) {
				FD_SET(sockarr[i]->r_sock, &fd_read);
				if (sockarr[i]->r_sock+1 > max)
					max = sockarr[i]->r_sock+1;

#ifdef BUFFER_OUTPUT
				if (ship_list_first(sockarr[i]->output)) {
					FD_SET(sockarr[i]->w_sock, &fd_write);
					if (sockarr[i]->w_sock+1 > max)
						max = sockarr[i]->w_sock+1;
				}
#endif
				i++;
			}
			netio_ff_update = 0;
			ship_unlock(netio_ff_entries);
		}
#ifdef BUFFER_OUTPUT
		memcpy(&fd_read_cp, &fd_read, sizeof(fd_read));
		memcpy(&fd_write_cp, &fd_write, sizeof(fd_write));
                retval = select(max, &fd_read_cp, &fd_write_cp, NULL, NULL);
#else
		memcpy(&fd_read_cp, &fd_read, sizeof(fd_read));
                retval = select(max, &fd_read_cp, NULL, NULL, NULL);
#endif
                if (retval > 0) {
			int spos = 0, r = 0;
                        if (FD_ISSET(netio_ff_l_pipe[0], &fd_read_cp)) {
                                r = read(netio_ff_l_pipe[0], buf, NETIO_FF_MAX_RECV_SIZE);
				retval--;
                        }
                        
			/* loop through the list of sockets, if set then forward */
			while (retval > 0 && sockarr[spos]) {
				netio_ff_t *ff = sockarr[spos];
				if (FD_ISSET(ff->r_sock, &fd_read_cp)) {
					r = recv(ff->r_sock, buf, NETIO_FF_MAX_RECV_SIZE, 0);
					if (r < 0) {
						netio_ff_remove(ff->r_sock);
					} else {
						int sval = -1;
						
						/* check for fragmentation */
						if (r == FRAGMENT_MAGIC_PACKET_LEN &&
						    !memcmp(FRAGMENT_MAGIC_PACKET, buf, FRAGMENT_MAGIC_PACKET_LEN)) {
							ff->defragment_input = 1;
							
							/* should we send this packet or not ?? */
							r = 0;
						}
						
						/* check for fragmented packets! */
						if (ff->defragment_input && 
						    r > 1 && (buf[r-2] == 'f')) {
							void **outs = 0;
							r -= 2; /* remove two last bytes! */
							
							/* if last packet and no queued ones, do nothing, otherwise.. */
							if (!buf[r+1]) {
								if (ship_list_first(ff->input)) {
									/* combine into one */
									while ((outs = ship_list_pop(ff->input))) {
										int len = (*((int*)outs[0]));
										if ((len + r) < NETIO_FF_MAX_RECV_SIZE) {
											memcpy(buf+r, outs[1], len);
											r += len;
										}
										freez(outs[0]);
										freez(outs[1]);
										freez(outs);
									}
								}
							} else if (buf[r+1] < 33) {
								/* 'tis a fragment - store it. */
								outs = malloc(2*sizeof(void*));
								if (outs) {
									outs[0] = malloc(sizeof(int));
									outs[1] = malloc(r+10);
									if (outs[0] && outs[1]) {
										*((int*)outs[0]) = r;
										memcpy(outs[1], buf, r);
										/* todo: the fragments may come in wrong order, 
										   but we don't mind for now .. */
										ship_list_push(ff->input, outs);
										r = 0;
									} else {
										freez(outs[0]);
										freez(outs[1]);
										freez(outs);
									}
								}
							}
						}
						
#ifdef BUFFER_OUTPUT
						/* if something is already on the list or the sending fails, 
						   use the buffer */
						if (r && !ship_list_first(ff->output)) {
#endif
							sval = netio_ff_send(ff, buf, r);
#ifdef BUFFER_OUTPUT
						}
#endif
						if (r && sval < 0) {
#ifdef BUFFER_OUTPUT
							void **outs = malloc(2*sizeof(void*));
							if (outs) {
								outs[0] = malloc(sizeof(int));
								outs[1] = malloc(r);
								if (outs[0] && outs[1]) {
									*((int*)outs[0]) = r;
									memcpy(outs[1], buf, r);
									if (!ship_list_first(ff->output))
										netio_ff_update = 1;
									ship_list_add(ff->output, outs);
								} else {
									freez(outs[0]);
									freez(outs[1]);
									freez(outs);
								}
							}
							
#else
							/* ..these might occur for odd reasons .. */
							//LOG_WARN("Error sending FF %d bytes (%d)!\n", r, sval);
#endif
						} else if (ff->counter)
							*(ff->counter) += r;
					}
					retval--;
				}
#ifdef BUFFER_OUTPUT
				if (FD_ISSET(ff->w_sock, &fd_write_cp)) {
					/* send some data.. */
					void **outs = ship_list_first(ff->output);
					if (outs) {
						int sval = -1;
						int len = (*((int*)outs[0]));
						LOG_DEBUG("sending buffered data..\n");
						sval = netio_ff_send(ff, buf, len);
						if (sval != len) {
							//LOG_WARN("darn, buffered didn't go well: %d / %d\n", sval, len);
						}
						/* don't care about the return code anymore.. */
						//else {
						ship_list_pop(ff->output);
						freez(outs[0]);
						freez(outs[1]);
						freez(outs);
						//}
					}
					if (!ship_list_first(ff->output))
						netio_ff_update = 1;
					retval--;
				}
#endif
				spos++;
			}
		}   
        }
	freez(sockarr);
	freez(buf);
        LOG_INFO("the nio FF loop ends\n");
	return NULL;
}


/* the netio register */
static struct processor_module_s processor_module_ff = 
{
	.init = netio_ff_init,
	.close = netio_ff_close,
	.name = "netio_ff",
	.depends = "netio",
};

/* register func */
void
netio_ff_register() {
	processor_register(&processor_module_ff);
}
