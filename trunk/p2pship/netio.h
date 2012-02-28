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
#ifndef __NETIO_H__
#define __NETIO_H__

#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include "ship_utils.h"
#include "processor_config.h"
#include <netinet/tcp.h>
#include "ident_addr.h"

enum {
        NETIO_SOCK_UNKNOWN = 0,
        NETIO_SOCK_READ,
        NETIO_SOCK_WRITE, 
        NETIO_SOCK_ACCEPT,
        NETIO_SOCK_CONNTO,
        NETIO_SOCK_PACKET_READ,
};
        
//ioctl(fd, FIOSNBIO, option);
#define MAKE_NONBLOCK(fd)  \
{\
        int flags;\
        flags = fcntl(fd, F_GETFL, 0);\
        fcntl(fd, F_SETFL, flags | O_NONBLOCK); \
}

#define MAKE_TCP_NODELAY(fd)  \
{\
	int on = 1;\
	setsockopt(fd, SOL_TCP, TCP_NODELAY, &on, sizeof(on));\
}

typedef struct netio_sock_s
{
        int type;
        int s;
        int active;
	int flush;
	int remove;
	time_t last_heard;

        struct sockaddr *sa;
        socklen_t addrlen;

        void (*read_callback) (int s, char *data, ssize_t len);
        void (*write_callback) (int s, char *data, int len, int code);
        void (*accept_callback) (int s, struct sockaddr *sa, socklen_t addrlen, int ss);
        void (*connto_callback) (int s, struct sockaddr *sa, socklen_t addrlen);
        void (*packet_read_callback) (int s, char *data, size_t len, struct sockaddr *sa, socklen_t addrlen);

        /* if sending, this is our list of buffers */
        ship_list_t *send_queue;

} netio_sock_t;


int netio_init(processor_config_t *config);
void netio_register();
void netio_ff_register();
void netio_man_register();
void *netio_man_close_socket(int socket);
int netio_man_connto(struct sockaddr *sa, socklen_t sa_len,
		     void *conn_obj,
		     void (*conn_cb) (int s, void *obj),
		     void (*data_cb) (int s, void *obj, char *data, int datalen));

int netio_socket(int namespace, int style, int protocol);
void netio_close_socket(int s);
int netio_ff_add(int rec_socket, addr_t *addr, int *counter, int fragment_output);
void netio_ff_remove(int rec_socket);
int netio_packet_anon_send(char *data, int datalen, struct sockaddr* sa, socklen_t salen);

void netio_close();
int netio_new_listener(struct sockaddr *sa, socklen_t size, void (*callback) (int s, struct sockaddr *sa, socklen_t addrlen, int ss));
int netio_send(int s, const char *data, int datalen);
int netio_packet_send(int s, char *data, int datalen, struct sockaddr *sa, socklen_t size);
int netio_packet_anon_send(char *data, int datalen, struct sockaddr* sa, socklen_t salen);
int netio_read(int s, void (*callback) (int s, char *data, ssize_t datalen));
int netio_packet_read(int s,
		      void (*callback) (int s, char *data, size_t len,
					struct sockaddr *sa, socklen_t addrlen));

int netio_new_unix_socket(char *unix_socket, mode_t mode,
			  void (*callback) (int, struct sockaddr *, socklen_t, int));

int netio_connto(struct sockaddr *sa, socklen_t size, void (*callback) (int s, struct sockaddr *sa, socklen_t addrlen));

int netio_remove_read(int s);
void netio_close_socket(int s);
void netio_set_active(int socket, int active);

int netio_new_packet_socket(struct sockaddr *sa, socklen_t size);

int netio_new_packet_reader(struct sockaddr *sa, socklen_t size, 
			    void (*callback) (int s, char *data, size_t len,
					      struct sockaddr *sa, socklen_t addrlen));
int netio_new_multicast_reader(char *mc_addr, 
			       struct sockaddr *sa, socklen_t size,			   
			       void (*callback) (int s, char *data, size_t len,
						 struct sockaddr *sa, socklen_t addrlen));
     
#endif

