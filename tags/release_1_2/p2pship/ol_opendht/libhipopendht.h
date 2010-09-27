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
#ifndef lib_opendht
#define lib_opendht

#include "ship_utils.h"

/* Resolve the gateway address using opendht.nyuld.net */
#define OPENDHT_PORT 5851
#define OPENDHT_TTL 120

#define STATE_OPENDHT_IDLE 0
#define STATE_OPENDHT_WAITING_ANSWER 1
#define STATE_OPENDHT_WAITING_CONNECT 2
#define STATE_OPENDHT_START_SEND 3

int opendht_put(unsigned char * key,
                unsigned char * value,
		char *secret,
                int opendht_ttl,
                void (*callback) (char *key, char *value, void *param, int status),
		void *param,
		void (*part_callback) (char *key, char *value, void *param, int status));
int opendht_get(unsigned char * key,
                void (*callback) (char *key, char *value, void *param, int status),
		void *param);
void opendht_close();
int opendht_init(char* addr, void (*callback) (char *gateway, int port, int status));
int opendht_rm(char *key,
	       char *hash,
	       char *secret);

int read_packet_content2(char * in_buffer, char *** out_value);
int build_packet_put_rm(unsigned char * key, 
			int key_len,
			unsigned char * value,
			int value_len, 
			unsigned char *secret,
			int secret_len,
			int port,
			unsigned char * host_ip,
			char * out_buffer,
			int ttl);
int build_packet_rm(unsigned char * key, 
                    int key_len,
                    unsigned char * hash,
                    unsigned char * secret,
                    int secret_len,
                    int port,
                    unsigned char * host_ip,
                    char * out_buffer,
                    int ttl);

#define OPENDHT_TASK_NONE 0
#define OPENDHT_TASK_PUT 1
#define OPENDHT_TASK_GET 2
#define OPENDHT_TASK_SUBGET 3
#define OPENDHT_TASK_SUBSUBGET 4
#define OPENDHT_TASK_PUT_PART 5
#define OPENDHT_TASK_RM 6

typedef struct opendht_task_s opendht_task_t;

struct opendht_task_s 
{
        int type;
        void (*callback) (char *key, char *data, void *param, int status);
 
	int socket;
	int status;

        char *key;
        char *value;
	char *secret;
	int value_len;
        int timeout;

	char *read_buf;
	int read_buf_size;
	int read_buf_read;

	void *param;
	opendht_task_t *parent;
	int closed;
	ship_list_t *subs;

};

#endif /* lib_opendht */
