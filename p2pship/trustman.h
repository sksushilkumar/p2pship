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
#ifndef __TRUSTMAN_H__
#define __TRUSTMAN_H__

#include "ship_utils.h"
#include "processor_config.h"
#include "ident.h"

/* This represents all we know about a relationship with another person */
typedef struct trustparams_s {

	ship_list_t *queued_packets;

	/* from.. to */
	char *from_aor;
	char *to_aor;

	/*
	 * these are all pathfinder-related stuff
	 */

	/* the params blob */
	char *params;
	int params_len;

	/* sending - related flags */
	int current_sent;
	int send_flag;
	int requesting;

	/* when these expire! */
	time_t expires;
#ifdef CONFIG_OP_ENABLED
	/*
	 * these are the op ident things
	 */
	time_t op_expires;
	char *op_cert;
	int op_send;
#endif
} trustparams_t;

/* these are the ones we get from someone else.. */
typedef struct trustparams_remote_s 
{
	ship_lock_t lock;

	/* from.. to */
	char *from_aor;
	char *to_aor;

	/*
	 * these are all pathfinder-related stuff
	 */

	/* the pathfinder info */
	int pathfinder_len;

	/* when these expire! */
	time_t expires;

#ifdef CONFIG_OP_ENABLED
	/*
	 * these are the op ident things
	 */
	time_t op_expires;
	char *op_identity;
	char *op_key;
#endif
} trustparams_remote_t;

/* returns the address of the pathfinder */
char *trustman_get_pathfinder();
char *trustman_op_get_verification_key(char *from_aor, char *to_aor);
int trustman_get_pathlen(char *from_aor, char *to_aor);

void trustman_close();
int trustman_init(processor_config_t *config);

int trustman_mark_current_trust_sent(char *from_aor, char *to_aor);
int trustman_mark_send_trust_to(ident_t *ident, char *to_aor);

int trustman_check_trustparams(char *from_aor, char *to_aor, int (*func) (char *from_aor, char *to_aor, 
									  char *params, int param_len,
									  void *data), 
			       void *data);
#endif
