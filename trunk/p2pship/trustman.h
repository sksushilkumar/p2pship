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

/* This represents all we know about a relationship with another person */
typedef struct trustparams_s {

	ship_list_t *queued_packets;

	/* from.. to */
	char *from_aor;
	char *to_aor;

	/* the params blob */
	char *params;
	int params_len;

	/* the pathfinder info */
	int pathfinder_len;

	/* sending - related flags */
	int current_sent;
	int send_flag;
	int requesting;

	/* when these expire! */
	time_t expires;
} trustparams_t;

static trustparams_t *trustman_get_trustparams(char *from_aor, char *to_aor);
trustparams_t *trustman_get_valid_trustparams(char *from_aor, char *to_aor);
trustparams_t *trustman_get_create_trustparams(char *from_aor, char *to_aor);

/* returns the address of the pathfinder */
char *trustman_get_pathfinder();

#endif
