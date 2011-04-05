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
#ifndef __ACCESS_CONTROL_H__
#define __ACCESS_CONTROL_H__

#include <osipparser2/osip_message.h>
#include <osip2/osip.h>
#include <osipparser2/sdp_message.h>
#include "ship_utils.h"
#include "processor_config.h"
#include "sipp.h"

/* the verdicts */
#define AC_VERDICT_NONE 0
#define AC_VERDICT_ALLOW 1
#define AC_VERDICT_REJECT 2
#define AC_VERDICT_DROP 3
#define AC_VERDICT_IGNORE 4
#define AC_VERDICT_UNSUPP 5

/* struct for holding the sipp message info */
typedef struct ac_sip_s {
	void *pkg;

	osip_event_t *evt;
	
	char *local;
	char *remote;

	char *from;
	char *to;

	int verdict;
	
	void (*cb_func) (char *local_aor, char *remote_aor, void *msg, int verdict);
	
	/* the list of packet filters which this should go through */
	ship_list_t *filters;

	/* whether this was remotely got */
	int remotely_got;
} ac_sip_t;

ship_ht_t *ac_lists_whitelist();
ship_ht_t *ac_lists_blacklist();

#ifdef DO_STATS
int ac_send_stats(char *remote, char *local,
		  unsigned long time, char *callid, char *event);
void ac_packetfilter_stats_event(char *local_aor, char *remote_aor, char *event);
void stats_dump_json(char **str);
#else
#define ac_send_stats(remote, local, time, callid, event) 1
#endif

void ac_lists_save();
int ac_packetfilter_local(sipp_request_t *req, 
			  void (*func) (char *local_aor, char *remote_aor, void *msg, int verdict),
			  const int filter);
int ac_packetfilter_remote(char *local_aor, char *remote_aor, osip_event_t *evt, 
			   void (*func) (char *local_aor, char *remote_aor, void *msg, int verdict),
			   const int filter);
int ac_init(processor_config_t *config);
void ac_close();

#endif
