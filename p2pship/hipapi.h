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
/*
 * Module / api for all hip-related functionality
 */
#ifndef __HIPAPI_H__
#define __HIPAPI_H__ 

#include "processor_config.h"
#include "processor.h"
#include "ship_utils.h"
#include "ident.h"
#include "ident_addr.h"

/* from hipl, it is painful to include hipconf.h */
int hip_do_hipconf(int argc, char *argv[], int send_only);
void getaddrinfo_disable_hit_lookup();

/* inits the hipapi */
int hipapi_init(processor_config_t *config);
void hipapi_register();

/* closes */
void hipapi_close();

/* retrieves my own HITs */
int hipapi_gethits(ship_list_t *list);


/* prototypes for external stuff */
struct hip_tlv_common;
struct hip_common;
struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
					  const struct hip_tlv_common *current_param);
void *hip_get_param_contents_direct(const void *tlv_common);

/* resets all the SAs. Actually, this shouldn't be allowed to touch
   other that those created by the proxy, or that are related to the
   proxy's hit!  */
int hipapi_clear_sas();

int hipapi_list_hits();
int hipapi_gethit(addr_t *addr);
int hipapi_init_rvs(int on);
int hipapi_set_udp_encap(int mode);
int hipapi_register_to_rvs(addr_t *rvshit, addr_t *rvsloc, int add);
int hipapi_addr_is_hit(addr_t *addr);
int hipapi_has_linkto(addr_t *remote_hit);
int hipapi_establish(addr_t *remote_hit, ship_list_t *ips, ship_list_t *rvs);
int hipapi_hip_running();

int hipapi_getrvs(ship_list_t *list);

int hipapi_create_peer_hit_locator_mapping(char *sip_aor, addr_t *hit);
int conn_connection_uses_hip(char *remote_aor, char *local_aor);

#endif
