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
 * Module for managing the connections to peers. Sort of an adapter
 * between the ident module and the hip api (and the sipp)
 */
#ifndef __WEBCACHE_H__
#define __WEBCACHE_H__

void webcache_register();
void webcache_close_trackers(char *tracking_id);
int webcache_record(char *tracking_id, char *url, char *data, int datalen);
int webcache_p2p_lookup(char *url, void *ptr, void (*func) (char *url, void *obj, char *data, int datalen));
int webcache_get_resource(char *url, char **buf, int *len);

/* for resource fetching */
int resourcefetch_remove(char *rid);
int resourcefetch_store(char *filename, char **id);
int resourcefetch_get(char *host, char *rid,
		      char *local_aor,
		      void (*func) (void *param, char *host, char *rid, char *data, int datalen),
		      void *data);

#endif

