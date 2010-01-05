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
#ifndef __IDENT_ADDR_H__
#define __IDENT_ADDR_H__

#define IDENT_ADDR_MAX_LEN 255
#define IDENT_ADDR_TRANSPORT_MAX_LEN (IDENT_ADDR_MAX_LEN+32)

typedef struct addr_s
{
	/* AF_INET, AF_INET6 */
        short family;

        /* an integer 0-0xffff */
	unsigned short port;

        /* the address */
	char addr[IDENT_ADDR_MAX_LEN+1];

        /* IPPROTO_TCP, IPPROTO_UDP, IPPROTO_NONE, see netinet/in.h */
        int type;

        /* the hostname */
	char hostname[IDENT_ADDR_MAX_LEN+1];
}
addr_t;

#endif
