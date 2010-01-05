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
/* All XML RPC packet creation functions */

int build_packet_put(unsigned char *, int, unsigned char *, 
                     int, int, unsigned char*, char *, int);

int build_packet_get(unsigned char *, int, int, unsigned char*, char *);

int read_packet_content(char *, char *);

/* openSSL wrapper functions for base64 encoding and decoding */

unsigned char * base64_encode(unsigned char *, unsigned int);

unsigned char * base64_decode(unsigned char *, unsigned int *);

