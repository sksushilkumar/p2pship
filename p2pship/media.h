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
#ifndef __MEDIA_H__
#define __MEDIA_H__

typedef void (*media_observer_cb) (const int handle, const char *msgtype, const char *data, void *userdata);

void media_register();
int media_parse_pipeline(const char *pipeline, media_observer_cb callback, void *userdata);
int media_pipeline_start(const int handle);
int media_pipeline_stop(const int handle);
int media_pipeline_destroy(const int handle);

int media_check_element(const char *name);


#endif
