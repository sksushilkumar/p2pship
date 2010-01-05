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
#ifndef __UI_H__
#define __UI_H__

#define ui_define_operation(func_name, func_string, func_args, call_args) \
int func_name func_args\
{\
	int (*handler) func_args =\
		ship_ht_get_string(handler_funcs, func_string);\
	if (!handler) {\
		USER_ERROR("No UI found for operation %s\n", func_string);\
		return -1;\
	} else {\
		return handler call_args;\
	}\
}\


void ui_reg_handler(char *func_name, void *func);
void ui_register();



#endif
