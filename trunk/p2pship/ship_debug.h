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
 * Debugging stuff
 */
#ifndef __SHIP_DEBUG_H__
#define __SHIP_DEBUG_H__

#include <stdio.h>
#include "ship_utils.h"

extern int p2pship_log_level;
extern char *p2pship_log_labels[];
	
enum {
        LOG_ERROR = 0,
        LOG_WARN,
        LOG_INFO,
        LOG_DEBUG,
        LOG_VDEBUG
};


#ifdef REPORT_STATS
#define STATS_LOG(fmt, args...) \
    LOG_OUT("[STATS] 0x%08x, %u: " fmt, pthread_self(), ship_systemtimemillis(), ##args)
#else
#define STATS_LOG(fmt, args...) 
#endif

#ifdef PRINT_DEBUG

#define LOG_OUT(fmt, args...) \
	{ TUSER_PRINT(fmt, ##args); } 

#define LOG_HL(fmt, args...) \
	{ TUSER_PRINT("[HL] %s: " fmt, __FUNCTION__, ##args); }

#define LOG_CUSTOM(level, fmt, args...) \
	{ if (p2pship_log_level >= level) LOG_OUT("%s " fmt, p2pship_log_labels[level], ##args); }

#define LOG_WARN(fmt, args...) \
	{ if (p2pship_log_level >= LOG_WARN) LOG_OUT("[WARN] %s: " fmt, __FUNCTION__, ##args); }

#define LOG_DEBUG(fmt, args...) \
	{ if (p2pship_log_level >= LOG_DEBUG) LOG_OUT("[DEBUG] %s: " fmt, __FUNCTION__, ##args); }

#define LOG_VDEBUG(fmt, args...) \
	{ if (p2pship_log_level >= LOG_VDEBUG) LOG_OUT("[VDEBUG] %s: " fmt, __FUNCTION__, ##args); }

#define LOG_INFO(fmt, args...) \
	{ if (p2pship_log_level >= LOG_INFO) LOG_OUT("[INFO] %s: " fmt, __FUNCTION__, ##args); }

#define TODO(fmt, args...) \
	{ if (p2pship_log_level >= LOG_ERROR) LOG_OUT("[TODO] %s: " fmt, __FUNCTION__, ##args); }

#define LOG_ERROR(fmt, args...) \
	{ if (p2pship_log_level >= LOG_ERROR) LOG_OUT("[ERROR] %s: " fmt, __FUNCTION__, ##args); }

#define LOG_ASSERT(fmt, args...) \
	{ if (p2pship_log_level >= LOG_ERROR) LOG_OUT("[ASSERT] %s: " fmt, __FUNCTION__, ##args); }

#else

#define LOG_OUT(fmt, args...) ;
#define LOG_HL(fmt, args...) ;
#define LOG_WARN(fmt, args...) ;
#define LOG_DEBUG(fmt, args...) ;
#define LOG_VDEBUG(fmt, args...) ;
#define LOG_INFO(fmt, args...) ;
#define TODO(fmt, args...) ;
#define LOG_ERROR(fmt, args...) ;
#define LOG_ASSERT(fmt, args...) ;

#endif

#define PANIC(fmt, args...) {\
    USER_ERROR("[PANIC] %s: " fmt "\nAborting due to panic\n", __FUNCTION__, ##args);\
    exit(1);}

#define ASSERT_TRUE(val, lab, arg...) \
	{ long __tmp = (long)(val); if (!(__tmp)) { LOG_ASSERT("Assert failed @ %s:%d, not TRUE (%d)\n", __FILE__, __LINE__, __tmp); goto lab; }}

#define ASSERT_ZERO(val, lab) \
	{ long __tmp = (long)(val); if ((__tmp)) { LOG_ASSERT("Assert failed @ %s:%d, not ZERO (%d)\n", __FILE__, __LINE__, __tmp); goto lab; }}

#define ASSERT_TRUES(val, lab, fmt, args...)				\
	{ long __tmp = (long)(val); if (!(__tmp)) { LOG_ASSERT("Assert failed @ %s:%d, not TRUE (%d): " fmt, __FILE__, __LINE__, __tmp, ##args); goto lab; }}

#define ASSERT_ZEROS(val, lab, fmt, args...)				\
	{ long __tmp = (long)(val); if ((__tmp)) { LOG_ASSERT("Assert failed @ %s:%d, not ZERO (%d): " fmt, __FILE__, __LINE__, __tmp, ##args); goto lab; }}

int ship_debug_dump_json(char **msg);
    
#ifdef LOCK_DEBUG
void debug2_close();
inline void __NON_INSTRUMENT_FUNCTION__ debug2_wait(char *str, int thread, char *file, const char *function, int line);
inline void __NON_INSTRUMENT_FUNCTION__ debug2_complete(int thread, char *file, const char *function, int line);
#endif

#endif
