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
#include "ship_debug.h"

/* default log level */
int p2pship_log_level = LOG_INFO;
char* p2pship_log_file = 0;
time_t p2pship_start = 0;

char *p2pship_log_labels[] = {
	"[ERROR]",
	"[WARN]",
	"[INFO]",
	"[DEBUG]",
	"[VDEBUG]",
	0
};

#define DIE_ON_LOCK_WARNINGS 1

#ifdef LOCK_DEBUG
static int debug2_lock_count = 0;
static int debug2_wait_count = 0;

#include <execinfo.h>
#include <pthread.h>

/* one array for the locks */
static ship_list_t *debug2_locks = 0;

typedef struct debug2_lock_s {
	void *lock;
	
	int thread;
	time_t time;
	
	char *str;
	char *bt;
} debug2_lock_t;

/* one array for the waiting threads */
static ship_list_t *debug2_threads = 0;
static pthread_t debugger;

/* one for the restrictions on other locks */
static ship_list_t *debug2_restricts = 0;

typedef struct debug2_restriction_s {
	void *token; /* ..as long as this is held by */
	int thread; /* ..this thread, do not allow */
	
	void *target; /* ..this to be locked by the same thread (NULL = *any*!) */
	
	char *loc; /* ..as specified here! */
} debug2_restriction_t;

void *
__NON_INSTRUMENT_FUNCTION__
debug2_run(void *data)
{
	USER_PRINT(">>>\n>>>\n>>>  starting lock debugger thread..\n>>>\n>>>\n");
	while (1) {
		debug2_lock_t *l1;
		void *p1 = 0;
		time_t now;
		int head = 0;

		_ship_lock(debug2_threads);
		debug2_lock_count = 0;
		debug2_wait_count = 0;
		/* find any thread that has been waiting for over x
		   secs for a lock */
		time(&now);
		while (l1 = _ship_list_next(0, debug2_threads, &p1)) {
			if ((now - l1->time) > 3) {
				debug2_lock_t *l2 = 0;
				void *p2 = 0;
				
				/* find the thread that is currently hogging it! */
				while (l1->lock && !l2 && (l2 = _ship_list_next(0, debug2_locks, &p2))) {
					if (l1->lock != l2->lock)
						l2 = 0;
				}

				if (!head) {
					USER_PRINT("\n****** LOCKS\n");
					head = 1;
				}
				
				if (l1->lock) {
					debug2_lock_count++;
					USER_PRINT("DEADLOCK, thread has been waiting for %d secs!\n", (now - l1->time));
				} else {
					debug2_wait_count++;
					USER_PRINT("DEADWAIT for %s, thread has been waiting for %d secs!\n", 
						   l1->str, (now - l1->time));
				}
				USER_PRINT("[%08x] waiting for [%08x] in wait: '%s' at %s", l1->thread, l1->lock, l1->str, l1->bt);
				if (l2) {
					USER_PRINT("[%08x] currently has [%08x] from wait: '%s' at %s", l2->thread, l2->lock, l2->str, l2->bt);
				} else if (l1->lock) {
					USER_PRINT("No info no current holder!\n");
				}
			}
		}
		_ship_unlock(debug2_threads);
		sleep(3);
	}
	return 0;
}

int
debug2_init()
{
	debug2_locks = ship_list_new();
	debug2_threads = ship_list_new();
	debug2_restricts = ship_list_new();
	pthread_create(&debugger, NULL, debug2_run, NULL);
}

void
debug2_close()
{
}

static inline debug2_lock_t *
__NON_INSTRUMENT_FUNCTION__
debug2_new(void *lock, char *str, int thread, char *file, const char *function, int line)
{
	int i, s = 30, len = 0;
	void **bts = 0;
	debug2_lock_t *l = mallocz(sizeof(debug2_lock_t));
	char **symbols = 0;
	
	l->lock = lock;
	if (str)
		l->str = strdup(str);
	l->thread = thread;
	time(&(l->time));

	/* create the backtrace! */
	len += 128 + strlen(file) + strlen(function);
	bts = malloc(s * sizeof(void*));
	s = backtrace(bts, s);
	if (s > 0) {
		symbols = backtrace_symbols(bts, s);
		for (i=0; i < s; i++) {
			len += strlen(symbols[i]);
		}
	}

	l->bt = mallocz(len);
	sprintf(l->bt, "file %s:%s:%d:\n", file, function, line);
	if (symbols) {
		for (i=0; i < s; i++) {
			strcat(l->bt, "\t");
			strcat(l->bt, symbols[i]);
			strcat(l->bt, "\n");
			//freez(symbols[i]);
		}
		
		freez(symbols); 
	}
	freez(bts);
	return l;
}

inline void 
__NON_INSTRUMENT_FUNCTION__
debug2_wait(char *str, int thread, char *file, const char *function, int line)
{
	debug2_lock_t *l = debug2_new(0, str, thread, file, function, line);

	_ship_lock(debug2_threads);
	_ship_list_add(0, debug2_threads, l);
	_ship_unlock(debug2_threads);
}

inline void 
__NON_INSTRUMENT_FUNCTION__
debug2_complete(int thread, char *file, const char *function, int line)
{
	debug2_lock_t *l = 0;
	int i = 0;

	_ship_lock(debug2_threads);
	i = _ship_list_length(0, debug2_threads) - 1;
	while (!l && i > -1) {
		l = _ship_list_get(0, debug2_threads, i);
		if (l->lock || l->thread != thread)
			l = 0;
		i--;
	}
	_ship_list_remove(0, debug2_threads, l);
	_ship_unlock(debug2_threads);

	if (l) {
		freez(l->str);
		freez(l);
	}
}

void 
__NON_INSTRUMENT_FUNCTION__
debug2_check_restricts(int thread, const char *file, const char *func, int line)
{
	void *ptr = 0, *p2 = 0;
	debug2_restriction_t *r = 0;

	_ship_lock(debug2_threads);
	ptr = 0;
	while (r = _ship_list_next(0, debug2_restricts, &ptr)) {
		if (r->thread == thread) {
			debug2_lock_t *l = 0;
			USER_PRINT("+++++++ RESTRICT WARNING at %s:%s:%d (%s):\n\tRestriction for %08x :: %08x, token %08x\n",
				   file, func, line, r->loc, thread, r->target, r->token);

			/* print all the locks we still have on this one .. */
			l = 0;
			while (l = _ship_list_next(0, debug2_locks, &p2)) {
				if (l->lock == r->token && l->thread == thread) {
					USER_PRINT("\tLocked at %s / %s\n",
						   l->str, l->bt);
				}
			}
		}
	}
	_ship_unlock(debug2_threads);
}

void 
__NON_INSTRUMENT_FUNCTION__
debug2_restrict_locks(void *token, void *target, int thread, const char *file, const char *func, int line)
{
	_ship_lock(debug2_threads);
	if (!target) {
		USER_ERROR("ERROR: Trying to restrict a thread from locking ANYTHING!!\n");
		return;
	}

	if (token) {
		//_ship_lock(debug2_restricts);

		debug2_restriction_t* r = mallocz(sizeof(debug2_restriction_t));
		r->loc = mallocz(strlen(file) + strlen(func) + 64);
		sprintf(r->loc, "%s:%s:%d", file, func, line);
		r->token = token;
		r->target = target;
		r->thread = thread;
		
		//USER_PRINT("////////// restricting %08x :: %08x for %08x at %s:%s:%d\n", thread, target, token, file, func, line);
		_ship_list_add(0, debug2_restricts, r);
	}
	_ship_unlock(debug2_threads);
}

inline void*
__NON_INSTRUMENT_FUNCTION__
debug2_lock(void *lock, int thread, char *file, const char *function, int line)
{
	int i;
	debug2_restriction_t *r = 0;
	debug2_lock_t *w = 0, *l = 0;
	void *ptr = 0;
	
	if (!lock)
		return NULL;

	l = debug2_new(lock, 0, thread, file, function, line);
	_ship_lock(debug2_threads);
	//_ship_lock(debug2_restricts);
	//printf("Locking %08x :: %08x.. (%s:%s:%d)\n", thread, lock, file, function, line);

	/* if we have a wait for this thread, then add that message to
	   the lock also! */
	i = _ship_list_length(0, debug2_threads) - 1;
	while (!w && i > -1) {
		w = _ship_list_get(0, debug2_threads, i);
		if (w->lock || w->thread != thread)
			w = 0;
		i--;
	}
	if (w && w->str)
		l->str = strdup(w->str);
	
	/* check all possible restrictions! */
	ptr = 0;
	while (r = _ship_list_next(0, debug2_restricts, &ptr)) {
		if (r->thread == thread && (!r->target || r->target == lock)) {
			USER_PRINT("+++++++ LOCK WARNING at %s:%s:%d (%s):\n\tTrying to get a lock (%08x :: %08x) restricted at %s for %08x\n",
				   file, function, line, l->str, thread, r->target, r->loc, r->token);

			USER_PRINT("+++++++ Violation at: %s\n", l->bt);

			l = 0;
#ifdef DIE_ON_LOCK_WARNINGS
			USER_PRINT("+++++++ and I will die: %s\n", l->bt);
#endif
			//USER_PRINT("+++++++ Set at: %s\n", r->bt);
		}
	}

	_ship_list_add(0, debug2_threads, l);
	_ship_unlock(debug2_threads);

	_ship_lock(lock);
/* 	if (((ship_lock_t*)lock)->lc > 1) { */
/* 		USER_PRINT("+++++++ LOCK WARNING at %s:%s:%d (%s):\n\tLock locked already %d times\n", */
/* 			   file, function, line, l->str, ((ship_lock_t*)lock)->lc); */
/* 	} */

	_ship_lock(debug2_threads);
#ifdef LOCK_TRACE
	/* print out ALL locks this guy has right now => go through debug2_locks */
	if (((ship_lock_t*)lock)->lc == 1) {
		ptr = 0;
		i = 0;
		while (w = _ship_list_next(0, debug2_locks, &ptr)) {
			if (w->thread == thread) {
				char *t = 0;
				
				if (i == 0) {
					if (t = strstr(l->bt, "\n")) t[0] = 0;
					USER_PRINT("LOCK TRACE: %08x locked %08x (%s) while having ", thread, lock, l->bt);
					if (t) t[0] = '\n';
					
					//USER_PRINT("LOCK TRACE: %08x locked %08x (%s) while having ", thread, lock, l->bt);
					//USER_PRINT("LOCK TRACE: %08x locked %08x (%s:%s:%d) while having ", thread, lock, file, function, line);
				}
				
				if (t = strstr(w->bt, "\n")) t[0] = 0;
				USER_PRINT("%08x (%s), ", w->lock, w->bt);
				if(t) t[0] = '\n';
				i++;
			}
		}
		if (i) {
			USER_PRINT("\n");
		} else {
			//USER_PRINT("LOCK TRACE: %08x starts lockspree with %08x\n", thread);
		}
	}
#endif
	_ship_list_remove(0, debug2_threads, l);
	_ship_list_add(0, debug2_locks, l);
	_ship_unlock(debug2_threads);
	return lock;
}

inline void*
__NON_INSTRUMENT_FUNCTION__
debug2_unlock(void *lock, int thread, char *file, const char *function, int line)
{
	debug2_lock_t *l = 0;
	debug2_restriction_t *r = 0;
	void *ptr = 0, *last = 0;
	debug2_lock_t *l2 = 0;

	_ship_lock(debug2_threads);
	//_ship_lock(debug2_restricts);

	_ship_unlock(lock);
	//USER_PRINT("unlocking %08x :: %08x..\n", thread, lock);

	while (l2 = _ship_list_next(0, debug2_locks, &ptr)) {
		if (l2->lock == lock && l2->thread == thread)
			l = l2;
	}
	
	if (l) {
		_ship_list_remove(0, debug2_locks, l);
		freez(l->bt);
		freez(l->str);
		freez(l);
	}

	/* remove all restrictions on this if this is the last lock entry */
	ptr = 0;
	l = 0;
	while (!l && (l = _ship_list_next(0, debug2_locks, &ptr))) {
		if (l->lock != lock || l->thread != thread)
			l = 0;
	}
	
	ptr = 0;
	last = 0;
	while (!l && (r = _ship_list_next(0, debug2_restricts, &ptr))) {
				
		if (r->thread == thread && lock == r->token) {

			//USER_PRINT("\\\\\\\\ remove restrict %08x :: %08x for %08x\n", thread, r->target, r->token);

			_ship_list_remove(0, debug2_restricts, r);
			freez(r->loc);
			free(r);
			ptr = last;
		} else 
			last = ptr;
	}
	_ship_unlock(debug2_threads);
	return lock;
}

#endif



/* returns debugging info in json format */
int
ship_debug_dump_json(char **msg)
{
	int ret = -1;
	char *buf = 0;
	int buflen = 0, datalen = 0;
	time_t now;
	char tmp[32];
	time(&now);
	
	ASSERT_TRUE(buf = append_str("var p2pship_info = {\n", buf, &buflen, &datalen), err);

	sprintf(tmp, "%d\",\n", (int)(now-p2pship_start));
	ASSERT_TRUE(buf = append_str("     \"uptime\" : \"", buf, &buflen, &datalen), err);
	ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);

#ifdef LOCK_DEBUG
	_ship_lock(debug2_threads);
	sprintf(tmp, "%d\",\n", debug2_lock_count);
	ASSERT_TRUE(buf = append_str("     \"locks\" : \"", buf, &buflen, &datalen), err);
	ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);

	sprintf(tmp, "%d\",\n", debug2_wait_count);
	ASSERT_TRUE(buf = append_str("     \"waits\" : \"", buf, &buflen, &datalen), err);
	ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
	_ship_unlock(debug2_threads);
#endif

	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("};\n", buf, &buflen, &datalen), err);
	
	*msg = buf;
	buf = 0;
	ret = 0;
 err:
	freez(buf);
	return ret;
}





/* ptrace-like function call debugging */

#ifdef CALL_DEBUG

static ship_list_t *calldebug_threads = 0;

void 
__NON_INSTRUMENT_FUNCTION__
calldebug_init()
{
	calldebug_threads = ship_list_new();
}

void
__NON_INSTRUMENT_FUNCTION__
__cyg_profile_func_enter(void *this_fn, void *call_site)
{
	if (calldebug_threads) {
		char **strs = 0, **strs2 = 0;
		strs = backtrace_symbols(&this_fn, 1);
		strs2 = backtrace_symbols(&call_site, 1);
		
		//USER_PRINT("entering function.. %p (%s), calling %p (%s)\n", this_fn, strs[0], call_site, strs2[0]);
	}
	//(void)call_site;
}

/** According to gcc documentation: called upon function exit */
void
__NON_INSTRUMENT_FUNCTION__
__cyg_profile_func_exit(void *this_fn, void *call_site)
{
	if (calldebug_threads) {
		char **strs = 0, **strs2 = 0;
		strs = backtrace_symbols(&this_fn, 1);
		strs2 = backtrace_symbols(&call_site, 1);
		
		//USER_PRINT("exiting function.. %p (%s), calling %p (%s)\n", this_fn, strs[0], call_site, strs2[0]);
	}
	//	(void)call_site;
}

#endif

