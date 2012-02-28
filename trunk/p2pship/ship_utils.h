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
 * Utils, helpers
 */
#ifndef __SHIP_UTILS_H__
#define __SHIP_UTILS_H__

#include "../config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/hmac.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlmemory.h>
#include <libxml/xmlwriter.h>
#include <libxml/xpath.h>

/* print debugging */
#define PRINT_DEBUG 1

/* debug when objects are ref'd and unref'd */
//#define REF_DEBUG

/* debug for tracing when ship_objs are ref'd and unref'd */
//#define REF_DEBUG2

/* lock debugging - print info when deadlocks & -waits are detected */
//#define LOCK_DEBUG
//#define LOCK_TRACE


/* whether to bother with the statistics */
//#define REPORT_STATS
//#define DO_STATS

/* call debug - doesn't really do much. was supposed to give a better
   call trace stack on errors */
//#define CALL_DEBUG

/* remote debugging / reporting. used in trials to collect error
   information */
//#define REMOTE_DEBUG
//#define REMOTE_DEBUG_ALL

#ifdef CALL_DEBUG
#define __NON_INSTRUMENT_FUNCTION__ __attribute__((__no_instrument_function__))
#else
#define __NON_INSTRUMENT_FUNCTION__    
#endif

/**
 * used in remote debugging 
 */
#ifdef REMOTE_DEBUG
void __NON_INSTRUMENT_FUNCTION__ ship_remote_report(const char *template, ...);
#define REPORT(fmt, args...) \
    ship_remote_report(fmt, ##args)
#else
#define REPORT(fmt, args...)
#endif

/**
 * logging functions
 */
void __NON_INSTRUMENT_FUNCTION__ ship_printf(int timed, int error, const char *template, ...);

void ship_printf_bytearr(const void *arr, const int arrlen, const char *template, ...);

/* normal */
#define USER_ERROR(fmt, args...) {\
ship_printf(0, 1, fmt, ##args);\
REPORT(fmt, ##args);\
}\

/* timed */
#define TUSER_ERROR(fmt, args...) {\
ship_printf(1, 1, fmt, ##args);\
REPORT(fmt, ##args);\
}\

#define USER_PRINT(fmt, args...) \
ship_printf(0, 0, fmt, ##args)

#define TUSER_PRINT(fmt, args...) \
ship_printf(1, 0, fmt, ##args)

/** utility for expressing time in milliseconds since epoch */
unsigned long ship_systemtimemillis();

/**
 * lock / condition variables handling 
 */
#define SHIP_LOCK pthread_mutex_t

#define LOCK_DECL(name) \
    pthread_mutex_t *name

#define COND_DECL(name) \
    pthread_cond_t *name

#define STATIC_LOCK_DECL(name) \
    static LOCK_DECL(name) = 0

#define STATIC_COND_DECL(name) \
    static COND_DECL(name) = 0

#define LOCK_INIT(name) \
        name = malloc(sizeof(pthread_mutex_t));\
        if (pthread_mutex_init(name, NULL)) {\
                free(name);\
                name = NULL;\
        }

#define COND_INIT(cond) \
        cond = malloc(sizeof(pthread_cond_t));\
        if (pthread_cond_init(cond, NULL)) {\
                free(cond);\
                cond = NULL;\
        }

#define LOCK_FREE(lock)\
        if (lock) {\
                pthread_mutex_destroy(lock);\
                free(lock);\
                lock = NULL;\
        }

#define COND_FREE(cond)\
        if (cond) {\
                pthread_cond_destroy(cond);\
                free(cond);\
                cond = NULL;\
        }

void* __NON_INSTRUMENT_FUNCTION__ _ship_lock(void *list);
void* __NON_INSTRUMENT_FUNCTION__ _ship_unlock(void *list);
int ship_locked(void *lock);

#define LOCK_ACQ(name) \
    pthread_mutex_lock(name);

#define LOCK_RELEASE(name) \
    pthread_mutex_unlock(name);

#define COND_SIGNAL(name) \
    pthread_cond_signal(name);

#define COND_WAIT(cond, lock) \
    pthread_cond_wait(cond, lock);

#define COND_WAITUNTIL(cond, lock, timeout) \
    {\
            struct timespec ts;\
            time(&(ts.tv_sec));\
            ts.tv_sec += timeout;\
            ts.tv_nsec = 0;\
            \
            pthread_cond_timedwait(cond, lock, &ts);\
    }

#define COND_WAITUNTIL_MS(cond, lock, timeout) \
    {\
            struct timeval tv;\
            struct timespec ts;\
            gettimeofday(&tv, 0);\
            ts.tv_sec = tv.tv_sec;\
            ts.tv_nsec = tv.tv_usec;\
            ts.tv_sec += ((timeout) / 1000);\
            ts.tv_nsec += (((timeout) % 1000) * 1000000);\
            if (ts.tv_nsec > 1000000000) {\
                ts.tv_nsec -= 1000000000;\
                ts.tv_sec += 1;\
            }\
            /*printf("aiting for %u and %u\n", ts.tv_nsec, ts.tv_sec);*/\
            pthread_cond_timedwait(cond, lock, &ts);\
    }

#define COND_WAKEUP(cond, lock) \
    pthread_mutex_lock(lock);\
    pthread_cond_signal(cond);\
    pthread_mutex_unlock(lock);

#define COND_WAKEUP_ALL(cond, lock) \
    pthread_mutex_lock(lock);\
    pthread_cond_broadcast(cond);\
    pthread_mutex_unlock(lock);

#define SYNCHRONIZE(lock, block)\
    pthread_mutex_lock(lock);\
    { block; }\
    pthread_mutex_unlock(lock);

#define SYNCHRONIZE_SIGNAL(lock, cond, block)\
    pthread_mutex_lock(lock);\
    { block; }\
    pthread_cond_signal(cond);\
    pthread_mutex_unlock(lock);

/**
 * thread handling
 */
#define TREAD_EXIT() pthread_exit(NULL)
#define THREAD_ABORT(name) \
        pthread_kill(*(name), SIGCHLD)

typedef pthread_t THREAD;

#define THREAD_DECL(name) \
    pthread_t *name

#define STATIC_THREAD_DECL(name) \
    static THREAD_DECL(name) = 0;

#define THREAD_INIT(name) \
    (name = (pthread_t*)mallocz(sizeof(pthread_t)))

#define THREAD_JOIN(name) \
    { void *tmp; pthread_join(*(name), &tmp); }

#define THREAD_FREE(name) freez(name)

#define THREAD_RUN(name, func, arg) \
    pthread_create(name, NULL, func, arg)

/* a re-lockable lock */
typedef struct ship_lock_s {
        pthread_mutex_t *lock;
        pthread_mutex_t *ulock;
        int lc;
        pthread_t owner;
        pthread_cond_t *cond;
} ship_lock_t;

/* free & zero */
//#define freez(ptr) { void **__t = (void**)&ptr; if (*__t) free(*__t); *__t = NULL; }
#define freez(ptr) { if (ptr) free(ptr); ptr = NULL; }
#define freez_arr(ptr, len) { int _i; if (ptr) { for (_i=0; _i<len; _i++) { if (ptr[_i]) free(ptr[_i]); } free(ptr); ptr = NULL; } }

/* malloc & zero the area */
static inline void * __NON_INSTRUMENT_FUNCTION__ mallocz(size_t __size)
{
        void *ret = malloc(__size);
        if (ret) {
                memset(ret, 0, __size);
        }
        return ret;
}

/* swapping of pointers */
#define ship_swap(a, b) { void *__ptr = a; a = b; b = __ptr; }

/**
 * buffers with length
 */
typedef struct ship_lenbuf_s {
	int len;
	char *data;
} ship_lenbuf_t;

void ship_lenbuf_free(ship_lenbuf_t *);
ship_lenbuf_t *ship_lenbuf_create_copy(char *data, int len);
ship_lenbuf_t *ship_lenbuf_create_ref(char *data, int len);

/**
 * the home-brewed lists of ship. basic one-way linked structures.
 */
typedef struct ship_list_entry_s ship_list_entry_t;

struct ship_list_entry_s {
	void *data;
	ship_list_entry_t *next;
};

typedef struct ship_list_s
{
	ship_lock_t lock;
        ship_list_entry_t *entries;
}
ship_list_t;

/* considered harmful for debugging */
/* #define ship_list_sync(list, block) \ */
/*     {\ */
/*     ship_lock(list);\ */
/*     block;\ */
/*     ship_unlock(list);\ */
/*     } */

/**
 * ship object handling
 *
 * The app uses its own object-handling scheme. It is similar to
 * g_objects in ways, but hopefully a bit lighter and with the support
 * of locking and thread-safe.
 */
typedef struct ship_obj_s ship_obj_t;

/* a small structure describing a particular ship_obj type */
struct ship_obj_type_s {

	/* the size of the object */
	int obj_size;
	char *obj_name;

	/* the constructor.  It WILL be passed a valid, object-sized
	   head-allocated object.  The task of this function is just to 
	   initialize the stuff *within* the object. 
	   
	   should return 0 if the initialization went ok. */
	int (*obj_init) (ship_obj_t *obj, void *param);

	/* the destructor for an object type. This should NOT free the object
	   itself! */
	void (*obj_free) (ship_obj_t *obj);
};

/* the parent object for all ship_obj types */
struct ship_obj_s {
	
	/* the object lock. this is used by the application logic for
	   synchronizing data structures */
	ship_lock_t _ship_obj_lock;

	/* the lock used for the reffing / unreffing operations. this
	   is separate from the object-lock to ease writing the logic
	   as it would easily result in deadlocks as objects aren't
	   (seemengly) locked, but when un/reffing would become. */
        pthread_mutex_t *_ship_ref_lock;

	/* struct describing the particular ship_obj type instance. */
	struct ship_obj_type_s _ship_obj_type;

	/* the reference counter */
	int _ship_obj_ref;
};

/* macro for declearing new object types */	
#define SHIP_INCLUDE_TYPE(name) \
struct ship_obj_type_s TYPE_##name;

#define SHIP_DEFINE_TYPE(name) \
struct ship_obj_type_s TYPE_##name = { sizeof(struct name##_s), #name, (int (*) (ship_obj_t *, void *))name##_init, (void (*) (ship_obj_t *))name##_free }


/**
 * functions for managing the ship_objs.
 *
 * ground rules:
 *
 * - the object should alway be ref'd unless just created.
 * - this means that ref first, lock then. And, subsequently, unlock first, unref then.
 * - ..which means NEVER ref or unref when having a lock!
 */
void ship_obj_free(void *param);
ship_obj_t* ship_obj_new(struct ship_obj_type_s type, void *param);
void _ship_obj_unref(void *param);
void _ship_obj_ref(void *param);

#ifdef REF_DEBUG

#define ship_obj_unlockref(obj) { printf(">> unlockreffing at %s:%d\n", __FILE__, __LINE__); ship_unlock(obj); _ship_obj_unref(obj); }
#define ship_obj_lockref(obj) { printf(">> lockreffing at %s:%d\n", __FILE__, __LINE__); ship_lock(obj); _ship_obj_ref(obj); }
#define ship_obj_ref(obj) { printf(">> reffing at %s:%d\n", __FILE__, __LINE__); _ship_obj_ref(obj); }
#define ship_obj_unref(obj) { printf(">> unreffing at %s:%d\n", __FILE__, __LINE__); _ship_obj_unref(obj); }

#elif defined REF_DEBUG2

void ship_debug_initref();
void ship_debug_delref(void *obj);
void ship_debug_incref(void *obj, const char *file, const int line);
void ship_debug_decref(void *obj, const char *file, const int line);
void ship_debug_reportref();
void ship_debug_closeref();

#define ship_obj_ref(obj) { ship_debug_incref(obj, __FILE__, __LINE__); _ship_obj_ref(obj); }
#define ship_obj_unref(obj) { ship_debug_decref(obj, __FILE__, __LINE__); _ship_obj_unref(obj); }
#define ship_obj_unlockref(obj) { ship_unlock(obj); ship_debug_decref(obj, __FILE__, __LINE__); _ship_obj_unref(obj); }
#define ship_obj_lockref(obj) { ship_lock(obj); ship_debug_incref(obj, __FILE__, __LINE__); _ship_obj_ref(obj); }

#else

#define ship_obj_unlockref(obj) { ship_unlock(obj); _ship_obj_unref(obj); }
#define ship_obj_lockref(obj) { ship_lock(obj); _ship_obj_ref(obj); }
#define ship_obj_ref(obj) { _ship_obj_ref(obj); }
#define ship_obj_unref(obj) { _ship_obj_unref(obj); }
#endif

typedef ship_list_t ship_obj_list_t;

#define ship_obj_list_add(list, obj) { ship_obj_ref(obj); ship_list_add(list, obj); }
#define ship_obj_list_new() ship_list_new()
//#define ship_obj_list_remove(list, obj) { void *__o = ship_list_remove(list, obj); ship_obj_unref(__o); }
#define ship_obj_list_free(list) { ship_obj_t *_obj; while (list && (_obj = ship_list_pop(list))) { ship_obj_unref(_obj); } ship_list_free(list); }
#define ship_obj_list_clear(list) { ship_obj_t *_obj; while ((_obj = ship_list_pop(list))) { ship_obj_unref(_obj); } }

typedef ship_list_t ship_obj_ht_t;

#define ship_obj_ht_new() ship_ht_new()
#define ship_obj_ht_put_string(list, key, obj) { ship_obj_ref(obj); ship_ht_put_string(list, key, obj); }
#define ship_obj_ht_remove_string(list, obj) { void *__o = ship_ht_remove_string(list, obj); ship_obj_unref(__o); }
#define ship_obj_ht_free(list) { ship_obj_t *_obj; while (list && (_obj = ship_ht_pop(list))) { ship_obj_unref(_obj); } ship_ht_free(list); }
#define ship_obj_ht_clear(list) { ship_obj_t *_obj; while ((_obj = ship_ht_pop(list))) { ship_obj_unref(_obj); } }

#if 0
/*
 * Example of use 
 */

typedef struct example_obj_s {
	ship_obj_t parent;
	
	int var;
	char *str;
} example_obj_t;

/* this is used in header files. if the type is decleared in a source
   file (static), then this isn't needed */

 SHIP_INCLUDE_TYPE(example_obj);

void example_obj_free(example_obj_t *obj)
{
	freez(obj->str);
}

int example_obj_init(example_obj_t *obj, void *param)
{
	obj->var = 1;
	ASSERT_TRUE(obj->str = strdup("hello"), err);
	return 0;
 err:
	return -1;
}

SHIP_DEFINE_TYPE(example_obj);


void
test()
{
	example_obj_t *myobj = NULL;
	
	ASSERT_TRUE(myobj = ship_obj_new(TYPE_example_obj, "hello"), err);
	printf("%s world!\n", myobj->str);
 err:
	ship_obj_unref(myobj);
}

/* end of ship_obj examples */
#endif


/**
 * in/outrolling
 *
 * These are used to convert integer values into x byte bytearrays
 */
#define ship_inroll(val, buf, len) {\
        int __itemp;\
        for (__itemp=0; __itemp < len; __itemp++) {\
                (buf)[__itemp] = (((val) >> (8*(len-__itemp-1))) & 0xff);\
        }\
}

#define ship_unroll(val, buf, len) {\
        int __itemp;\
        val = 0;\
        for (__itemp = 0; __itemp < len; __itemp++) {\
                (val) = ((val) << 8) + ((buf)[__itemp] & 0xff);\
        }\
}

void ship_lock_wait_until(void *obj, int ms);
void ship_lock_wait(void *obj);
void ship_lock_signal(void *obj);

#ifdef LOCK_DEBUG
/* lock-debuggning, new version */

inline void* __NON_INSTRUMENT_FUNCTION__ debug2_lock(void *lock, int thread, char *file, const char *function, int line);
inline void* __NON_INSTRUMENT_FUNCTION__ debug2_unlock(void *lock, int thread, char *file, const char *function, int line);
int __NON_INSTRUMENT_FUNCTION__ debug2_init();

#define ship_lock(lock) debug2_lock(lock, pthread_self(), __FILE__, __FUNCTION__, __LINE__);
#define ship_unlock(lock) debug2_unlock(lock, pthread_self(), __FILE__, __FUNCTION__, __LINE__);

#define ship_wait(str) debug2_wait(str, pthread_self(), __FILE__, __FUNCTION__, __LINE__);
#define ship_complete() debug2_complete(pthread_self(), __FILE__, __FUNCTION__, __LINE__);

void debug2_restrict_locks(void *token, void *target, int thread, const char *file, const char *func, int line);
#define ship_restrict_locks(token, target) debug2_restrict_locks(token, target, pthread_self(), __FILE__, __FUNCTION__, __LINE__)

void debug2_check_restricts(int thread, const char *file, const char *func, int line);
#define ship_check_restricts() debug2_check_restricts(pthread_self(), __FILE__, __FUNCTION__, __LINE__)


/* 
 * this is the old version of the lock-debugging, ignore..
 */
#if 0

#define ship_lock(lock) \
    { USER_PRINT("+ Aquire[%x] %08x .. @ %s:%s:%d.. \n", pthread_self(), lock, __FILE__, __FUNCTION__, __LINE__);\
    _ship_lock(lock);\
      USER_PRINT("+ OK[%x] %08x .. @ %s:%s:%d.. \n", pthread_self(), lock, __FILE__, __FUNCTION__, __LINE__);}

#define ship_unlock(lock) \
    { USER_PRINT("- Release[%x] %08x .. @ %s:%s:%d.. \n", pthread_self(), lock, __FILE__, __FUNCTION__, __LINE__);\
    _ship_unlock(lock);}
#endif
/** end of old lock-debugging */

#else
/* non-lock-debug- mode */

#define ship_lock(lock) _ship_lock(lock)
#define ship_unlock(lock) _ship_unlock(lock)

#define ship_wait(str)
#define ship_complete()

#define ship_restrict_locks(token, target) 
#define ship_check_restricts()

#endif

void ship_list_deinit(ship_list_t *list);
int ship_list_init(ship_list_t *ret);
void __NON_INSTRUMENT_FUNCTION__ ship_lock_free(ship_lock_t *lock);
int __NON_INSTRUMENT_FUNCTION__ ship_lock_new(ship_lock_t *lock);

/* closes the list */
void __NON_INSTRUMENT_FUNCTION__ ship_list_free(ship_list_t *list);

/* creates a list */
ship_list_t*  __NON_INSTRUMENT_FUNCTION__ ship_list_new();

/* removes an entry from the list, which is returned (if present) */
void * __NON_INSTRUMENT_FUNCTION__ _ship_list_remove(int _l, ship_list_t *list, void *data);
#define ship_list_remove(args...) _ship_list_remove(1, ##args)

static inline void *ship_obj_list_remove(ship_list_t *list, void *data) {
	void *__o = _ship_list_remove(1, list, data); 
	ship_obj_unref(__o); 
	return __o;
}

/*  */
void * __NON_INSTRUMENT_FUNCTION__ _ship_list_find(int _l, ship_list_t *list, void *data);
#define ship_list_find(args...) _ship_list_find(1, ##args)

/* adds something to the list */
void __NON_INSTRUMENT_FUNCTION__ _ship_list_add(int _l, ship_list_t *list, void *data);
#define ship_list_add(args...) _ship_list_add(1, ##args)

/* pushes something to the list, first */
void __NON_INSTRUMENT_FUNCTION__ _ship_list_push(int _l, ship_list_t *list, void *data);
#define ship_list_push(args...) _ship_list_push(1, ##args)

/* returns the length of the list */
int __NON_INSTRUMENT_FUNCTION__ _ship_list_length(int _l, ship_list_t *list);
#define ship_list_length(args...) _ship_list_length(1, ##args)

/* returns the first element of the list */
void * __NON_INSTRUMENT_FUNCTION__ _ship_list_first(int _l, ship_list_t *list);
#define ship_list_first(args...) _ship_list_first(1, ##args)

/* loops through */
void * __NON_INSTRUMENT_FUNCTION__ _ship_list_next(int _l, ship_list_t *list, void **ptr);
#define ship_list_next(args...) _ship_list_next(1, ##args)

/* returns the nth element of the list */
void * __NON_INSTRUMENT_FUNCTION__ _ship_list_get(int _l, ship_list_t *list, const int index);
#define ship_list_get(args...) _ship_list_get(1, ##args)

/* returns & removes the first element of the list */
void * __NON_INSTRUMENT_FUNCTION__ _ship_list_pop(int _l, ship_list_t *list);
#define ship_list_pop(args...) _ship_list_pop(1, ##args)

/* empties the list, freeing all data */
void __NON_INSTRUMENT_FUNCTION__ _ship_list_empty_free(int _l, ship_list_t *list);
#define ship_list_empty_free(args...) _ship_list_empty_free(1, ##args)

/* empties the list */
void  __NON_INSTRUMENT_FUNCTION__ _ship_list_clear(int _l, ship_list_t *list);
#define ship_list_clear(args...) _ship_list_clear(1, ##args)

/* empties the list, passing each data to the given func */
void __NON_INSTRUMENT_FUNCTION__ _ship_list_empty_with(int _l, ship_list_t *list, void (*func) (void *data));
#define ship_list_empty_with(queue, func) _ship_list_empty_with(1, queue, (void (*) (void*))func)

/** 
 * hashtables. 
 *
 * quite inefficient built right now
 * @todo: use real hashtables
 */
typedef ship_list_t ship_ht_t;
typedef ship_ht_t ship_ht2_t;

typedef struct ship_ht_entry_s {
	char *key;
	void *value;
} ship_ht_entry_t;

ship_ht_t * __NON_INSTRUMENT_FUNCTION__ ship_ht_new();
void __NON_INSTRUMENT_FUNCTION__ ship_ht_empty_free_with(ship_ht_t *ht, void (*func) (void *));
void __NON_INSTRUMENT_FUNCTION__ ship_ht_free(ship_ht_t *ht);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_next(ship_ht_t *ht, void **ptr);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_next_with_key(ship_ht_t *ht, void **ptr, char **key);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_first(ship_ht_t *ht);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_put_int(ship_ht_t *ht, const int key, void *val);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_put_string(ship_ht_t *ht, const char *key, void *val);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_get_int(ship_ht_t *ht, const int key);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_get_string(ship_ht_t *ht, const char *key);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_remove(ship_ht_t *ht, void *value);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_remove_int(ship_ht_t *ht, const int key);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_remove_string(ship_ht_t *ht, const char *key);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht_pop(ship_ht_t *ht);
void __NON_INSTRUMENT_FUNCTION__ ship_ht_clear(ship_ht_t *ht);
void __NON_INSTRUMENT_FUNCTION__ ship_ht_empty_free(ship_ht_t *ht);
ship_list_t * __NON_INSTRUMENT_FUNCTION__ ship_ht_values(ship_ht_t *ht);
ship_list_t * __NON_INSTRUMENT_FUNCTION__ ship_ht_keys(ship_ht_t *ht);
int __NON_INSTRUMENT_FUNCTION__ ship_ht_has_value(ship_ht_t *ht, void *val);
void ship_ht_keys_add(ship_ht_t *ht, ship_list_t *ret);
void *ship_ht_get_ptr(ship_ht_t *ht, const void *key);
void *ship_ht_put_ptr(ship_ht_t *ht, void *key, void *val);
int ship_ht_get_int_key(const char *key);

/* these are 2-dim hashtables. really innefficiently implemented right
   now (hashtable with hashtable entries) */
ship_ht2_t * __NON_INSTRUMENT_FUNCTION__ ship_ht2_new();
void __NON_INSTRUMENT_FUNCTION__ ship_ht2_free(ship_ht2_t *ht);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht2_put_string(ship_ht2_t *ht, char *key, char *key2, void *val);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht2_get_string(ship_ht2_t *ht, char *key, char *key2);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht2_remove_string(ship_ht2_t *ht, char *key, char *key2);
void * __NON_INSTRUMENT_FUNCTION__ ship_ht2_pop(ship_ht2_t *ht);
ship_list_t * __NON_INSTRUMENT_FUNCTION__ ship_ht2_keys(ship_ht2_t *ht, char *key);

void __NON_INSTRUMENT_FUNCTION__ ship_tokens_free(char **tokens, int len);
int __NON_INSTRUMENT_FUNCTION__ ship_tokens_replace(char **tokens, char *str, int pos);
int __NON_INSTRUMENT_FUNCTION__ ship_tokenize(const char *str, int len, char ***tokens, int *toklen, char token);
int __NON_INSTRUMENT_FUNCTION__ ship_tokenize_trim(const char *str, int len, char ***tokens, int *toklen, char token);
int ship_find_token(char *str, char *token, char limiter);

/* flattens an array of strings */
char *__NON_INSTRUMENT_FUNCTION__ ship_untokenize(char **tokens, int toklen, const char *token, const char *prefix);

/* dups & trims a string */
char *__NON_INSTRUMENT_FUNCTION__ strdup_trim(char *str);
char *__NON_INSTRUMENT_FUNCTION__ trim(char *str);

int ship_is_true(const char* tmp);

int __NON_INSTRUMENT_FUNCTION__ str_startswith(const char *str, const char *token);
char *__NON_INSTRUMENT_FUNCTION__ strstr_after(char *str, char *token);
char *__NON_INSTRUMENT_FUNCTION__ memmem_after(char *str, int len, char *token, int len2);
char *__NON_INSTRUMENT_FUNCTION__ append_mem(const char *str, int strlen, char *buf, int *buflen, int *datalen);
char *append_int(const int val, char *buf, int *buflen, int *datalen);
char *__NON_INSTRUMENT_FUNCTION__ append_str(const char *str, char *buf, int *buflen, int *datalen);
int __NON_INSTRUMENT_FUNCTION__ append_str2(char **str, char *buf);
char *combine_str(const char *str1, const char *str2);
char *replace_end(char *str, int *buflen, int *datalen, char *end, char *newend);

#define zstrcat(target, source) if (source && target) { strcat(target, source); }
#define zstrlen(str) (str? strlen(str):0)
int zstrcmp(const char *str1, const char *str2);

#define zdefault(str, def) (str? str:def)

/**
 * misc. data parsing functions
 */
void ship_urldecode(char *str);
char *ship_urlencode(char *str);
char *ship_addparam_urlencode(char *key, char *val, char *buf, int *size, int *len);
char *ship_pangoify(char *str);

char *ship_encode_base64(unsigned char *input, int length);
unsigned char *ship_decode_base64(char *input, int length, int* outlen);
char *ship_hash_sha1_base64(char *data, int datalen);

time_t ship_parse_time(char *str);
int ship_format_time(time_t time, char* buf, size_t len);
int ship_format_time_human(time_t time, char* buf, size_t len);

//char *strndup(const char *s, size_t n);
char *strdupz(const char *str);

/**
 * file / path handling functions
 */
int ship_get_homedir_file(char *filename, char **target);
int ship_ensure_file(char *filename, char *initial_data);
ship_list_t* ship_list_dir(const char *dir, const char *pattern, const int fullpath);
int ship_ensure_dir(char *filename);
int ship_read_file(char *filename, void *data,
		   void (*cb_content_line) (void *data, int lc, char *key, char *value, char *line),
		   void (*cb_ignore_line) (void *data, int lc, char *content, char *line));
int ship_read_mem(char *buf, int buflen, void *data,
		  void (*cb_content_line) (void *data, int lc, char *key, char *value, char *line),
		  void (*cb_ignore_line) (void *data, int lc, char *content, char *line));
int ship_load_file(const char* file, char **rbuf, int *len);
int ship_move(const char *from, const char *to);
int ship_file_exists(const char *filename);

/**
 * Cryto functions 
 */
char *ship_get_random_base64(const int bytes);
int ship_get_random (unsigned char *random, size_t len);
int ship_hash (const char *algo, unsigned char *data, unsigned char **hash);
char *ship_hmac_sha1_base64(const char *key, const char *secret);
unsigned char *ship_encrypt (const char *algo, unsigned char *key, unsigned char *iv, unsigned char *text, int *clen);
unsigned char *ship_decrypt (const char *algo, unsigned char *key, unsigned char *iv, unsigned char *cipher, int clen);
/* encrypt string & encode to based64 format */
unsigned char *ship_encrypt64 (const char *algo, unsigned char *key, unsigned char *iv, unsigned char *text);
/* decode based64 data & decrypt to string */
unsigned char *ship_decrypt64 (const char *algo, unsigned char *key, unsigned char *iv, unsigned char *cipher);

int ship_rsa_public_encrypt ( RSA* pu_key, unsigned char *data, int inlen, unsigned char **cipher);
int ship_rsa_private_decrypt ( RSA* pr_key, unsigned char *cipher, unsigned char **decipher);

unsigned char *ship_timestamp (int timeout);

RSA *ship_create_private_key();
X509 *ship_create_selfsigned_cert(char *subject, int ttl, RSA* signer_key);
X509 *ship_parse_cert(char *subject);

int fwrite_all(const char *data, const int len, FILE *f);

int ship_get_random(unsigned char *random, size_t len);
int ship_cmp_pubkey(X509 *cert, X509 *cert2);
char *ship_get_pubkey(X509 *cert);

/**
 * xml handling
 */
int ship_load_xml_file(const char *docname, int (*func) (xmlNodePtr, void *), void *ptr);
int ship_load_xml_mem(const char *data, int datalen, int (*func) (xmlNodePtr, void *), void *ptr);

/* evals an xpath expression (either with/without //-prefix) & returns
   the result */
xmlXPathObjectPtr ship_getnodeset (xmlDocPtr doc, xmlChar *xpath);
/* fetches an xpath obj from the given doc */
char* ship_xml_get_xpath_string_req(xmlDocPtr doc, char *key, int req);
/* fetches a child's value */
char* ship_xml_get_child_field_dup(xmlNodePtr node, char *key);
/* fetches a child's value */
char* ship_xml_get_child_field(xmlNodePtr node, char *key);
/* fetches a child element */
xmlNodePtr ship_xml_get_child(xmlNodePtr node, char *key);
int ship_xml_get_child_addr_list(xmlNodePtr node, char *key, ship_list_t *addr_list);

/* static int ship_xml_get_xpath_addr_list(xmlDocPtr doc, char *key, ship_list_t *addr_list); */
char* ship_xml_get_xpath_string_req(xmlDocPtr doc, char *key, int req);

int ship_xml_attr_is(xmlNodePtr node, char *key, char *value);

/* returns an xml field value using xpath */
#define ship_xml_get_xpath_field(doc, key) ship_xml_get_string_req(doc, key, 0)
#define ship_xml_get_xpath_single_string(doc, key) ship_xml_get_string_req(doc, key, 1)


#ifdef CONFIG_BLOOMBUDDIES_ENABLED

#define BLOOM_FUNCS 2

/**
 * bloomfilters
 */
typedef unsigned int (*hashfunc_t)(const char *);

typedef struct ship_bloom_s {
	size_t asize;
	size_t size_in_bytes;
	unsigned char *a;
	size_t nfuncs;
	hashfunc_t *funcs;
} ship_bloom_t;

ship_bloom_t *ship_bloom_new(size_t size);
void ship_bloom_free(ship_bloom_t *bloom);
int ship_bloom_add(ship_bloom_t *bloom, const char *s);
int ship_bloom_check(ship_bloom_t *bloom, const char *s);
int ship_bloom_empty(ship_bloom_t *bloom);
int ship_bloom_combine_bloom(ship_bloom_t *target, ship_bloom_t *source);
int ship_bloom_dump_size(ship_bloom_t *bloom);
void ship_bloom_dump(ship_bloom_t *bloom, char *buf);
ship_bloom_t *ship_bloom_load(char *buf, int buflen);

int ship_bloom_check_cert(ship_bloom_t *bloom, X509 *cert);
int ship_bloom_add_cert(ship_bloom_t *bloom, X509 *cert);
#endif

/* packing. should replace lenbufs etc atsome point .. */
typedef void* ship_pack_t;

void ship_pack_free(ship_pack_t *list);
ship_pack_t *ship_pack(char *fmt, ...);
ship_pack_t *ship_create_pack(char *fmt, va_list ap);
char ship_pack_type(ship_pack_t *list, const int elm);

int ship_unpack(int keep, int elm, ship_pack_t *list, ...);
#define ship_unpack_keep(list, args...) ship_unpack(1, -1, list, ##args)
#define ship_unpack_keep_one(element, list, args...) ship_unpack(1, element, list, ##args)
#define ship_unpack_transfer(list, args...) ship_unpack(0, -1, list, ##args)
#define ship_unpack_transfer_one(element, list, args...) ship_unpack(0, element, list, ##args)

#endif
