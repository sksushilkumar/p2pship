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
#define	_GNU_SOURCE /* for memmem */
#define _XOPEN_SOURCE /* for strptime */

#include <stdio.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sys/stat.h>
#include <glob.h>
#include <regex.h>
#include <ctype.h>
#include <string.h>
#include <sys/time.h>

#include "processor_config.h"
#include "ident.h"
#include "ship_utils.h"
#include "ship_debug.h"
#include "services.h"

extern char *p2pship_log_file;
extern ship_list_t *getaddrinfolock;
#define LOG_SIZE_LIMIT (100 * 1024)


/* this should be in services .. */
service_type_t
service_str_to_type(char *service)
{
	if (!service)
		return SERVICE_TYPE_NONE;

	if (!strcmp(service, "sip")) {
		return SERVICE_TYPE_SIP;
	} else {
		return atoi(service);
	}
}


/* the debuggning addr */
#ifdef REMOTE_DEBUG
char *remote_debug_addr = 0;

void
ship_remote_debug_init(processor_config_t *config)
{
	if (!processor_config_get_string(config, P2PSHIP_CONF_REMOTE_DEBUG, &remote_debug_addr)) {
		remote_debug_addr = strdup(remote_debug_addr);
	}
}
#endif

/* returns the current time in ms */
unsigned long
ship_systemtimemillis()
{
	struct timeval tv;
	if (!gettimeofday(&tv, 0)) {
		return (unsigned long)(tv.tv_sec * 1000) + (tv.tv_usec / 1000);
	}
	return 0;
}

/* the loggin func */
void 
ship_printf(int timed, int error, const char *template, ...)
{

	/* add current time */
        if (timed) {
		time_t t;
		char buf[64];
		struct tm tm;
		memset(&tm, 0, sizeof(struct tm));
		time(&t);
		localtime_r(&t, &tm);
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S ", &tm);
		ship_printf(0, error, buf);
		ship_printf(0, error, "(%08x) ", pthread_self());
	}

	va_list ap;
	va_start(ap, template);
	if (!p2pship_log_file) {
		if (error)
			vfprintf(stderr, template, ap);
		else
			vfprintf(stdout, template, ap);
	} else {
		FILE *f = NULL;
		struct stat sdata;
		char *nn = 0;
		/* keep file size under LIMIT */
		if (!stat(p2pship_log_file, &sdata) && 
		    sdata.st_size > LOG_SIZE_LIMIT &&
		    (nn = mallocz(strlen(p2pship_log_file) + 5))) {
			strcpy(nn, p2pship_log_file);
			strcat(nn, ".old");
			rename(p2pship_log_file, nn);
			freez(nn);
		}

		if ((f = fopen(p2pship_log_file, "a"))) {
			vfprintf(f, template, ap);
			fclose(f);	
		}
	}

	va_end(ap);

#ifdef REMOTE_DEBUG_ALL
	{
		char *buf = 0;
		va_start(ap, template);
		
		if (buf = mallocz(10 * 1048)) {
			int len = vsprintf(buf, template, ap);
			ship_list_t *idents = 0;
			struct sockaddr *sa = 0;
			socklen_t salen = 0;

			if (getaddrinfolock && remote_debug_addr && !ident_addr_str_to_sa_lookup(remote_debug_addr/* remote addr */, &sa, &salen)) {
				netio_packet_anon_send(buf, strlen(buf), sa, salen);
			}
			freez(sa);
		}
		freez(buf);
		va_end(ap);
	}
#endif
}

/* this is only for local debugging. prints out a byte array */
void
ship_printf_bytearr(const void *arr, const int arrlen, const char *template, ...)
{
	int i;
	va_list ap;
	va_start(ap, template);
	vfprintf(stderr, template, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	for (i=0; i < arrlen; i++) {
		if (i % 16 == 0)
			fprintf(stderr, "0x%02x:  ", i);
		fprintf(stderr, "%02x ", (0xff & ((const char*)arr)[i]));
		if (i % 16 == 15)
			fprintf(stderr, "\n");
	}
	fprintf(stderr, "\n");
}

int 
ship_locked(void *lock)
{
	ship_lock_t *list = (ship_lock_t *)lock;
	if (list && list->lc > 0)
		return 1;
	return 0;
}

void*
_ship_lock(void *lock)
{        
	ship_lock_t *list = (ship_lock_t *)lock;
	if (!list)
		return NULL;
        /* check if we already have the lock */
        LOCK_ACQ(list->ulock);

        //if (!pthread_equal(list->owner, pthread_self()) || !list->lc) {
        if (!(list->owner == pthread_self()) || !list->lc) {
                LOCK_RELEASE(list->ulock);
                LOCK_ACQ(list->lock);
                LOCK_ACQ(list->ulock);
                list->lc = 0;
        }
        list->owner = pthread_self();
        list->lc++;
        LOCK_RELEASE(list->ulock);
	return lock;
}

/* closes the list */
void*
_ship_unlock(void *lock)
{      
	ship_lock_t *list = (ship_lock_t *)lock;
	if (!list)
		return NULL;
        /* check if we have & how much!! */
        LOCK_ACQ(list->ulock);
        //if (pthread_equal(list->owner, pthread_self()) && list->lc) {
        if ((list->owner == pthread_self()) && list->lc) {
                list->lc--;
                if (list->lc == 0) {
                        LOCK_RELEASE(list->lock);
                }
        }
        LOCK_RELEASE(list->ulock);
	return lock;
}

/* frees a lock */
void
ship_lock_free(ship_lock_t *lock) 
{
	LOCK_FREE(lock->lock);
	LOCK_FREE(lock->ulock);
}

/* creates a lock */
int
ship_lock_new(ship_lock_t *lock)
{
	LOCK_INIT(lock->lock);
	LOCK_INIT(lock->ulock);
	lock->lc = 0;
	if (!lock->lock || !lock->ulock) {
		return -1;
	} else {
		return 0;
	}
}

/*********** The list functions ***********/

/* closes the list */
void 
ship_list_deinit(ship_list_t *list)
{        
	if (list) {
		_ship_lock(list);
		ship_list_clear(list);
		ship_lock_free(&list->lock);
	}
}

void 
ship_list_free(ship_list_t *list)
{        
	if (list) {
		ship_list_deinit(list);
		free(list);
	}
}


/* creates a list */
int
ship_list_init(ship_list_t *ret)
{
	bzero(ret, sizeof(*ret));
	return ship_lock_new(&ret->lock);
}

ship_list_t * 
ship_list_new()
{
	ship_list_t * ret = (ship_list_t *)mallocz(sizeof(ship_list_t));
	if (!ret || ship_list_init(ret)) {
		ship_list_free(ret);
		ret = NULL;
	}
	return ret;
}

void * 
_ship_list_remove(int _l, ship_list_t *list, void *data)
{
	ship_list_entry_t *entry = 0, *last = 0;
	if (_l) ship_lock(list);
	
	entry = list->entries;
	while (entry && entry->data != data) {
		last = entry;
		entry = entry->next;
	}
	
	if (entry) {
		if (last)
			last->next = entry->next;
		else
			list->entries = entry->next;
		freez(entry);
	} else
		data = 0;
	if (_l) ship_unlock(list);
	return data;
}

/* finds na entry */
void * 
_ship_list_find(int _l, ship_list_t *list, void *data)
{
	ship_list_entry_t *entry = 0;
	if (_l) ship_lock(list);
	
	entry = list->entries;
	while (entry && entry->data != data) {
		entry = entry->next;
	}

	if (!entry)
		data = 0;

	if (_l) ship_unlock(list);
	return data;
}

/* adds something to the list */
void 
_ship_list_add(int _l, ship_list_t *list, void *data)
{
	ship_list_entry_t **e = 0;
	if (!data)
		return;
	if (_l) ship_lock(list);

	e = &(list->entries);
	while (*e) {
		e = &((*e)->next);
	}
	
	if (((*e) = mallocz(sizeof(ship_list_entry_t))))
		(*e)->data = data;
	else {
		PANIC("list_add() failed\n");
	}
	if (_l) ship_unlock(list);
}

/* pushes something first on the list */
void 
_ship_list_push(int _l, ship_list_t *list, void *data)
{
	ship_list_entry_t *e = 0;
	if (!data)
		return;
	if (_l) ship_lock(list);

	if ((e = mallocz(sizeof(ship_list_entry_t)))) {
		e->data = data;
		e->next = list->entries;
		list->entries = e;
	} else {
		PANIC("list_push() failed\n");
	}
	if (_l) ship_unlock(list);
}

/* returns the length of the list */
int 
_ship_list_length(int _l, ship_list_t *list)
{        
	int len = 0;
	ship_list_entry_t *entry = 0;

	if (_l) ship_lock(list);
	entry = list->entries;
	while (entry) {
		len++;
		entry = entry->next;
	}
	if (_l) ship_unlock(list);
	return len;
}

/* returns the first element of the list */
void * 
_ship_list_first(int _l, ship_list_t *list)
{
	void *d = 0;
	if (_l) ship_lock(list);
	if (list->entries)
		d = list->entries->data;
	if (_l) ship_unlock(list);
	return d;
}

/* loops through */
void * 
_ship_list_next(int _l, ship_list_t *list, void **ptr)
{
	ship_list_entry_t *eptr = 0;
	void *ret = 0;
	if (_l) ship_lock(list);
	if (*ptr) {
		eptr = (*((ship_list_entry_t**)ptr))->next;
	} else {
		eptr = list->entries;
	}
	
	*ptr = eptr;
	if (eptr)
		ret = eptr->data;
	if (_l) ship_unlock(list);
	return ret;
}

/* returns the nth element of the list */
void * 
_ship_list_get(int _l, ship_list_t *list, const int index)
{
	ship_list_entry_t *entry = 0;
	void *ret = 0;
	int c = 0;
	if (!list)
		return NULL;
	if (_l) ship_lock(list);

	entry = list->entries;
	while (index > -1 && c != index && entry) {
		entry = entry->next;
		c++;
	}
	
	if (entry)
		ret = entry->data;
	if (_l) ship_unlock(list);
	return ret;
}

/* returns & removes the first element of the list */
void * 
_ship_list_pop(int _l, ship_list_t *list)
{
	void *ret = 0;
	ship_list_entry_t *e = 0;
	if (!list)
		return NULL;
	if (_l) ship_lock(list);

	if (list->entries) {
		ret = list->entries->data;
		e = list->entries->next;
		freez(list->entries);
		list->entries = e;
	}
	if (_l) ship_unlock(list);
	return ret;
}

void
_ship_list_empty_with(int _l, ship_list_t *list, void (*func) (void *data))
{        
	ship_list_entry_t *e = 0;
	if (list) {
		if (_l) ship_lock(list);
		e = list->entries;
		list->entries = 0;
		while (e) {
			ship_list_entry_t *n = e->next;
			func(e->data);
			freez(e);
			e = n;
		}
		if (_l) ship_unlock(list);
	}
}

/* empties the list, does not delete data */
void 
_ship_list_clear(int _l, ship_list_t *list)
{        
	ship_list_entry_t *e = 0;
	if (list) {
		if (_l) ship_lock(list);
		e = list->entries;
		list->entries = 0;
		while (e) {
			ship_list_entry_t *n = e->next;
			freez(e);
			e = n;
		}
		if (_l) ship_unlock(list);
	}
}

/* empties the list, deleting (freez) all data */
void 
_ship_list_empty_free(int _l, ship_list_t *list)
{        
	_ship_list_empty_with(_l, list, free);
}

/************** token'ze & string handling ***************/

/* 
   tries to find a case-insensitive token from a list. 
   
   e.g. list: "hello:man: this :iS: Great:whoa!", finding the token
   'is' using deliimter ':' will return 3;

   @return -1 if not found.
*/
int
ship_find_token(char *str, char *token, char limiter)
{
	char **tokens = 0;
	int toklen = 0;
	int i = 0;

	if (ship_tokenize_trim(str, strlen(str), &tokens, &toklen, limiter))
		return -1;

	while ((i < toklen) &&
	       strcasecmp(tokens[i], token)) {
		i++;
	}
	
	if (i >= toklen)
		i = -1;
	ship_tokens_free(tokens, toklen);
	return i;
}

void
ship_tokens_free(char **tokens, int len) 
{
	freez_arr(tokens, len);
}

int
ship_tokens_replace(char **tokens, char *str, int pos)
{
	char *ns;
	if ((ns = strdup(str))) {
		if (tokens[pos])
			free(tokens[pos]);
		tokens[pos] = ns;
		return 0;
	} else {
		return -1;
	}
}

int
ship_tokenize_trim(const char *str, int len, char ***tokens, int *toklen, char token)
{
	if (!ship_tokenize(str, len, tokens, toklen, token)) {
		int i;
		for (i=0; i < (*toklen); i++) {
			trim((*tokens)[i]);
		}
		return 0;
	}
	return -1;
}

/* tokenizes -
   
@param str - the string
@param len - the string's length

*/
int
ship_tokenize(const char *str, int len, char ***tokens, int *toklen, char token)
{
	int nr, i;
	const char *tstr;
	const char *ltstr;

	// len .. ?
	if (len < 0) len = strlen(str);

	/* calc number of tokens */
	nr = 1;
	for (tstr = str; tstr < (str+len); tstr++)
		if ((*tstr) == token) nr++;
        
	if (!((*tokens) = (char**)mallocz(sizeof(char*) * (nr+1))))
		return -1;
        
	tstr = str;
	ltstr = tstr;
	i = 0;
	while (i < nr && tstr < (str+len)) {
		if ((*tstr) == token) {
			ASSERT_TRUE((*tokens)[i] = (char*)mallocz(tstr - ltstr + 1), err);
			memcpy((*tokens)[i], ltstr, tstr-ltstr);
			i++;
			ltstr = tstr+1;
		}
		tstr++;
	}
        
	if (i < nr) {
		ASSERT_TRUE((*tokens)[i] = (char*)mallocz(tstr - ltstr + 1), err);
		memcpy((*tokens)[i], ltstr, tstr-ltstr);
	}
        
	*toklen = nr;
	return 0;

 err:
	while (nr > -1) {
		if ((*tokens)[nr-1])
			free((*tokens)[nr-1]);
		nr--;
	}
	free((*tokens));
	return -1;
}

/* flattens an array of strings */
char *
ship_untokenize(char **tokens, int toklen, const char *token, const char *prefix)
{
	char *ret = NULL;
	int i, len;
        
	len = 0;
	for (i=0; i < toklen; i++) {
		len += strlen(tokens[i]) + strlen(token);
	}
	len ++;
	if (prefix)
		len += strlen(prefix);
        
	if ((ret = (char*)mallocz(len))) {
		if (prefix)
			strcat(ret, prefix);
                
		for (i=0; i < toklen; i++) {
			strcat(ret, tokens[i]);
			if (i < toklen-1) {
				strcat(ret, token);
			}
		}
                
		ret[len-1] = 0;
	}

	return ret;
}

char *
strdupz(const char *str) 
{
	if (!str)
		return NULL;
	else 
		return strdup(str);
}

/* dups & trims a string */
char *
strdup_trim(char *str)
{
	int s = 0;
	int e = 0;
	char *ret;
	while (str[s] != 0 && 
	       (str[s] == ' ' || 
		str[s] == '\n' || 
		str[s] == '\r' || 
		str[s] == '\t'))
		s++;

	e = strlen(str)-1;
	while (e > s &&
	       (str[e] == ' ' || 
		str[e] == '\n' || 
		str[e] == '\r' || 
		str[e] == '\t'))
		e--;

	ret = (char*)mallocz(e-s+2);
	if (ret)
		memcpy(ret, str+s, e-s+1);

	return ret;
}

/* checks whether the string is something that could be seen as
   'true' */
int
ship_is_true(const char* tmp)
{
	if ((strlen(tmp) > 0) &&
	    (*tmp == '1' || 
	     tolower(*tmp) == 'y' ||
	     tolower(*tmp) == 't'))
		return 1;
	return 0;
}
		
/* trims a string */
char *
trim(char *str)
{
	int s = 0;
	int e = 0;

	if (!str) 
		return str;

	while (str[s] != 0 && 
	       (str[s] == ' ' || 
		str[s] == '\n' || 
		str[s] == '\r' || 
		str[s] == '\t'))
		s++;
	
	e = strlen(str)-1;
	while (e > s &&
	       (str[e] == ' ' ||
		str[e] == '\n' ||
		str[e] == '\r' ||
		str[e] == '\t'))
		e--;

	if (str[e+1])
		str[e+1] = 0;
	if (s) {
		e = -1;
		do { e++; str[e] = str[e+s]; } while (str[e+s]);
		//memcpy(str, str+s, e-s+2);
	}
	return str;
}

int 
str_startswith(const char *str, const char *token)
{
	if (!str || !token)
		return 0;
	return !strncmp(str, token, strlen(token));
}

char *
strstr_after(char *str, char *token)
{
	char *ret;
	if (!str || !token)
		return 0;
	ret = strstr(str, token);
	if (ret)
		ret += strlen(token);
	return ret;
}

char *
memmem_after(char *str, int len, char *token, int len2)
{
	char *ret;
	if (!str || !token)
		return 0;
	ret = (char*)memmem(str, len, token, len2);
	if (ret)
		ret += len2;
	return ret;
}

char *
replace_end(char *str, int *buflen, int *datalen, char *end, char *newend)
{
	if (strlen(str) < strlen(end))
		return str;
	
	if (strcmp(&(str[strlen(str) - strlen(end)]), end))
		return str;
	
	str[strlen(str) - strlen(end)] = 0;
	(*datalen) -= strlen(end);

	str = append_str(newend, str, buflen, datalen);
	return str;
}

char *
append_mem(const char *str, int strlen, char *buf, int *buflen, int *datalen)
{
	if (!str)
		return buf;
	if (!buf || (*buflen - *datalen - 1) < strlen) {
		int newlen = *buflen + strlen + 80;
		char *tmp = mallocz(newlen+1);
		if (!tmp)
			return 0;
		if (buf) {
			memcpy(tmp, buf, *datalen);
		}
		*buflen = newlen;
		free(buf);
		buf = tmp;
	}
	
	memcpy(buf + *datalen, str, strlen);
	*datalen += strlen;
	return buf;
}

int 
append_str2(char **str, char *buf)
{
	void *tmp = 0;
	if (!buf)
		return 0;
	
	if (!*str) {
		ASSERT_TRUE(tmp = strdup(buf), err);
	} else {
		ASSERT_TRUE(tmp = mallocz(strlen(*str) + strlen(buf) + 1), err);
		strcat(tmp, *str);
		strcat(tmp, buf);
		free(*str);
	}
	*str = tmp;
	return 0;
 err:
	return -1;
}

char *
append_str(const char *str, char *buf, int *buflen, int *datalen)
{
	if (!str)
		return buf;
	else
		return append_mem(str, strlen(str), buf, buflen, datalen);
}

char *
combine_str(const char *str1, const char *str2)
{
	char *ret = 0;
	if ((ret = mallocz(strlen(str1) + strlen(str2) + 1))) {
		strcat(ret, str1);
		strcat(ret, str2);
	}
	return ret;
}

/********** The HT stuff **************/

ship_ht2_t *
ship_ht2_new()
{
	return ship_ht_new();
}

void 
ship_ht2_free(ship_ht2_t *ht)
{
	ship_ht_t *tmp = 0;
	ship_lock(ht);
	
	while ((tmp = ship_ht_pop(ht))) {
		ship_ht_clear(tmp);
		ship_list_free(tmp);
	}
	ship_list_free(ht);
}

void *
ship_ht2_put_string(ship_ht2_t *ht, char *key, char *key2, void *val)
{
	ship_ht_t *tmp = 0;
	ship_lock(ht);
	
	tmp = ship_ht_get_string(ht, key);
	if (!tmp) {
		tmp = ship_ht_new();
		ship_ht_put_string(ht, key, tmp);
	}

	if (tmp) {
		ship_ht_put_string(tmp, key2, val);
	} else
		val = 0;
	ship_unlock(ht);
	return val;
}

void *
ship_ht2_get_string(ship_ht2_t *ht, char *key, char *key2)
{
	ship_ht_t *tmp = 0;
	void *ret = 0;
	
	ship_lock(ht);
	if ((tmp = ship_ht_get_string(ht, key))) {
		ret = ship_ht_get_string(tmp, key2);
	}
	ship_unlock(ht);
	return ret;
}

void *
ship_ht2_remove_string(ship_ht2_t *ht, char *key, char *key2)
{
	ship_ht_t *tmp = 0;
	void *ret = 0;
	
	ship_lock(ht);
	if ((tmp = ship_ht_get_string(ht, key))) {
		ret = ship_ht_remove_string(tmp, key2);
		if (!ship_ht_first(tmp)) {
			tmp = ship_ht_remove_string(ht, key);
			ship_ht_free(tmp);
		}
	}
	ship_unlock(ht);
	return ret;
}

void *
ship_ht2_pop(ship_ht2_t *ht)
{
	ship_ht_t *tmp = 0;
	void *ret = 0;
	
	ship_lock(ht);
	while (!ret && (tmp = ship_ht_first(ht))) {
		if (!(ret = ship_ht_pop(tmp))) {
			ship_ht_remove(ht, tmp);
			ship_ht_free(tmp);
		}
	}
	ship_unlock(ht);
	return ret;
}

ship_list_t *
ship_ht2_keys(ship_ht2_t *ht, char *key)
{
	ship_ht_t *tmp = 0;
	ship_list_t *ret = 0;
	
	ship_lock(ht);
	if ((tmp = ship_ht_get_string(ht, key))) {
		ret = ship_ht_keys(tmp);
	} else
		ret = ship_list_new();
	ship_unlock(ht);
	return ret;
}




static ship_ht_entry_t *
ship_ht_get_entry(ship_ht_t *ht, const char *key)
{
	ship_ht_entry_t *e = NULL;
	void *ptr = 0;
	ship_lock(ht);
	while (!e && (e = ship_list_next(ht, &ptr))) {
		if (strcmp(key, e->key))
			e = NULL;
	}

	ship_unlock(ht);
	return e;
}

ship_ht_t * 
ship_ht_new()
{
	return ship_list_new();
}

void 
ship_ht_free(ship_ht_t *ht)
{
	ship_ht_clear(ht);
	ship_list_free(ht);
}

void *
ship_ht_put_ptr(ship_ht_t *ht, void *key, void *val)
{
	char buf[64];
	sprintf(buf, "ptr:%x", (unsigned int)key);
	return ship_ht_put_string(ht, buf, val);
}

void *
ship_ht_put_int(ship_ht_t *ht, int key, void *val)
{
	char buf[64];
	sprintf(buf, "int:%d", key);
	return ship_ht_put_string(ht, buf, val);
}

void *
ship_ht_put_string(ship_ht_t *ht, const char *key, void *val)
{
	ship_ht_entry_t *e;
	void *ptr = 0;
	
	if (!val)
		return ptr;

	ship_lock(ht);	
	if (!(e = ship_ht_get_entry(ht, key)) && 
	    (e = mallocz(sizeof(ship_ht_entry_t)))) {
		if (!(e->key = strdup(key))) {
			freez(e);
		} else {
			ship_list_add(ht, e);
		}
	}
	
	if (e) {
		e->value = val;
		ptr = val;
	} else
		ptr = NULL;

	ship_unlock(ht);
	return ptr;
}

void * 
ship_ht_get_ptr(ship_ht_t *ht, const void *key)
{
	char buf[64];
	sprintf(buf, "ptr:%x", (unsigned int)key);
	return ship_ht_get_string(ht, buf);
}

void * 
ship_ht_get_int(ship_ht_t *ht, const int key)
{
	char buf[64];
	sprintf(buf, "int:%d", key);
	return ship_ht_get_string(ht, buf);
}

void * 
ship_ht_get_string(ship_ht_t *ht, const char *key)
{
	ship_ht_entry_t *e;
	void *ptr = 0;

	ship_lock(ht);
	if ((e = ship_ht_get_entry(ht, key))) {
		ptr = e->value;
	}
	ship_unlock(ht);
	return ptr;
}

void * 
ship_ht_pop(ship_ht_t *ht)
{
	ship_ht_entry_t *e;
	void *ptr = 0;

	ship_lock(ht);
	if ((e = ship_list_pop(ht))) {
		ptr = e->value;
		freez(e->key);
		freez(e);
	}
	ship_unlock(ht);
	return ptr;
}

void * 
ship_ht_remove_ptr(ship_ht_t *ht, void *key)
{
	char buf[64];
	sprintf(buf, "ptr:%x", (unsigned int)key);
	return ship_ht_remove_string(ht, buf);
}

void * 
ship_ht_remove_int(ship_ht_t *ht, int key)
{
	char buf[64];
	sprintf(buf, "int:%d", key);
	return ship_ht_remove_string(ht, buf);
}

void * 
ship_ht_remove(ship_ht_t *ht, void *value)
{
	ship_ht_entry_t *e;
	void *ptr = 0, *ret = 0;
	ship_lock(ht);
	while (!ret && (e = ship_list_next(ht, &ptr))) {
		if (value == e->value) {
			ret = value;
			ship_list_remove(ht, e);
			freez(e->key);
			freez(e);			
		}
	}
	ship_unlock(ht);
	return ret;
}

void * 
ship_ht_remove_string(ship_ht_t *ht, const char *key)
{
	ship_ht_entry_t *e;
	void *ptr = 0;
	ship_lock(ht);
	if ((e = ship_ht_get_entry(ht, key))) {
		ptr = e->value;
		ship_list_remove(ht, e);
		freez(e->key);
		freez(e);
	}

	ship_unlock(ht);
	return ptr;
}

void 
ship_ht_clear(ship_ht_t *ht)
{
	ship_ht_entry_t *e = NULL;
	ship_lock(ht);
	while ((e = ship_list_pop(ht))) {
		freez(e->key);
		freez(e);
	}
	ship_unlock(ht);
}

void *
ship_ht_first(ship_ht_t *ht)
{
	ship_ht_entry_t *e = ship_list_first(ht);
	if (e)
		return e->value;
	else
		return NULL;
}

void *
ship_ht_next(ship_ht_t *ht, void **ptr)
{
	ship_ht_entry_t *e = ship_list_next(ht, ptr);
	if (e)
		return e->value;
	else
		return NULL;
}

void *
ship_ht_next_with_key(ship_ht_t *ht, void **ptr, char **key)
{
	ship_ht_entry_t *e = ship_list_next(ht, ptr);
	if (e) {
		*key = e->key;
		return e->value;
	} else
		return NULL;
}

void 
ship_ht_empty_free(ship_ht_t *ht)
{
	ship_ht_entry_t *e = NULL;
	ship_lock(ht);
	while ((e = ship_list_pop(ht))) {
		freez(e->key);
		freez(e->value);
		freez(e);
	}
	ship_unlock(ht);
}

void 
ship_ht_empty_free_with(ship_ht_t *ht, void (*func) (void *))
{
	ship_ht_entry_t *e = NULL;
	ship_lock(ht);
	while ((e = ship_list_pop(ht))) {
		freez(e->key);
		func(e->value);
		freez(e);
	}
	ship_unlock(ht);
}

void
ship_ht_values_add(ship_ht_t *ht, ship_list_t *ret)
{
	ship_ht_entry_t *e = NULL;
	void *ptr = 0;
	while ((e = ship_list_next(ht, &ptr))) {
		ship_list_add(ret, e->value);
	}
	ship_unlock(ht);
}

ship_list_t * 
ship_ht_values(ship_ht_t *ht)
{
	ship_list_t *ret = ship_list_new();
	if (!ret)
		return ret;
	ship_ht_values_add(ht, ret);
	return ret;
}

void
ship_ht_keys_add(ship_ht_t *ht, ship_list_t *ret)
{
	ship_ht_entry_t *e = NULL;
	void *ptr = 0;
	ship_lock(ht);
	while ((e = ship_list_next(ht, &ptr))) {
		ship_list_add(ret, strdup(e->key));
	}
	ship_unlock(ht);
}

int
ship_ht_has_value(ship_ht_t *ht, void *val)
{
	int ret = 0;
	ship_ht_entry_t *e = NULL;
	void *ptr = 0;
	ship_lock(ht);
	while (!ret && (e = ship_list_next(ht, &ptr))) {
		if (e->value == val)
			ret = 1;
	}
	ship_unlock(ht);
	return ret;
}

ship_list_t * 
ship_ht_keys(ship_ht_t *ht)
{
	ship_list_t *ret = ship_list_new();
	if (!ret)
		return ret;
	ship_ht_keys_add(ht, ret);
	return ret;
}

/* decodes an url-decoded string */
void
ship_urldecode(char *str)
{
	char *end = str + strlen(str);
	while (str < end) {
		if ((*str) == '+') {
			(*str) = ' ';
		} else if ((*str) == '%' && ((end - str) > 2)) {
			int val = 0, doagain = 1;
		again:
			str++;
			if ((*str) >= '0' && (*str) <= '9') {
				val = (val << 4 ) + (*str) - '0';
			} else if (tolower(*str) >= 'a' && tolower(*str) <= 'f') {
				val = (val << 4 ) + 10 + tolower(*str) - 'a';
			} else
				goto skip;
			if (doagain) {
				doagain = 0;
				goto again;
			}
			
			str -= 2;
			*(str) = (char)(0xff & val);
			memcpy(str+1, str+3, end-str-3);
			end -=2;
			end[0] = 0;
		}
	skip:
		str++;
	}
}

/* decodes an url-decoded string */
char *
ship_urlencode(char *str)
{
	char *ret = 0;
	int len = 0, size = strlen(str)*2;
	char c = 0;

	ret = mallocz(size+1);
	while (ret && (c = str[0])) {
		char tmp[4];
		char *r2 = 0;

		if (strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_.!~*'()0123456789", c)) {
			tmp[0] = c;
			tmp[1] = 0;
		} else if (c == ' ') {
			tmp[0] = '+';
			tmp[1] = 0;
		} else {
			int t, p=1;
			tmp[0] = '%';
			
			t = (0x0f & (c >> 4));
		again:
			if (t < 10)
				tmp[p] = '0' + t;
			else
				tmp[p] = 'A' + t - 10;
			p++;
			t = (0x0f & c);
			if (p < 3)
				goto again;
			tmp[3] = 0;
		}

		r2 = append_str(tmp, ret, &size, &len);
		if (r2)
			ret = r2;
		else
			freez(ret);
		str++;
	}
	return ret;
}

/* decodes an url-decoded string */
char *
ship_pangoify(char *str)
{
	char *ret = 0;
	int len = 0, size = strlen(str) + 10;
	char c = 0;

	ret = mallocz(size+1);
	while (ret && (c = str[0])) {
		char tmp[10];
		char *r2 = 0;

		switch (c) {
		case '<':
			strcpy(tmp, "&lt;");
			break;
		case '>':
			strcpy(tmp, "&gt;");
			break;
		default:
			tmp[0] = c;
			tmp[1] = 0;
			break;
		}
		r2 = append_str(tmp, ret, &size, &len);
		if (r2)
			ret = r2;
		else
			freez(ret);
		str++;
	}
	return ret;
}

char *
ship_addparam_urlencode(char *key, char *val, char *buf, int *size, int *len)
{
	char *tmp = 0, *obuf = buf;
	char *uk = 0, *uv = 0;
	
	ASSERT_TRUE(uk = ship_urlencode(key), err);
	ASSERT_TRUE(uv = ship_urlencode(val), err);
	if (*len) {
		ASSERT_TRUE(tmp = append_str("&", buf, size, len), err);
		buf = tmp;
	}
	ASSERT_TRUE(tmp = append_str(uk, buf, size, len), err);
	buf = tmp;
	ASSERT_TRUE(tmp = append_str("=", buf, size, len), err);
	buf = tmp;
	ASSERT_TRUE(tmp = append_str(uv, buf, size, len), err);
	buf = tmp;
 err:
	if (!tmp && obuf != buf)
		freez(buf);
	freez(uk);
	freez(uv);
	return buf;
}


time_t 
ship_parse_time(char *str)
{
	struct tm tm;
	memset(&tm, 0, sizeof(struct tm));
	
	if (strptime(str, "%Y-%m-%dT%H:%M:%S%z", &tm) ||
	    strptime(str, "%Y-%m-%dT%H:%M:%SZ", &tm) ||
	    strptime(str, "%Y-%m-%dT%H:%M:%S", &tm)) {
		
		/* this seems clumsy, but accounts for daylight
		   savings etc.. */
		long int tz = tm.tm_gmtoff;
		return timegm(&tm) - tz;
	}
	return 0;
}

int 
ship_format_time(time_t time, char* buf, size_t len)
{
	struct tm tm;
	memset(&tm, 0, sizeof(struct tm));
	
	if (!localtime_r(&time, &tm))
		return 0;

	return strftime(buf, len, "%Y-%m-%dT%H:%M:%S%z", &tm);
}

int 
ship_format_time_human(time_t time, char* buf, size_t len)
{
	struct tm tm;
	memset(&tm, 0, sizeof(struct tm));

	if (!localtime_r(&time, &tm))
		return 0;

	return strftime(buf, len, "%d %b %Y, %H:%M:%S (%z)", &tm);
}

int 
ship_format_time_human2(time_t time, char* buf, size_t len)
{
	struct tm tm;
	memset(&tm, 0, sizeof(struct tm));

	if (!localtime_r(&time, &tm))
		return 0;

	return strftime(buf, len, "%a, %e %b %Y %H:%M:%S %z", &tm);
}

/* crypto functions */

int
ship_get_random(unsigned char *random, size_t len) 
{
	FILE* f = NULL;
	int ret = -1;
		
	if ((f = fopen("/dev/urandom", "r")) == NULL) {
		LOG_ERROR("open urandom error\n");
		goto err;
	}
	
	if ((fread(random, 1, len, f)) == 0) {
		LOG_ERROR("urandom error\n");
		goto err;
	}
	ret = 0;	
 err:
	if (f) 
		fclose(f);
	return ret;
}

/* read a file into a buffer */
int
ship_load_file(const char* file, char **rbuf, int *len)
{
	char *buf = 0;
	struct stat sdata;
	int ret = -1;
	FILE *f = 0;
	
	ASSERT_ZERO(stat(file, &sdata), err);
	ASSERT_TRUE(buf = malloc(sdata.st_size), err);
	ASSERT_TRUE(f = fopen(file, "r"), err);
	ASSERT_TRUE(sdata.st_size == fread(buf, 1, sdata.st_size, f), err);

	(*rbuf) = buf;
	buf = 0;
	
	*len = sdata.st_size;
	ret = 0;
 err:
	if (f)
		fclose(f);
	freez(buf);
	return ret;
}

#ifdef REMOTE_DEBUG
#include "p2pship_version.h"


void 
ship_remote_report(const char *template, ...)
{
	char *buf = 0, *buf2 = 0;
	va_list ap;
	va_start(ap, template);
	
	if ((buf = mallocz(1048)) && (buf2 = mallocz(2048))) {
		int len = vsprintf(buf, template, ap);
		ship_list_t *idents = 0;
		
		/* add to the reports - ip, list of usernames
		   configured */

		/* this is dangerous, but has to be so .. */
		
		strcat(buf2, "# report:\n");
		strcat(buf2, "client_version: ");
		strcat(buf2, P2PSHIP_BUILD_VERSION);
		strcat(buf2, "\n");
		idents = ident_get_identities();
		if (idents) {
			ship_lock(idents);
			char tmp[64];
			void *ptr = 0;
			ident_t *ident = 0;
			time_t now;
			time(&now);
			
			strcat(buf2, "# idents:\n");
			while (ident = ship_list_next(idents, &ptr)) {
				ship_lock(ident);
				strcat(buf2, ident->sip_aor);
				strcat(buf2, ";");
				strcat(buf2, ident->contact_addr.addr);
				
				sprintf(tmp, ":port=%d;s=%d;TO=%d\n", ident->contact_addr.port, ident->state, 
					ident->reg_time + ident->expire - now);
				strcat(buf2, tmp);
				ship_unlock(ident);
			}
			ship_unlock(idents);
		}
		strcat(buf2, "# data:\n");
		strcat(buf2, buf);
		strcat(buf2, "\n# end: report\n");
		
		struct sockaddr *sa = 0;
		socklen_t salen = 0;
		
		if (getaddrinfolock && remote_debug_addr && !ident_addr_str_to_sa_lookup(remote_debug_addr/* remote addr */, &sa, &salen)) {
			netio_packet_anon_send(buf2, strlen(buf2), sa, salen);
		}
		freez(sa);
	}
	freez(buf);
	freez(buf2);
	va_end(ap);
}

#endif



static void
ship_read_stream(FILE *f, void *data,
		 void (*cb_content_line) (void *data, int lc, char *key, char *value, char *line),
		 void (*cb_ignore_line) (void *data, int lc, char *content, char *line))
{
	/* load file .. */
	int lc = 0;
	char *buf = NULL;
	size_t len = 0;
	ssize_t got = 0;
	while ((got = getline(&buf, &len, f)) > -1) {
		char *key;
		char k = 0;
		lc++;
		key = strdup_trim(buf);
		k = *key;
		if (str_startswith(key, "//") || str_startswith(key, "/*"))
			k = '#';
		
		/* check what we've got.. */
		switch (k) {
		case '#':
		case ';':
		case 0:
			if (cb_ignore_line)
				cb_ignore_line(data, lc, key, buf);
			break;
		default: 
			if (cb_content_line) {
				/* ok, find the =-sign */
				char *value = strstr(key, "=");
				if (!value) {
					cb_content_line(data, lc, key, value, buf);
				} else {
					*(value++) = 0;
					value = trim(value);
					key = trim(key);
					cb_content_line(data, lc, key, value, buf);
				}
			}
			break;
		}
		freez(key);
	}
	freez(buf);
}

/* file reading .. */
int
ship_read_file(char *filename, void *data,
	       void (*cb_content_line) (void *data, int lc, char *key, char *value, char *line),
	       void (*cb_ignore_line) (void *data, int lc, char *content, char *line))
{
	/* load file .. */
	FILE *f = fopen(filename, "r");
	if (f) {
		ship_read_stream(f, data, cb_content_line, cb_ignore_line);
		fclose(f);
		return 0;
	} else {
		USER_ERROR("Failed to open configuration file %s\n", filename);
		return -1;
	}
}

/* file reading .. */
int
ship_read_mem(char *buf, int buflen, void *data,
	      void (*cb_content_line) (void *data, int lc, char *key, char *value, char *line),
	      void (*cb_ignore_line) (void *data, int lc, char *content, char *line))
{
	/* load file .. */
	FILE *f = (FILE *)fmemopen(buf, buflen, "r");
	if (f) {
		ship_read_stream(f, data, cb_content_line, cb_ignore_line);
		fclose(f);
		return 0;
	} else {
		USER_ERROR("Failed to read mem\n");
		return -1;
	}
}

/* lists the content of some directory */
ship_list_t*
ship_list_dir(const char *dir, const char *pattern, const int fullpath)
{
	glob_t gl;
	ship_list_t *ret = 0;
	char *p = NULL;

	ASSERT_TRUE(ret = ship_list_new(), err);
	ASSERT_TRUE(p = mallocz(strlen(dir) + 5 + strlen(pattern)), err);
	strcpy(p, dir);
	if (p[strlen(p)-1] != '/')
		strcat(p, "/");
	strcat(p, pattern);
	if (!glob(p, 0, NULL, &gl)) {
		int l;
		for (l = 0; l < gl.gl_pathc; l++) {
			//regex_t exp;
			char *shortn = strrchr(gl.gl_pathv[l], '/');

			if (shortn && !fullpath) 
				shortn++;
			else 
				shortn = gl.gl_pathv[l];

			/*
			printf("will do %s\n", shortn);
			if (pattern && !regcomp(&exp, pattern, REG_ICASE)) {
				if (regexec(&exp, shortn, 0, NULL, 0))
					shortn = NULL;
				regfree(&exp);
			}
			printf("will do ----- %s\n", shortn);
			*/
			
			if (shortn)
				ship_list_add(ret, strdup(shortn));

			free(gl.gl_pathv[l]);
		}
		free(gl.gl_pathv);
	}
 err:
	freez(p);
	return ret;
}

/* returns the given filename in the current process owner's home
   directory */
int
ship_get_homedir_file(char *filename, char **target)
{
	struct passwd *pw = 0;	
	int ret = -1;

	if ((pw = getpwuid(getuid())) == NULL || !pw->pw_dir)
		goto err;
	
	if (!((*target) = mallocz(strlen(pw->pw_dir) + strlen(filename) + 2)))
		goto err;

	strcpy(*target, pw->pw_dir);
	strcat(*target, "/");
	strcat(*target, filename);
	ret = 0;
 err:
	return ret;
}

int
ship_ensure_file(char *filename, char *initial_data)
{
	struct stat sdata;
	int ret = 0;
	FILE *f = NULL;
	
	if (stat(filename, &sdata)) {
		/* create the directory recursively */
		char *p = strchr(filename, '/');
		while (p) {
			p[0] = 0;
			if (p != filename && stat(filename, &sdata))
				ret = mkdir(filename, S_IRWXU);
			p[0] = '/';
			p = strchr(p+1, '/');
			
			ASSERT_ZERO(ret, err);
		}
		if ((f = fopen(filename, "w")))
			fwrite(initial_data, sizeof(char), strlen(initial_data), f);
		else
			ret = -2;
	}
 err:
	if (f)
		fclose(f);	
	return ret;
}

int
ship_ensure_dir(char *filename)
{
	struct stat sdata;
	int ret = 0;
	if (stat(filename, &sdata)) {
		/* create the directory recursively */
		char *p = strchr(filename, '/');
		while (p) {
			p[0] = 0;
			if (p != filename && stat(filename, &sdata))
				ret = mkdir(filename, S_IRWXU);
			p[0] = '/';
			p = strchr(p+1, '/');
			
			ASSERT_ZERO(ret, err);
		}
		
		if (stat(filename, &sdata))
			ret = mkdir(filename, S_IRWXU);
	}
 err:
	return ret;
}

int
ship_move(const char *from, const char *to)
{
	int ret = 0;
	ret = rename(from, to);
	if (ret == -1) {
		char *buf;
		int len = 4096;
		FILE *f = 0, *f2 = 0;

		/* do a manual copy */
		buf = malloc(len);
		if (buf && (f = fopen(from, "r")) && (f2 = fopen(to, "w"))) {
			int r = 0;
			while ((r = fread(buf, sizeof(char), len, f)) > 0) {
				fwrite(buf, sizeof(char), r, f2);
			}
			unlink(from);
			ret = 0;
		}
		freez(buf);
		if (f)
			fclose(f);
		if (f2)
			fclose(f2);
	}
	return ret;
}

int
fwrite_all(const char *data, const int len, FILE *f)
{
	int w = 0, s = 0;
	do {
		w = fwrite(data+s, sizeof(char), len-s, f);
		if (w < 1)
			break;
		s += w;
	} while (s < len);
	return s;
}


/////////////////////////////////////////////////////////
/////////////////////////////////////// generic xml-only


/* evals an xpath expression (either with/without //-prefix) & returns
   the result */
xmlXPathObjectPtr 
ship_getnodeset (xmlDocPtr doc, xmlChar *xpath)
{
	xmlXPathContextPtr context = NULL;
	xmlXPathObjectPtr result = NULL;
	xmlChar *realpath = NULL;
	const char *prefix = "//";

	if (strstr((char*)xpath, prefix) != (char*)xpath) {
		ASSERT_TRUE(realpath = (xmlChar*)malloc(strlen((char*)prefix) + strlen((char*)xpath) + 1), err);
		strcpy((char*)realpath, (char*)prefix);
		strcat((char*)realpath, (char*)xpath);
	} else {
		realpath = xpath;
	}
	
	ASSERT_TRUE(context = xmlXPathNewContext(doc), err);
	ASSERT_TRUE(result = xmlXPathEvalExpression(realpath, context), err);
	
	if (!xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		xmlXPathFreeObject(result);
		result = NULL;
	}
 err:
	if (context) xmlXPathFreeContext(context);
	if (realpath != xpath)
		freez(realpath);
	
	return result;
}

/* fetches an xpath obj from the given doc */
char*
ship_xml_get_xpath_string_req(xmlDocPtr doc, char *key, int req)
{
	char *ret = NULL;
	xmlNodeSetPtr nodeset = NULL;
	xmlXPathObjectPtr result = NULL;
	
	ASSERT_TRUE(result = ship_getnodeset(doc, (xmlChar *)key), err);
	nodeset = result->nodesetval;
	if (req > 0 && nodeset->nodeNr != req) {
		goto err;
	}
	
	ret = (char*)xmlNodeListGetString(doc, nodeset->nodeTab[0]->xmlChildrenNode, 1);
 err:
	if (result)
		xmlXPathFreeObject(result);
	
	return ret;
}

/* fetches a child's value */
char*
ship_xml_get_child_field_dup(xmlNodePtr node, char *key)
{
	char *ret = ship_xml_get_child_field(node, key);
	if (ret)
		return strdup(ret);
	return NULL;
}

/* checks if an attribute is a certain value */
int
ship_xml_attr_is(xmlNodePtr node, char *key, char *value)
{
	int ret = 0;
	xmlChar *result = 0;
	result = xmlGetProp(node, (unsigned char*)key);
	if (result && !strcmp((char*)result, value))
		ret = 1;
	if (result)
		xmlFree(result);
	return ret;
}

/* fetches a child's value */
char*
ship_xml_get_child_field(xmlNodePtr node, char *key)
{
	node = ship_xml_get_child(node, key);
	if (node) {
		return (char*)xmlNodeListGetString(node->doc, node->xmlChildrenNode, 1);
	}
	return NULL;
}

/* fetches a child element */
xmlNodePtr
ship_xml_get_child(xmlNodePtr node, char *key)
{
	for (node = node->children; node; node = node->next) {
		if (!strcmp((char*)node->name, key)) {
			return node;
		}
	}	
	return NULL;
}

int
ship_xml_get_child_addr_list(xmlNodePtr node, char *key, ship_list_t *addr_list)
{
	xmlNodePtr cur_node = NULL;
	
	for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
		if (!strcmp((char*)cur_node->name, key)) {				
			addr_t *tempaddr = (addr_t*)mallocz(sizeof(addr_t));
			
			if (!tempaddr)
				continue;

			char *str = (char*)xmlNodeListGetString(cur_node->doc, cur_node->xmlChildrenNode, 1);
			if (!str || ident_addr_str_to_addr(str, tempaddr)) {
				freez(tempaddr);
				freez(str);
				continue;
			}
			freez(str);
			ship_list_add(addr_list, tempaddr);
		}
	}	

	return 0;
}

int
ship_load_xml_file(const char *docname, int (*func) (xmlNodePtr, void *), void *ptr)
{
	char *buf = 0;
	int ret = -1, len;

	ASSERT_ZERO(ship_load_file(docname, &buf, &len), err);
	ret = ship_load_xml_mem(buf, len, func, ptr);
 err:
	if (ret) {
		LOG_ERROR("Error loading XML document: %s\n", docname);
	}
	freez(buf);
	return ret;
}

int
ship_load_xml_mem(const char *data, int datalen, int (*func) (xmlNodePtr, void *), void *ptr)
{
	xmlDocPtr doc = NULL;
	int result = -1;
	xmlNodePtr cur = NULL;
	
	doc = xmlParseMemory(data, datalen);
	if (doc == NULL){
		LOG_WARN("Invalid XML document\n");
		goto err;
	}

	ASSERT_TRUE(cur = xmlDocGetRootElement(doc), err);
	result = func(cur, ptr);
 err:
	if (doc) xmlFreeDoc(doc);
	//xmlCleanupParser();
	return result;
}


/**
 * object handling
 */

void 
ship_obj_free(void *param) 
{
	ship_obj_t *obj = (ship_obj_t *)param;
	if (obj) {
		obj->_ship_obj_type.obj_free(obj);
		ship_lock_free(&(obj->_ship_obj_lock));
		LOCK_FREE(obj->_ship_ref_lock);
		free(obj);
	}
}

ship_obj_t*
ship_obj_new(struct ship_obj_type_s type, void *param) 
{
	ship_obj_t *obj = NULL;
	
	ASSERT_TRUE(obj = mallocz(type.obj_size), err);
	ASSERT_ZERO(ship_lock_new(&obj->_ship_obj_lock), err);
	LOCK_INIT(obj->_ship_ref_lock);
	ASSERT_TRUE(obj->_ship_ref_lock, err);
	
	obj->_ship_obj_type.obj_init = type.obj_init;
#ifdef REF_DEBUG
	obj->_ship_obj_type.obj_name = type.obj_name;
#endif
	obj->_ship_obj_type.obj_free = type.obj_free;
	obj->_ship_obj_type.obj_size = type.obj_size;
	
	ASSERT_ZERO(obj->_ship_obj_type.obj_init(obj, param), err);
	ship_obj_ref(obj);
	return obj;	
 err:
	ship_obj_free(obj);
	return NULL;
}

void 
_ship_obj_unref(void *param) 
{
	ship_obj_t *obj = (ship_obj_t *)param;
	if (!obj)
		return;

        LOCK_ACQ(obj->_ship_ref_lock);
	obj->_ship_obj_ref--;
	if (obj->_ship_obj_ref < 1) {
#ifdef REF_DEBUG
		USER_PRINT("**** freeing an '%s' obj [%08x] of size '%d'**\n", obj->_ship_obj_type.obj_name, obj, obj->_ship_obj_type.obj_size);
		if (ship_locked(obj)) {
			PANIC("unreffing an '%s' obj [%08x] while locked!", obj->_ship_obj_type.obj_name, obj, obj->_ship_obj_type.obj_size);
		}

#elif defined REF_DEBUG2
		ship_debug_delref(obj);
#endif
		ship_obj_free(obj);
	} else {

#ifdef REF_DEBUG
		USER_PRINT("-- unreffing an '%s' obj [%08x] of size '%d', count %d\n", obj->_ship_obj_type.obj_name, obj, obj->_ship_obj_type.obj_size, obj->_ship_obj_ref);
#endif
                //obj->_ship_obj_lock.lc = 1; // release it totally!
		LOCK_RELEASE(obj->_ship_ref_lock);
	}
}

void 
_ship_obj_ref(void *param) 
{
	ship_obj_t *obj = (ship_obj_t *)param;
	if (!obj)
		return;
        LOCK_ACQ(obj->_ship_ref_lock);
	obj->_ship_obj_ref++;
#ifdef REF_DEBUG
	USER_PRINT("++ reffing an '%s' obj [%08x] of size '%d', count %d\n", obj->_ship_obj_type.obj_name, obj, obj->_ship_obj_type.obj_size, obj->_ship_obj_ref);
#endif
	LOCK_RELEASE(obj->_ship_ref_lock);
}

void
ship_lenbuf_free(ship_lenbuf_t *buf)
{
	if (buf) {
		freez(buf->data);
		free(buf);
	}
}

ship_lenbuf_t*
ship_lenbuf_create_copy(char *data, int len)
{
	ship_lenbuf_t* ret = mallocz(sizeof(ship_lenbuf_t));
	if (ret && (ret->data = mallocz(len+1))) {
		memcpy(ret->data, data, len);
		ret->len = len;
	} else {
		freez(ret);
	}
	return ret;
}


ship_lenbuf_t*
ship_lenbuf_create_ref(char *data, int len)
{
	ship_lenbuf_t* ret = mallocz(sizeof(ship_lenbuf_t));
	if (ret) {
		ret->data = data;
		ret->len = len;
	}
	return ret;
}

/*
 * packing
 */

/* packs a bunch of values into a single pack (void**)
   format: p - pointer, s - string (copy made), i - int,
   l - long, c - char, m - memory buffer (followed by size, copy made)
*/

void **
ship_pack(char *fmt, ...)
{
	va_list ap;
	void **ret = 0;
	int p = 1, s, i, elms = strlen((char*)fmt);
	int vi;
	long vl;
	void *vm;
	
	ASSERT_TRUE(ret = mallocz(sizeof(void*) * (elms+1)), err);
	ASSERT_TRUE(ret[0] = strdup(fmt), err);

	va_start(ap, fmt);
	for (i=0; i < elms; i++) {
		vm = NULL;
		switch (fmt[i]) {
		case 'i':
			vi = (int)va_arg(ap, int);
			vm = &vi;
			s = sizeof(int);
			break;
		case 'l':
			vl = (long)va_arg(ap, long);
			vm = &vl;
			s = sizeof(long);
			break;
		case 'm':
			vm = (void*)va_arg(ap, void*);
			s = (int)va_arg(ap, int);
			break;
		case 's':
			vm = (char*)va_arg(ap, char*);
			if (vm)
				s = strlen((char*)vm)+1;
			break;
		case 'p':
			ret[p] = (void*)va_arg(ap, void*);
			break;
		default:
			PANIC("Invalid pack: %c\n", fmt[i]);
		}
		
		if (vm) {
			ASSERT_TRUE(ret[p] = malloc(s), err2);
			memcpy(ret[p], vm, s);
		}
		p++;
	}
	va_end(ap);
	return ret;
 err2:
	va_end(ap);
 err:
	ship_pack_free(ret);
	return NULL;
}

/* return the number of values unpacked. ownership transferred, can be
   called only once per pack. */
int
ship_unpack(int keep, int elm, void **list, ...)
{
	int i, ret = 0;
	char *fmt;
	va_list ap;
	void *vm;
	
	if (!list || !list[0])
		return ret;

	va_start(ap, list);
	
	fmt = list[0];
	for (i=0; i < strlen(fmt); i++) {
		if (elm > -1 && i != elm)
			continue;

		vm = (void*)va_arg(ap, void*);
		if (!vm)
			continue;

		switch (fmt[i]) {
		case 'i':
			if (list[i+1])
				memcpy(vm, list[i+1], sizeof(int));
			break;
		case 'l':
			if (list[i+1])
				memcpy(vm, list[i+1], sizeof(long));
			break;
		case 'm':
		case 's':
		case 'p':
			*(void**)vm = (void*)list[i+1];
			if (!keep)
				list[i+1] = NULL;
			break;
		default:
			PANIC("Invalid unpack: in '%s' unknown char %c\n", fmt, fmt[i]);
		}

		if (!keep) {
			freez(list[i+1]);
			list[i+1] = NULL;
		}
		ret++;
	}
	va_end(ap);
	return ret;
}

void
ship_pack_free(void **list)
{
	int i;
	char *fmt;
	
	if (!list || !list[0])
		return;
	fmt = list[0];
	for (i=0; i < strlen(fmt); i++) {
		switch (fmt[i]) {
		case 'i':
		case 's':
		case 'm':
		case 'l':
			freez(list[i+1]);
			break;
		}
	}
	free(fmt);
	free(list);
}

#ifdef CONFIG_BLOOMBUDDIES_ENABLED

#include<limits.h>
#include<stdarg.h>

#define SETBIT(a, n) (a[n/CHAR_BIT] |= (1<<(n%CHAR_BIT)))
#define GETBIT(a, n) (a[n/CHAR_BIT] & (1<<(n%CHAR_BIT)))

static unsigned int sax_hash(const char *key)
{
	unsigned int h=0;

	while(*key) h^=(h<<5)+(h>>2)+(unsigned char)*key++;

	return h;
}

static unsigned int sdbm_hash(const char *key)
{
	unsigned int h=0;
	while(*key) h=(unsigned char)*key++ + (h<<6) + (h<<16) - h;
	return h;
}

static ship_bloom_t *ship_bloom_create(size_t size, size_t nfuncs, ...)
{
	ship_bloom_t *bloom;
	va_list l;
	int n;
	
	if(!(bloom=malloc(sizeof(ship_bloom_t)))) return NULL;
	bloom->size_in_bytes = (size+CHAR_BIT-1)/CHAR_BIT;
	if(!(bloom->a=calloc(bloom->size_in_bytes, sizeof(char)))) {
		free(bloom);
		return NULL;
	}
	if(!(bloom->funcs=(hashfunc_t*)malloc(nfuncs*sizeof(hashfunc_t)))) {
		free(bloom->a);
		free(bloom);
		return NULL;
	}

	va_start(l, nfuncs);
	for(n=0; n<nfuncs; ++n) {
		bloom->funcs[n]=va_arg(l, hashfunc_t);
	}
	va_end(l);

	bloom->nfuncs=nfuncs;
	bloom->asize=size;

	return bloom;
}

ship_bloom_t *ship_bloom_new(size_t size)
{
	return ship_bloom_create(size, BLOOM_FUNCS, sax_hash, sdbm_hash);
}

void
ship_bloom_free(ship_bloom_t *bloom)
{
	if (!bloom)
		return;
	free(bloom->a);
	free(bloom->funcs);
	free(bloom);
}

int
ship_bloom_add(ship_bloom_t *bloom, const char *s)
{
	size_t n;

	for(n=0; n<bloom->nfuncs; ++n) {
		SETBIT(bloom->a, bloom->funcs[n](s)%bloom->asize);
	}

	return 0;
}

int 
ship_bloom_check_cert(ship_bloom_t *bloom, X509 *cert)
{
	char *tmp = ship_get_pubkey(cert);
	int ret = 0;
	ret = ship_bloom_check(bloom, tmp);
	freez(tmp);
	return ret;
}

int 
ship_bloom_add_cert(ship_bloom_t *bloom, X509 *cert)
{
	char *tmp = NULL;
	int ret = -1;
	ASSERT_TRUE(tmp = ship_get_pubkey(cert), err);
	ret = ship_bloom_add(bloom, tmp);
 err:
	freez(tmp);
	return ret;
}

int
ship_bloom_check(ship_bloom_t *bloom, const char *s)
{
	size_t n;
	if (!bloom || !s)
		return 0;
	for(n=0; n<bloom->nfuncs; ++n) {
		if(!(GETBIT(bloom->a, bloom->funcs[n](s)%bloom->asize))) return 0;
	}

	return 1;
}

int
ship_bloom_combine_bloom(ship_bloom_t *target, ship_bloom_t *source)
{
	int i;
	if (!target || !source ||
	    (target->asize != source->asize))
		return -1;
	
	for (i=0; i < target->size_in_bytes; i++)
		target->a[i] |= source->a[i];
	return 0;
}

int 
ship_bloom_dump_size(ship_bloom_t *bloom)
{
	if (!bloom)
		return 0;
	int ret = bloom->size_in_bytes * sizeof(char);
	ret += 4; // size in bits
	ret += 2; // number of hashfunctions
	return ret;
}

void
ship_bloom_dump(ship_bloom_t *bloom, char *buf)
{
	if (!bloom)
		return;
	ship_inroll(bloom->asize, buf, 4);
	ship_inroll(bloom->nfuncs, &(buf[4]), 2);
	memcpy(&(buf[6]), bloom->a, bloom->size_in_bytes);
}

ship_bloom_t *
ship_bloom_load(char *buf, int buflen)
{
	ship_bloom_t *ret = 0;
	int size, funcs;
	ASSERT_TRUE(buf, err);
	ASSERT_TRUE(buflen >= 6, err);
	
	ship_unroll(size, buf, 4);
	ship_unroll(funcs, &(buf[4]), 2);
	ASSERT_TRUE(funcs == BLOOM_FUNCS, err);
	ASSERT_TRUE(ret = ship_bloom_new(size), err);
	ASSERT_TRUE(buflen >= (ret->size_in_bytes + 6), err);
	memcpy(ret->a, &(buf[6]), ret->size_in_bytes);
	return ret;
 err:
	ship_bloom_free(ret);
	return NULL;
}

#endif


#ifdef REF_DEBUG2

static ship_ht_t *debug_refs = NULL;

void ship_debug_initref()
{
	debug_refs = ship_ht_new();
}

void ship_debug_delref(void *obj)
{
	ship_list_t *refs = NULL;
	if (!obj) return;
	ship_lock(debug_refs);
	if (refs = ship_ht_remove_ptr(debug_refs, obj)) {
		ship_list_empty_free(refs);
		ship_list_free(refs);
	}
	ship_unlock(debug_refs);
}

void ship_debug_incref(void *obj, const char *file, const int line)
{
	ship_list_t *refs = NULL;
	char *str = NULL;
	ship_obj_t *o = (ship_obj_t *)obj;
	if (!obj) return;
	ship_lock(debug_refs);
	if (!(refs = ship_ht_get_ptr(debug_refs, obj))) {
		refs = ship_list_new();
		ship_ht_put_ptr(debug_refs, obj, refs);
	}
	
	str = mallocz(strlen(file) + 64);
	sprintf(str, "REF    %s:%d (%d)", file, line, o->_ship_obj_ref);
	ship_list_add(refs, str);
	ship_unlock(debug_refs);
}

void ship_debug_decref(void *obj, const char *file, const int line)
{
	ship_list_t *refs = NULL;
	char *str = NULL;
	ship_obj_t *o = (ship_obj_t *)obj;
	if (!obj) return;
	ship_lock(debug_refs);
	if (!(refs = ship_ht_get_ptr(debug_refs, obj))) {
		USER_ERROR("***** unreffing something that doesn't exist at %s:%d\n", file, line);
		refs = ship_list_new();
		ship_ht_put_ptr(debug_refs, obj, refs);
	}
	
	str = mallocz(strlen(file) + 64);
	sprintf(str, "UNREF  %s:%d (%d)", file, line, o->_ship_obj_ref);
	ship_list_add(refs, str);
	ship_unlock(debug_refs);
}

void ship_debug_reportref()
{
	ship_list_t *refs = NULL, *keys = NULL;
	char *key, *pos;

	ship_lock(debug_refs);
	USER_ERROR("****** refs *******\n");

	keys = ship_ht_keys(debug_refs);
	while (key = ship_list_pop(keys)) {
		void *ptr = 0;
		USER_ERROR("++ object %s:\n", key);
		refs = ship_ht_get_string(debug_refs, key);
		while (pos = ship_list_next(refs, &ptr)) {
			USER_ERROR("\t%s\n", pos);
		}
		USER_ERROR("-- object %s:\n", key);
	}
	ship_list_free(keys);
	USER_ERROR("****** /refs *******\n");
	ship_unlock(debug_refs);
}

void ship_debug_closeref()
{
	ship_list_t *refs = NULL;
	USER_ERROR("****** refs at closing: *******\n");
	ship_lock(debug_refs);
	ship_debug_reportref();

	while (refs = ship_ht_pop(debug_refs)) {
		ship_list_empty_free(refs);
		ship_list_free(refs);
	}
	ship_ht_free(debug_refs);
}


#endif
