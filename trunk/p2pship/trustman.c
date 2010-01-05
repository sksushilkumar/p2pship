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
#include <string.h>
#include "ship_debug.h"
#include "ship_utils.h"
#include "processor_config.h"
#include "trustman.h"

#define trustman_pf_get_template "http://%s/pathlength/from/%s/to/%s/"

/* whether the trustfetch should block the traffic. this should be
   disabled (not set) generally as it is old logic that might be
   useful only for debugging. */
//#define BLOCKING_TRUSTFETCH

static ship_list_t *params_ht = NULL;
static char *pathfinder = 0;
static int trustman_fetch_params(trustparams_t *params);

static void
trustman_trustparams_free(trustparams_t *params)
{
	if (!params)
		return;
	freez(params->from_aor);
	freez(params->to_aor);
	freez(params->params);
	ship_list_empty_free(params->queued_packets);
	ship_list_free(params->queued_packets);
	freez(params);
}

static trustparams_t *
trustman_trustparams_new(char *from_aor, char *to_aor)
{
	trustparams_t *params = 0;
	ASSERT_TRUE(params = mallocz(sizeof(trustparams_t)), err);
	ASSERT_TRUE(params->from_aor = strdup(from_aor), err);
	ASSERT_TRUE(params->to_aor = strdup(to_aor), err);
	ASSERT_TRUE(params->queued_packets = ship_list_new(), err);
	params->pathfinder_len = -1;
	return params;
 err:
	trustman_trustparams_free(params);
	return 0;
}

static int
trustman_cb_config_update(processor_config_t *config, char *k, char *v)
{
	freez(pathfinder);
	if (pathfinder = strdup(processor_config_string(config, P2PSHIP_CONF_PATHFINDER)))
		return 0;
	return -1;
}

int
trustman_init(processor_config_t *config)
{
	ASSERT_TRUE(params_ht = ship_list_new(), err);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_PATHFINDER, trustman_cb_config_update);
	processor_config_set_dynamic(config, P2PSHIP_CONF_USE_PATHFINDER);
	ASSERT_ZERO(trustman_cb_config_update(config, NULL, NULL), err);
	return 0;
 err:
	return -1;
}

void
trustman_close()
{
	trustparams_t *param = NULL;
	ship_list_t *list = params_ht;

	ship_lock(params_ht);
	params_ht = NULL;
	ship_unlock(list);
	while (param = ship_list_pop(list)) {
		ship_lock(param->queued_packets);
		ship_unlock(param->queued_packets);
		trustman_trustparams_free(param);
	}
	ship_list_free(list);
	freez(pathfinder);
}

/* marks that we have sent the current trust parameters */
int
trustman_mark_current_trust_sent(char *from_aor, char *to_aor)
{
	trustparams_t *params = trustman_get_create_trustparams(from_aor, to_aor);
	if (params) {
		params->current_sent = 1;
		params->send_flag = 0;
		ship_unlock(params->queued_packets);
		return 0;
	} else {
		return -1;
	}
}

/* marks that the given remote person should be provided trust parameters */
int
trustman_mark_send_trust_to(char *from_aor, char *to_aor)
{
	/* find aor - to_aor */
	trustparams_t *params = trustman_get_create_trustparams(from_aor, to_aor);
	if (params) {
		params->send_flag = 1;
		trustman_fetch_params(params);
		ship_unlock(params->queued_packets);
		return 0;
	} else {
		return -1;
	}
}

static void 
trustman_fetch_params_cb(char *url, int respcode, char *data, int data_len, void *pkg)
{
	trustparams_t *params = pkg;
	void **ptr;
	
	if (!params_ht)
		return;
	
	LOG_INFO("Got trust parameters (code %d) for %s -> %s\n", respcode, params->from_aor, params->to_aor);
	ship_lock(params->queued_packets);
	freez(params->params);
	params->params_len = 0;
	time(&(params->expires));
	if (data && data_len) {
		params->params = mallocz(data_len+1);
		if (params->params) {
			int plen = -1;
			
			memcpy(params->params, data, data_len);
			params->params_len = data_len;
			params->current_sent = 0;
			
			/* todo: here we should parse the
			   data. timeouts etcetc.. */

			if (sscanf(data, "%d", &params->pathfinder_len) != 1)
				params->pathfinder_len = -1;

			plen = atoi(data);
			if (plen > 0)
				params->expires += 30;
		}
	} else {
		/* put some timeout here for nulls.. */
		params->expires += 30;
	}
	params->requesting = 0;
	
	/* we should do something with the queued packets.. */
	while (ptr = ship_list_pop(params->queued_packets)) {
		int (*func) (char *from_aor, char *to_aor, 
			     char *params, int param_len,
			     void *data) = ptr[0];
		void *data = ptr[1];
		free(ptr);
		func(params->from_aor, params->to_aor, params->params, params->params_len, data);
	}
	ship_unlock(params->queued_packets);
}

char *
trustman_get_pathfinder()
{
	return pathfinder;
}

/* the params got to be locked before entering!
 *
 * This initiates the trustman fetch, if necessary. */
static int
trustman_fetch_params(trustparams_t *params)
{
	char *url = 0, *fh = 0, *th = 0, *fuh = 0, *tuh = 0;
	int ret = -1;
	time_t now;
	
	if (params->requesting)
		return 0;
	
	/* if we still have valid parameters, then do nothing! */
	/* note: both if we have the data and if we dont! */
	time(&now);
	if (/*params->params &&*/ (now < params->expires))
		return 0;

	LOG_INFO("Fetching Trust parameters for %s -> %s\n", params->from_aor, params->to_aor);
	params->requesting = 1;
	freez(params->params);
	params->params_len = 0;

	/* make a http request! */
	/* note: this isn't really safe as params might be free'd
	   before this completes! */
	
	/* create the url */
	ASSERT_TRUE(fh = ship_hash_sha1_base64(params->from_aor, strlen(params->from_aor)), err);
	ASSERT_TRUE(fuh = ship_urlencode(fh), err);
	ASSERT_TRUE(th = ship_hash_sha1_base64(params->to_aor, strlen(params->to_aor)), err);
	ASSERT_TRUE(tuh = ship_urlencode(th), err);
	
	/* fetch the reverse path */
	ASSERT_TRUE(url = mallocz(strlen(trustman_pf_get_template) + strlen(tuh) + 
				  strlen(fuh) + strlen(trustman_get_pathfinder()) + 64), err);
	sprintf(url, trustman_pf_get_template, trustman_get_pathfinder(), tuh, fuh);
	ret = netio_http_get(url, trustman_fetch_params_cb, params);
	if (ret)
		trustman_fetch_params_cb("", -1, NULL, 0, params);
 err:
	freez(url);
	freez(fh);
	freez(th);
	freez(fuh);
	freez(tuh);
	return ret;
}

/* the main logic of the trust module. checks whether we should send
   our trustparams, and initiates fetch & puts on wait if so. */
int
trustman_check_trustparams(char *from_aor, char *to_aor, int (*func) (char *from_aor, char *to_aor, 
								      char *params, int param_len,
								      void *data), 
			   void *data)
{
	int ret = -1;
	trustparams_t *params = 0;

	/* do we know *anything* about any trust params to send? */
	params = trustman_get_trustparams(from_aor, to_aor);
	if (processor_config_is_true(processor_get_config(), P2PSHIP_CONF_USE_PATHFINDER) && 
	    params && 
	    params->send_flag) {

		/* check for expired, initiate fetch if necessary */
		trustman_fetch_params(params);
		if (!params->current_sent && params->params) {
			/* we have new trust params to send! */
			ret = func(from_aor, to_aor, params->params, params->params_len, data);
			data = NULL;
		} else if (!params->params && params->requesting) {
			/* ..wait for trust params */
			void **ptr = mallocz(2*sizeof(void*));
			if (ptr) {
				LOG_INFO("queueing request as we're making trust request.. \n");
				ptr[0] = func;
#ifdef BLOCKING_TRUSTFETCH
				ptr[1] = data;
				data = NULL;
#endif
				ship_list_add(params->queued_packets, ptr);
			}
			ret = trustman_fetch_params(params);
			ret = 0;
		}
	}
		
	/* we don't have any params, and aren't expecting any
	   either */
	if (data)
		ret = func(from_aor, to_aor, NULL, 0, data);
	
	if (params)
		ship_unlock(params->queued_packets);
	return ret;
}

int
trustman_handle_trustparams(char *from_aor, char *to_aor, char *payload, int pkglen)
{
	trustparams_t *params = 0;
	char *tmp = 0;

	/* save trust params somewhere as from_aor - to_aor.. */
	if (tmp = mallocz(pkglen+1))
		memcpy(tmp, payload, pkglen);
	
	LOG_DEBUG("Got remotely trust parameters: '%s'\n", tmp);
	params = trustman_get_create_trustparams(from_aor, to_aor);
	if (params && tmp) {
		freez(params->params);
		params->params = tmp;
		params->params_len = pkglen;
		
		/* when should these expire? */
		params->expires = time(0) + 30;
		
		if (sscanf(tmp, "%d", &params->pathfinder_len) != 1)
			params->pathfinder_len = -1;
		ship_unlock(params->queued_packets);
		tmp = 0;
	}
	
	freez(tmp);
	return 0;
}


/* this one is for internal use. it just fetches from the cache the
   trustparam instance for the given pair of aors */
static trustparams_t *
trustman_get_trustparams(char *from_aor, char *to_aor)
{
	trustparams_t *params = 0;
	void *ptr = 0;

	/* find, lock, return */
	ship_lock(params_ht);
	while (!params && (params = ship_list_next(params_ht, &ptr))) {
		if (strcmp(from_aor, params->from_aor) ||
		    strcmp(to_aor, params->to_aor))
			params = 0;
	}
	
	if (params)
			ship_lock(params->queued_packets);
	
	ship_unlock(params_ht);
	return params;
}

/* this one is for 'external' use. It fetches the instance for the
   given aor pair from the cache (if exists), perhaps adding something
   to that, and checking the validity of the parameters. */
trustparams_t *
trustman_get_valid_trustparams(char *from_aor, char *to_aor)
{
	trustparams_t *params = 0;
	time_t now;
	int has_valid = 0;

	ship_lock(params_ht);
	params = trustman_get_trustparams(from_aor, to_aor);

	/* check the validity */
	time(&now);
	if (params && (now < params->expires)) {
		has_valid = 1;
	}
	
	/* here, we should probably check our address book as well to
	   see whether we have that person there .. */
	if (!has_valid) {
	    if (addrbook_has_contact(to_aor, from_aor)) {
		    if (!params && (params = trustman_trustparams_new(from_aor, to_aor))) {
			    ship_lock(params->queued_packets);
			    ship_list_add(params_ht, params);
		    }
		    
		    if (params) {
			    params->pathfinder_len = 1;
			    params->expires = now + 30;
		    }
	    } else if (params) {
		    ship_unlock(params->queued_packets);
		    params = 0;
	    }
	}
	ship_unlock(params_ht);
	return params;
}


trustparams_t *
trustman_get_create_trustparams(char *from_aor, char *to_aor)
{
	trustparams_t *params = 0;
	void *ptr = 0;

	ship_lock(params_ht);
	params = trustman_get_trustparams(from_aor, to_aor);
	if (!params) { 
		if (params = trustman_trustparams_new(from_aor, to_aor)) {
			ship_lock(params->queued_packets);
			ship_list_add(params_ht, params);
		}
	}
	ship_unlock(params_ht);
	
	if (!params) {
		LOG_WARN("Couldn't create new trust params!\n");
	}
	return params;
}


