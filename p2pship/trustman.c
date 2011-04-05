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
#include "processor.h"
#include "processor_config.h"
#include "processor.h"
#include "trustman.h"
#include "ident.h"
#include "addrbook.h"
#include "netio_http.h"
#ifdef CONFIG_OP_ENABLED
#include <opconn.h>
#endif

#define trustman_pf_get_template "http://%s/pathlength/from/%s/to/%s/"

/* whether the trustfetch should block the traffic. this should be
   disabled (not set) generally as it is old logic that might be
   useful only for debugging. */
//#define BLOCKING_TRUSTFETCH

static ship_list_t *params_ht = NULL;
static ship_list_t *params_remote_ht = NULL;
static char *pathfinder = 0;
static int trustman_fetch_params(trustparams_t *params);
static trustparams_t *trustman_get_trustparams(char *from_aor, char *to_aor);
static trustparams_t *trustman_get_create_trustparams(char *from_aor, char *to_aor);
static trustparams_remote_t *trustman_get_create_remote_trustparams(char *from_aor, char *to_aor);
static int trustman_handle_trustparams(char *from_aor, char *to_aor, char *payload, int pkglen);


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
#ifdef CONFIG_OP_ENABLED
	freez(params->op_cert);
#endif
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
	return params;
 err:
	trustman_trustparams_free(params);
	return 0;
}

static void
trustman_trustparams_remote_free(trustparams_remote_t *params)
{
	if (!params)
		return;
	ship_lock_free(&params->lock);
	freez(params->from_aor);
	freez(params->to_aor);
#ifdef CONFIG_OP_ENABLED
	freez(params->op_identity);
	freez(params->op_key);
#endif
	freez(params);
}

static trustparams_remote_t *
trustman_trustparams_remote_new(char *from_aor, char *to_aor)
{
	trustparams_remote_t *params = 0;
	ASSERT_TRUE(params = mallocz(sizeof(trustparams_remote_t)), err);
	ASSERT_TRUE(params->from_aor = strdup(from_aor), err);
	ASSERT_TRUE(params->to_aor = strdup(to_aor), err);
	ASSERT_ZERO(ship_lock_new(&params->lock), err);
	return params;
 err:
	trustman_trustparams_remote_free(params);
	return 0;
}

static void
trustman_cb_config_update(processor_config_t *config, char *k, char *v)
{
	freez(pathfinder);
	if ((pathfinder = strdup(processor_config_string(config, P2PSHIP_CONF_PATHFINDER))))
		return;
	return;
}
static int
trustman_handle_trust_message(char *data, int data_len, 
			      ident_t *target, char *source, 
			      service_type_t service_type)
{
	return trustman_handle_trustparams(source, target->sip_aor, data, data_len);
}

static struct service_s trust_service =
{
 	.data_received = trustman_handle_trust_message,
	.service_closed = 0,
	.service_handler_id = "trust_service"
};

int
trustman_init(processor_config_t *config)
{
	ASSERT_TRUE(params_ht = ship_list_new(), err);
	ASSERT_TRUE(params_remote_ht = ship_list_new(), err);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_PATHFINDER, trustman_cb_config_update);
	processor_config_set_dynamic(config, P2PSHIP_CONF_USE_PATHFINDER);
	trustman_cb_config_update(config, NULL, NULL);

	ident_register_default_service(SERVICE_TYPE_TRUST, &trust_service);
	return 0;
 err:
	return -1;
}

void
trustman_close()
{
	trustparams_t *param = NULL;
	trustparams_remote_t *paramr = NULL;
	ship_list_t *list = params_ht;

	ship_lock(params_ht);
	params_ht = NULL;
	ship_unlock(list);
	while ((param = ship_list_pop(list))) {
		ship_lock(param->queued_packets);
		ship_unlock(param->queued_packets);
		trustman_trustparams_free(param);
	}
	ship_list_free(list);
	freez(pathfinder);

	list = params_remote_ht;
	ship_lock(params_remote_ht);
	params_remote_ht = NULL;
	ship_unlock(list);
	while ((paramr = ship_list_pop(list))) {
		ship_lock(paramr);
		ship_unlock(paramr);
		trustman_trustparams_remote_free(paramr);
	}
	ship_list_free(list);
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
trustman_mark_send_trust_to(ident_t *ident, char *to_aor)
{
	/* find aor - to_aor */
	trustparams_t *params = 0;
	ASSERT_TRUE(params = trustman_get_create_trustparams(ident->sip_aor, to_aor), err);
	params->send_flag = 1;
	trustman_fetch_params(params);
	ship_unlock(params->queued_packets);
	
#ifdef CONFIG_OP_ENABLED
	if (ident_is_op_verify(ident))
		params->op_send = 1;
#endif
	return 0;
 err:
	return -1;
}

static void 
trustman_fetch_params_cb(char *url, int respcode, char *data, int data_len, void *pkg)
{
	trustparams_t *params = pkg;
	void **ptr;
	char *params_copy = NULL, *from_copy = NULL, *to_copy = NULL;
	int params_len = 0;
	
	if (!params_ht)
		return;

	LOG_INFO("Got trust parameters (code %d) for %s -> %s\n", respcode, params->from_aor, params->to_aor);
	ship_lock(params->queued_packets);
	freez(params->params);
	params->params_len = 0;
	time(&(params->expires));
	if (data && data_len) {
		params->params = mallocz(data_len+1+32);
		if (params->params) {
			/* mm.. hope the data is in asciiz */
			strcpy(params->params, "pathlen:");
			strcat(params->params, data);
			params->params_len = strlen(params->params);
			params->current_sent = 0;
			
			/* todo: here we should parse the
			   data. timeouts etcetc.. */

			params->expires += 30;
		}
	} else {
		/* put some timeout here for nulls.. */
		params->expires += 30;
	}
	params->requesting = 0;

	if ((params_copy = mallocz(params->params_len + 1))) {
		memcpy(params_copy, params->params, params->params_len);
		params_len = params->params_len;
	}
	from_copy = strdup(params->from_aor);
	to_copy = strdup(params->to_aor);
	
	/* we should do something with the queued packets.. */
	while ((ptr = ship_list_pop(params->queued_packets))) {
		int (*func) (char *from_aor, char *to_aor, 
			     char *params, int param_len,
			     void *data) = ptr[0];
		void *data = ptr[1];
		free(ptr);
		ship_unlock(params->queued_packets);
		func(from_copy, to_copy, params_copy, params_len, data); // cbret
		ship_lock(params->queued_packets);
	}
	freez(params_copy);
	freez(from_copy);
	freez(to_copy);
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
	freez(params->params);
	params->params_len = 0;

	/* make a http request! */
	/* note: this isn't really safe as params might be free'd
	   before this completes! */
	
	/* create the url */
	if (processor_config_is_true(processor_get_config(), P2PSHIP_CONF_USE_PATHFINDER)) {
		ASSERT_TRUE(fh = ship_hash_sha1_base64(params->from_aor, strlen(params->from_aor)), err);
		ASSERT_TRUE(fuh = ship_urlencode(fh), err);
		ASSERT_TRUE(th = ship_hash_sha1_base64(params->to_aor, strlen(params->to_aor)), err);
		ASSERT_TRUE(tuh = ship_urlencode(th), err);
		
		/* fetch the reverse path */
		ASSERT_TRUE(url = mallocz(strlen(trustman_pf_get_template) + strlen(tuh) + 
					  strlen(fuh) + strlen(trustman_get_pathfinder()) + 64), err);
		sprintf(url, trustman_pf_get_template, trustman_get_pathfinder(), tuh, fuh);
		if (!(ret = netio_http_get(url, trustman_fetch_params_cb, params)))
			params->requesting = 1;
	} else {
		params->params = strdup("sorry, no trustparams this time!");
		params->params_len = strlen(params->params);
		time(&(params->expires));
		params->expires += 30;
		ret = 0;
	}
	
	//if (ret)
	//	trustman_fetch_params_cb("", -1, NULL, 0, params);
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
	char *params_copy = NULL;
	int params_len = 0;
	
	/* do we know *anything* about any trust params to send? */

	params = trustman_get_trustparams(from_aor, to_aor);
	if (params && params->send_flag) {
		
#ifdef CONFIG_OP_ENABLED
		time_t now;
		now = time(0);
		if (params->op_send && (now > params->op_expires)) {
			/* fetch, send, set new expires */
			freez(params->op_cert);
			if(!opconn_request_cert(from_aor, &(params->op_cert))) {
				X509 *cert = 0;
				time_t start, end;
				char *tmp = 0;
				
				ASSERT_TRUE(cert = ship_parse_cert(params->op_cert), op_err);
				ASSERT_ZERO(ident_data_x509_get_validity(cert, &start, &end), op_err);
				params->op_expires = end;
				LOG_INFO("got a cert for another %d seconds..\n", end-now);
				ASSERT_TRUE(tmp = mallocz(strlen(params->op_cert) + 32), op_err);
				strcpy(tmp, "op_cert:");
				strcat(tmp, params->op_cert);
				func(from_aor, to_aor, tmp, strlen(tmp), NULL);
			op_err:
				freez(tmp);
				if (cert) X509_free(cert);
			}
		}
#endif

		/* check for expired, initiate fetch if necessary */
		trustman_fetch_params(params);
		if (!params->current_sent && params->params) {
			/* we have new trust params to send! */
			ASSERT_TRUE(params_copy = mallocz(params->params_len + 1), err);
			memcpy(params_copy, params->params, params->params_len);
			params_len = params->params_len;
			//ret = func(from_aor, to_aor, params->params, params->params_len, NULL);
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
		
 err:
	if (params)
		ship_unlock(params->queued_packets);

	/* we don't have any params, and aren't expecting any
	   either */
	if (data)
		ret = func(from_aor, to_aor, params_copy, params_len, data); // cbret	
	freez(params_copy);
	return ret;
}

int
trustman_handle_trustparams(char *from_aor, char *to_aor, char *payload, int pkglen)
{
	trustparams_remote_t *params = 0;
	char *tmp = 0, *data = 0;
	X509 *cert = 0;

	/* save trust params somewhere as from_aor - to_aor.. */
	if ((tmp = mallocz(pkglen+1)))
		memcpy(tmp, payload, pkglen);
	
	/* to ensure we have asciiz now */
	ASSERT_TRUE(tmp = mallocz(pkglen+1), err);
	memcpy(tmp, payload, pkglen);
	
	LOG_DEBUG("Got remotely trust parameters: '%s'\n", tmp);
	ASSERT_TRUE(params = trustman_get_create_remote_trustparams(from_aor, to_aor), err);
	data = strstr(payload, ":");
	ASSERT_TRUE(data, err);
	data[0] = 0;
	data++;
	
	/* interpret the trustparameters we got */
	if (!strcmp(payload, "pathlen")) {
		LOG_INFO("got pathfinder length\n");
			
		/* when should these expire? */
		params->expires = time(0) + 30;
		if (sscanf(data, "%d", &params->pathfinder_len) != 1)
			params->pathfinder_len = -1;
#ifdef CONFIG_OP_ENABLED
	} else if (!strcmp(payload, "op_cert")) {
		time_t start = 0;
			
		LOG_INFO("got an op certificate\n");
		ASSERT_TRUE(cert = ship_parse_cert(data), err);
		if (1 || ident_data_x509_check_signature(cert, cert)) {
			freez(tmp);
			
			ASSERT_TRUE(tmp = ident_data_x509_get_cn(X509_get_subject_name(cert)), err);
			if (strcmp(from_aor, tmp)) {
				LOG_WARN("got cert for mismatching identity (%s / %s)!\n",
					 from_aor, tmp);
				ASSERT_TRUE(0, err);
			}
			
			freez(params->op_identity);
			freez(params->op_key);
			params->op_expires = 0;

			params->op_identity = tmp;
			tmp = 0;
			ASSERT_ZERO(ident_data_x509_get_validity(cert, &start, &params->op_expires), err);
			ASSERT_TRUE(params->op_key = ident_data_get_pkey_base64(cert), err);
			
			LOG_INFO("got cert for '%s' valid until %d, key: '%s'\n", params->op_identity, 
				 params->op_expires, params->op_key);
		} else {
			LOG_WARN("invalid signature, now self-signed\n");
		}
#endif
	}
 err:
	if (cert) X509_free(cert);
	ship_unlock(params);
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


/* returns the pathlen between two, used for checking the path we have
   got from someone else */
int
trustman_get_pathlen(char *from_aor, char *to_aor)
{
	trustparams_remote_t *params = 0;
	time_t now;
	int ret = -1;
	int has_valid = 0;
	ident_t *ident = ident_find_by_aor(from_aor);
	
	params = trustman_get_create_remote_trustparams(from_aor, to_aor);
	
	/* check the validity */
	time(&now);
	if (params && (now < params->expires)) {
		has_valid = 1;
	}
	
	/* here, we should probably check our address book as well to
	   see whether we have that person there .. */
	if (!has_valid) {
		int new_len = 0;
		
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
		/* go through the ident's buddies, check whether we
		   have any info on this guy */
		if (ident) {
			new_len = ident_data_bb_get_first_level(ident->buddy_list, to_aor);
		}
#endif
		/* actually, as we're checking ident's buddies in
		   bloombuddies, this might not be necessary: */
		if (addrbook_has_contact(to_aor, from_aor))
			new_len = 1;

		if ((new_len > -1) && params) {
			params->pathfinder_len = new_len;
			params->expires = now + 30;
		}
	}

	if (params) {
		ret = params->pathfinder_len;
		ship_unlock(params);
	}
	ship_obj_unlockref(ident);
	return ret;
}

#ifdef CONFIG_OP_ENABLED
/* returns a copy of the key (if any) which the user was veirfied
   with */
char *
trustman_op_get_verification_key(char *from_aor, char *to_aor)
{
	trustparams_remote_t *params = 0;
	time_t now;
	char *ret = 0;
	
	ASSERT_TRUE(params = trustman_get_create_remote_trustparams(from_aor, to_aor), err);
	/* check the validity */
	time(&now);
	if (params->op_key && now < params->op_expires)
		ret = strdup(params->op_key);
 err:
	ship_unlock(params);
	return ret;
}
#endif

static trustparams_remote_t *
trustman_get_create_remote_trustparams(char *from_aor, char *to_aor)
{
	trustparams_remote_t *params = 0;
	void *ptr = 0;

	ship_lock(params_remote_ht);
	while (!params && (params = ship_list_next(params_remote_ht, &ptr))) {
		if (strcmp(from_aor, params->from_aor) ||
		    strcmp(to_aor, params->to_aor))
			params = 0;
	}

	if (!params) { 
		if ((params = trustman_trustparams_remote_new(from_aor, to_aor))) {
			ship_list_add(params_remote_ht, params);
		}
	}
	
	if (params)
		ship_lock(params);

	ship_unlock(params_remote_ht);
	
	if (!params) {
		LOG_WARN("Couldn't create new trust params!\n");
	}
	return params;
}

static trustparams_t *
trustman_get_create_trustparams(char *from_aor, char *to_aor)
{
	trustparams_t *params = 0;

	ship_lock(params_ht);
	params = trustman_get_trustparams(from_aor, to_aor);
	if (!params) { 
		if ((params = trustman_trustparams_new(from_aor, to_aor))) {
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


