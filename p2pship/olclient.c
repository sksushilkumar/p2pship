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
#include "olclient.h"
#ifdef CONFIG_OP_ENABLED
#include <opconn.h>
#endif
#ifdef CONFIG_OPENDHT_ENABLED
#include "libhipopendht.h"
#include "ol_opendht.h"
#endif
#include "ship_utils.h"
#include "ship_debug.h"
#include "processor.h"

#ifdef CONFIG_BROADCAST_ENABLED
#include "ol_broadcast.h"
#endif
#ifdef CONFIG_P2PEXT_ENABLED
#include "ol_p2pext.h"
#endif

/* crypto stuff */
#define CRYPT_ALGO "aes-256-cbc"

#define OL_CACHE_LIMIT 20
#define SUBSCRIBE_POLL_PERIOD 30000

/* the crypt functions */
static unsigned char* olclient_encrypt_for_someone(const char *data, buddy_t *receiver);
static char* olclient_create_signed_wrap(const char *key, const char *data, ident_t *signer, const int add_cert, const int timeout);
static char* olclient_sign_xml_record(const char *data, ident_t *ident, const int addcert);
static char* olclient_create_wrap_xml_record(const char *key, const char *data, const int timeout);
static int olclient_decrypt_for_someone(olclient_verifier_t *pr_key, const char *value, char **res_value);
static char *olclient_verify_data_sig(olclient_signer_t *cert, const char *data, char **signer);
static int olclient_subscribe_poll(void* data);

static ship_obj_list_t *olclient_lookups = 0;
static ship_list_t *olclient_modules = 0;

static ship_list_t *entries = NULL;
static ship_obj_list_t *pollers = NULL;

static void olclient_lookup_free(olclient_lookup_t *obj);
static int olclient_lookup_init(olclient_lookup_t *ret, char *key);
SHIP_DEFINE_TYPE(olclient_lookup);

static void olclient_get_task_free(olclient_get_task_t *obj);
static int olclient_get_task_init(olclient_get_task_t *ret, olclient_lookup_t *lookup);
SHIP_DEFINE_TYPE(olclient_get_task);


static void 
olclient_get_task_free(olclient_get_task_t *obj)
{
	if (obj->callback) {
		obj->callback(NULL, -1, obj);
	}
	ship_obj_unref(obj->lookup);
	freez(obj->id);
}

static int 
olclient_get_task_init(olclient_get_task_t *ret, olclient_lookup_t *lookup)
{
 	ASSERT_TRUE(ret->id = mallocz(64), err);
	sprintf(ret->id, "%08x.%d", (unsigned int)ret, rand());

	ship_obj_ref(lookup);
	ret->lookup = lookup;
	return 0;
 err:
	return -1;
}

void
olclient_cb_state_change(struct olclient_module* module, int status, char *info)
{
	/* note: this isn't actually called from anywhere .. :( */
	LOG_INFO("changed state of storage module %s to %d: %s\n", module->name, status, info);
	processor_event_generate_pack("ol_state_update", NULL);
}

static void
olclient_extra_free(olclient_extra_t *e)
{
	if (e) {
		freez(e->cipher_secret);
		if (e->signer) X509_free(e->signer);
		if (e->receiver) RSA_free(e->receiver);
		free(e);
	}
}

static void 
olclient_lookup_free(olclient_lookup_t *l)
{
	if (l->callback) {
		l->callback(l->key, NULL, NULL, l->param, l->status);
	}
	ship_list_empty_free(l->results);
	ship_list_free(l->results);
	ship_list_empty_free(l->cache);
	ship_list_free(l->cache);
	ship_obj_list_free(l->tasks);
	olclient_extra_free(l->extra);
	freez(l->key);
	freez(l->signer_aor);
}

static olclient_extra_t *
olclient_extra_new(const char *cipher_secret, ident_t *receiver, 
		   buddy_t *signer, int flags)
{
	olclient_extra_t *ret;
  	ASSERT_TRUE(ret = (olclient_extra_t *)mallocz(sizeof(olclient_extra_t)), err);
  	if (cipher_secret) {
  		ASSERT_TRUE(ret->cipher_secret = strdup(cipher_secret), err);
  	}
	
	ret->verify_flags = flags;
	if (signer)
		ret->signer = X509_dup(signer->cert);

	/* todo op: if op is used, we should just mark this somehow */
	if (receiver)
		ret->receiver = RSAPrivateKey_dup(receiver->private_key);
	return ret;
 err:
	olclient_extra_free(ret);
	return NULL;
}

/* running counter of the lookup handles.. */
static int lookup_handle = 1;

static int 
olclient_lookup_init(olclient_lookup_t *ret, char *key)
{
        ASSERT_TRUE(ret->key = strdup(key), err);
        ASSERT_TRUE(ret->tasks = ship_obj_list_new(), err);
        ASSERT_TRUE(ret->results = ship_list_new(), err);
        ASSERT_TRUE(ret->cache = ship_list_new(), err);

	/* this is considered good enough for now .. */
	if (lookup_handle < 1)
		lookup_handle = 1;
	while (!ret->handle)
		ret->handle = lookup_handle++;
	ret->status = -1;
        return 0;
     err:
        return -1;
}

/* registers a new module */
int
olclient_register_module(struct olclient_module* mod)
{
	ship_list_remove(olclient_modules, mod);
	ship_list_add(olclient_modules, mod);
	return 0;
}

/* de-registers a new module */
void
olclient_unregister_module(struct olclient_module* mod /*const char *name, void *module_data*/)
{
	ship_list_remove(olclient_modules, mod);

	/* todo: go through the unfinished calls, remove this from those also! */
}

struct olclient_module* 
olclient_module_new(const struct olclient_module mod, const char *name, void *module_data)
{
	struct olclient_module* ret = (struct olclient_module*)mallocz(sizeof(*ret));
	memcpy(ret, &mod, sizeof(mod));
	if ((ret->name = strdup(name))) {
		ret->module_data = module_data;
		return ret;
	}
	olclient_module_free(ret);
	return NULL;
}

void 
olclient_module_free(struct olclient_module* mod)
{
	if (mod) {
		freez(mod->name);
		freez(mod);
	}
}

/* inits the system */
int 
olclient_init(processor_config_t *config)
{
	LOG_INFO("initing the overlay client\n");
        
        ASSERT_TRUE(olclient_lookups = ship_list_new(), err);
        ASSERT_TRUE(olclient_modules = ship_list_new(), err);

	/* init the storage */
	ASSERT_TRUE(entries = ship_list_new(), err);
	ASSERT_TRUE(pollers = ship_list_new(), err);
	
	/* init all the different modules */
#ifdef CONFIG_OPENDHT_ENABLED
	ASSERT_ZERO(ol_opendht_init(config), err);
#endif        
#ifdef CONFIG_BROADCAST_ENABLED
	ASSERT_ZERO(ol_broadcast_init(config), err);
#endif
#ifdef CONFIG_P2PEXT_ENABLED
	ASSERT_ZERO(ol_p2pext_init(config), err);
#endif
	ASSERT_ZERO(processor_tasks_add_periodic(olclient_subscribe_poll, NULL, SUBSCRIBE_POLL_PERIOD), err);
        return 0;
 err:
        LOG_ERROR("overlay client failed to start\n");
        return -1;
}

/* shuts down */
void 
olclient_close()
{
        LOG_INFO("closing the overlay client\n");
	ship_obj_list_free(olclient_lookups);
	olclient_lookups = NULL;

	if (olclient_modules) {
		struct olclient_module *mod;
		ship_lock(olclient_modules);
		while ((mod = (struct olclient_module *)ship_list_pop(olclient_modules))) {
			mod->close(mod);
			/* freez(mod->name); */
			/* freez(mod); */
		}
		ship_list_free(olclient_modules);
		olclient_modules = NULL;
	}

	/* close the storage */
	if (entries) {
		olclient_storage_entry_t *e;
		while ((e = ship_list_pop(entries))) {
			olclient_storage_entry_free(e);
		}
		ship_list_free(entries);
		entries = NULL;
	}

	ship_obj_list_free(pollers);
	pollers = NULL;
}


/**************************************
 * gets
 */

static void
olclient_notify_complete_done(void *data, int code)
{
	ship_obj_unref(data);
}

static int
olclient_notify_complete(void *data, processor_task_t **wait, int wait_for_code)
{
        olclient_lookup_t *l = (olclient_lookup_t *)data;
	char *res;
	void (*callback) (char *, char *, char *, void *, int) = 0;

	/* sync over results */
	ship_lock(l);

	/* we take charge of the callback so that no
	   other thread would falsely report that
	   things are done because they can't see the
	   res we're currently reporting */
	callback = l->callback;
	l->callback = 0;

	/* is it our time to shine? */
	if (callback) {
		do {
			if ((res = (char*)ship_list_pop(l->results))) {
				ship_unlock(l);
				callback(l->key, res, l->signer_aor, l->param, 1);
				freez(res);
				ship_lock(l);
			}
		} while (res);
	}

	/* are we done? ..we might have had more results put here,
	   thefore check the results list also! */
	if (!ship_list_first(l->tasks)) {
		ship_obj_list_remove(olclient_lookups, l);
		if (callback)
			callback(l->key, NULL, NULL, l->param, l->status);
	} else if (callback)
		l->callback = callback;
	ship_unlock(l);
	return 0;
}


/* adds a result to the list of received values. Unless it has been
   seen before already! 
   
   @return true if added, 0 if not (already seen!)
*/
static int
olclient_add_result(olclient_lookup_t *l, const char *value)
{
	void *ptr = NULL;
	char *val = 0;
	char *cval = 0;
	int found = 0;
	
	ship_lock(l->cache);
	if ((val = ship_hash_sha1_base64((char*)value, strlen(value)))) {
		while (!found && (cval = ship_list_next(l->cache, &ptr))) {
			if (!strcmp(val, cval))
				found = 1;
		}
		if (!found) {
			ship_list_add(l->cache, val);
			while (ship_list_length(l->cache) > OL_CACHE_LIMIT)
				free(ship_list_pop(l->cache));
			val = NULL;
		}
	}
	ship_unlock(l->cache);
	
	if (!found)
		ship_list_add(l->results, (void*)value);
	else {
		LOG_DEBUG("suppressing already seen data!\n");
	}
		
	freez(val);
	return !found;
}

/* 
   Callback called by the lookup modules.
   
   status codes:
   1 - more is to come still
   0 - done, ok
   < 0 - done, error.

   This module assumes ownership of the data!
 */

static void
olclient_cb_get(char *value, int status,
		olclient_get_task_t *task)
{
	olclient_lookup_t *l = task->lookup;

	/* check that we still have that lookup in the list! */
	ship_lock(l);
	LOG_VDEBUG("got from module %s for '%s', status %d\n", task->mod->name, l->key, status);
	if (value) {
		char *res_value = NULL;
	
		/* symm secret? */
		if (l->extra->cipher_secret && value) {
			unsigned char *cipher_key = NULL;
			unsigned char *cipher_key64 = NULL;
			unsigned char *iv = NULL;
			unsigned char *iv64 = NULL;
			LOG_VDEBUG("decrypting using symmetric..\n");

			/* generate 16-bytes iv from a cipher_secret */
			ship_hash("md5", (unsigned char *)l->extra->cipher_secret, &iv);
			/* generate 32-bytes key from a cipher_secret */
			ship_hash("sha256", (unsigned char *)l->extra->cipher_secret, &cipher_key);
			
			if (cipher_key && iv) {
				cipher_key64 = (unsigned char *)ship_encode_base64((char*)cipher_key, 32);
				iv64 = (unsigned char *)ship_encode_base64((char*)iv, 16);
				if (!(res_value = (char*)ship_decrypt64(CRYPT_ALGO, cipher_key, iv, (unsigned char*)value)))
					LOG_WARN("Cannot decrypt the data with the cipher_secret %s\n", cipher_key);
			}
			freez(value);
			freez(cipher_key64);
			freez(cipher_key);
			freez(iv);
			freez(iv64);
			value = res_value;
			LOG_INFO("get_with_secret done\n");
		}

		/* recipient - private key? */
		if (l->extra->receiver && value) {
			LOG_VDEBUG("decrypting using private..\n");
			/* todo op: use op if we should */
			if (olclient_decrypt_for_someone(l->extra->receiver, value, &res_value)) {
				LOG_WARN("Cannot decrypt the data using private key\n");
			}
			freez(value);
			value = res_value;
		}
		
		/* verify still the internal signer? */
		if ((l->extra->verify_flags & VERIFY_INTERNAL_SIGNER) && value) {
			LOG_VDEBUG("checking anon signature..\n");
			freez(l->signer_aor);
			if (!(res_value = olclient_verify_data_sig(l->extra->signer, value, &l->signer_aor)))
				LOG_WARN("could not verify the internal signature for data\n");
			freez(value);
			value = res_value;
		}
				
		/* if even one module succeeds finding
		   something, consider the whole
		   operation a success */
		if ((status > -1) && (value != NULL))
			l->status = 0;
		
		if (value) {
			LOG_VDEBUG("got data '%s'\n", value);
			if (olclient_add_result(l, value))
				value = 0;
		}
	}

	ship_obj_ref(l);
	if (status != 1)
		ship_obj_list_remove(l->tasks, task);

	ship_unlock(l);
	freez(value);
	
	/* we separate the callback processing into a separate task so
	   we dont hog up the module thread (if any..)! */

	processor_tasks_add(olclient_notify_complete, l, olclient_notify_complete_done);
}

/* This call back function is used only when the module doesn't support get_signed directly */
static void
olclient_cb_get_signed(char *value, int status,
		       olclient_get_task_t *task)
{
	char *tmp = NULL;
	olclient_lookup_t *l = task->lookup;
	
	/* check that we still have that lookup in the list! */
	LOG_VDEBUG("got signed cb from module %s for '%s'\n", task->mod->name, l->key);

	ship_lock(l);
	if (value && (l->extra->verify_flags & VERIFY_SIGNER)) {
		freez(l->signer_aor);
		if (!(tmp = olclient_verify_data_sig(l->extra->signer, value, &l->signer_aor)))
			LOG_WARN("could not verify the signature for data\n");
	}
	freez(value);
	ship_unlock(l);
	
	/* if we didn't succeed in verifying signature, and more is on
	   its way, don't pass this one to the callback */
	if (status != 1 || tmp) 
		olclient_cb_get(tmp, status, task);
}

static int 
olclient_get_to(void *data, processor_task_t **wait, int wait_for_code)
{
	olclient_get_task_t* task;
	olclient_lookup_t *l = data;
	void *ptr = 0;

	/* timeout expired on the lookup, clear the queue, call for
	   notification */
	ship_lock(l);
	while ((task = ship_list_next(l->tasks, &ptr))) {
		LOG_DEBUG("timeout for lookup on module %s..\n", task->mod->name);

		if (l->is_subscribe && task->mod->cancel) {
			task->mod->cancel(l->key, task);
		}
	}

	ship_obj_list_clear(l->tasks);
	ship_unlock(l);
	processor_tasks_add(olclient_notify_complete, l, olclient_notify_complete_done);
	return 0;
}


static void 
olclient_subscribe_poll_cb(char *val, int status, olclient_get_task_t *task)
{
	if (!pollers || !ship_list_find(pollers, task))
		return;
	if (!val || status < 0 || strlen(val) < 1)
		return;

	if (task->old_callback)
		task->old_callback(val, 1, task);
	else
		olclient_cb_get(val, 1, task);
}

static int 
olclient_subscribe_poll(void* data)
{
	void *ptr = NULL;
	olclient_get_task_t *task;

	if (!pollers)
		return -1;

	//ship_lock(pollers);
	while ((task = ship_list_next(pollers, &ptr))) {

		task->callback = olclient_subscribe_poll_cb;
		//if ((task->lookup->extra->verify_flags & VERIFY_SIGNER) && 
		//    task->lookup->extra->signer && task->mod->get_signed) {
		if (!task->old_callback) {
			task->mod->get_signed(task->lookup->key, task->lookup->extra->signer, task);
		} else {
			task->mod->get(task->lookup->key, task);
		}
	}
	//ship_unlock(pollers);
	return 0;
}

static int
olclient_subscribe_bypoll(char *key, olclient_get_task_t *task)
{
	ship_obj_list_add(pollers, task);
	
	/* do one immediately */
	task->old_callback = task->callback;
	task->callback = olclient_subscribe_poll_cb;
	task->mod->get(task->lookup->key, task);
	return 0;
}

static int
olclient_subscribe_signed_bypoll(char *key, olclient_signer_t *signer, olclient_get_task_t *task)
{
	ship_obj_list_add(pollers, task);
	
	/* do one immediately */
	task->old_callback = NULL;
	task->callback = olclient_subscribe_poll_cb;
	task->mod->get_signed(task->lookup->key, signer, task);
	return 0;
}

static int
olclient_unsubscribe_bypoll(olclient_get_task_t *task)
{
       	if (ship_obj_list_remove(pollers, task)) {
		//task->callback(NULL, 0, task);
		olclient_cb_get(NULL, 0, task);
	}
	return 0;
}

static int 
olclient_get_entry_do(void *data, processor_task_t **wait, int wait_for_code)
{
	int ret = -1;
	void *ptr = 0;
	struct olclient_module *mod;
	olclient_lookup_t *l = (olclient_lookup_t *)data;

	while ((mod = (struct olclient_module*)ship_list_next(olclient_modules, &ptr))) {    	    			    
		int (*fetch) (char *key, olclient_get_task_t *task) = mod->get;
		int (*fetch_signed) (char *key, olclient_signer_t *signer, olclient_get_task_t *task) = mod->get_signed;
		olclient_get_task_t *task = NULL;
	       
		if (!(task = (olclient_get_task_t *)ship_obj_new(TYPE_olclient_get_task, l)))
			continue;
		
		task->callback = olclient_cb_get;
		task->mod = mod;
		if (l->is_subscribe) {
			fetch = mod->subscribe;
			fetch_signed = mod->subscribe_signed;

			/* if it has get, but no subscribe, use the generic polling mechanism */
			if (!fetch && mod->get) {
				fetch = olclient_subscribe_bypoll;
				LOG_DEBUG("using polling to simulate subscribe for %s..\n", mod->name);
			}
			if (!fetch_signed && mod->get_signed) {
				fetch_signed = olclient_subscribe_signed_bypoll;
				LOG_DEBUG("using polling to simulate signed subscribe for %s..\n", mod->name);
			}
		}

		ship_obj_list_add(l->tasks, task);		
		/* for functions .. get_signed, get_signed_for_someone */ 
		if (l->extra->verify_flags & VERIFY_SIGNER) {
			if (l->extra->signer && fetch_signed && 
			    !fetch_signed(l->key, l->extra->signer, task)) {

				ret = 0;
			} else {
				/* if no signer, then fetch whatever and check in olclient 
				   that it is someone trusted! */
				/* module doesn't support get_signed, we call mod->get and
				   ask cb_get_signed to verify the data signature instead */
				task->callback = olclient_cb_get_signed;
				if (fetch && !fetch(l->key, task))
					ret = 0;
			} 
		} else if (fetch && !fetch(l->key, task))
			ret = 0;
		
		if (ret)
			ship_obj_list_remove(l->tasks, task);
		ship_obj_unref(task);
	}

	if (!ret) {
		ship_obj_list_add(olclient_lookups, l);
		/* add a global timeout for all the lookup modules */
		ship_obj_ref(l);
		if (!l->is_subscribe)
			processor_tasks_add_timed(olclient_get_to, l, NULL, 5000);
	}

	return ret;
}

static void 
olclient_get_entry_done(void *data, int code)
{
	olclient_lookup_t *l = (olclient_lookup_t *)data;
	ship_obj_unref(l);
}

/* request some resource from the dht / other overlay.  The resource
   will be fetched and the provided callback will be called with
   potentially more than one entry, more than one time (specified by
   the status value).

   The status value of the callback method specifies whether the
   lookup was successful, failed ro still in progress:
     0 - ok, lookup complete
     1 - ok, lookup successful, but still waiting for more values
   < 0 - some sort of error, no lookup done.
*/
static int
olclient_getsub_entry(const char *key, void *param, olclient_extra_t *extra, 
		      olclient_get_cb callback, const int subscribe)
{
	olclient_lookup_t *l = NULL;

	ASSERT_TRUE(l = (olclient_lookup_t *)ship_obj_new(TYPE_olclient_lookup, (char *)key), err);
	l->param = param;
	l->extra = extra;
	l->callback = callback;
	l->is_subscribe = subscribe;

	/* do this async, keep the l ref'd */
	ASSERT_TRUE(processor_tasks_add(olclient_get_entry_do,
					l,
					olclient_get_entry_done), err);
	return l->handle;
 err:
	ship_obj_unref(l);
	return -1;
}

void
olclient_cancel(const int handle)
{
	void *ptr = NULL;
	olclient_lookup_t *l = NULL;
	olclient_get_task_t *task = NULL;

	ship_lock(olclient_lookups);
	while ((l = ship_list_next(olclient_lookups, &ptr))) {
		if (l->handle == handle) {
			void *ptr2 = NULL;
			while ((task = ship_list_next(l->tasks, &ptr2))) {
				if (task->mod->cancel)
					task->mod->cancel(l->key, task);
				else
					olclient_unsubscribe_bypoll(task);
			}
		}
	}
	ship_unlock(olclient_lookups);
}

int 
olclient_getsub(const char *key, void *param, olclient_get_cb callback, const int subscribe)
{
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, NULL, NULL, VERIFY_NONE), err);
	return olclient_getsub_entry(key, param, extra, callback, subscribe);	
 err:
	return -1;
}

int
olclient_getsub_signed(const char *key, buddy_t *signer, void *param, 
		    olclient_get_cb callback, const int subscribe)
{
	/* verify sig */
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, NULL, signer, VERIFY_SIGNER), err);
	return olclient_getsub_entry(key, param, extra, callback, subscribe);	
 err:
	return -1;
}

int 
olclient_getsub_signed_trusted(const char *key, void *param, 
			       olclient_get_cb callback, const int subscribe)
{
	/* verify sig */
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, NULL, NULL, VERIFY_SIGNER), err);
	return olclient_getsub_entry(key, param, extra, callback, subscribe);
 err:
	return -1;
}


/* lookups something (unencrypted) using a shared secret. not used right now? */
int 
olclient_getsub_with_secret(const char *key, const char *cipher_secret, void *param, 
			 olclient_get_cb callback, const int subscribe)
{	
	/* decrypt using symm key */
	char *hmac_key64 = NULL;	
	int ret = -1;
	olclient_extra_t *extra = NULL;
	
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, cipher_secret), err);
	ASSERT_TRUE(extra = olclient_extra_new(cipher_secret, NULL, NULL, VERIFY_NONE), err);
	ASSERT_ZERO(ret = olclient_getsub_entry(hmac_key64, param, extra, callback, subscribe), err);
	extra = NULL;
 err:
	olclient_extra_free(extra);
	freez(hmac_key64);
	return ret;
}

/* lookups something that has been encrypted for the receiver using a public lookup key */
int
olclient_getsub_for_someone(const char *key, ident_t *receiver, void *param, 
			    olclient_get_cb callback, const int subscribe)
{
	/* decrypt using priv key */
	olclient_extra_t *extra;
	int ret = -1;
	
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, NULL, VERIFY_NONE), err);
	ASSERT_ZERO(ret = olclient_getsub_entry(key, param, extra, callback, subscribe), err);
	extra = NULL;
err:
	olclient_extra_free(extra);
	return ret;
}

/* lookups something encrypted using a shared secret- key */
int 
olclient_getsub_for_someone_with_secret(const char *key, ident_t *receiver, const char *shared_secret,
					void *param, olclient_get_cb callback, const int subscribe)
{	
	/* decrypt using priv */
	char *hmac_key64 = NULL;
	int ret = -1;
	olclient_extra_t *extra = NULL;

	/* hmac the key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, NULL, VERIFY_NONE), err);
	ASSERT_ZERO(ret = olclient_getsub_entry(hmac_key64, param, extra, callback, subscribe), err);
	extra = NULL;
err:
	olclient_extra_free(extra);
	freez(hmac_key64);
	return ret;
}

/* lookups something encrypted by a specific person using a shared secret- key */
int 
olclient_getsub_signed_for_someone_with_secret(const char *key, buddy_t *signer, ident_t *receiver, const char *shared_secret,
					    void *param, olclient_get_cb callback, const int subscribe)
{	
	/* verify sig, decrypt using priv */
	char *hmac_key64 = NULL;
	int ret = -1;
	olclient_extra_t *extra = NULL;
	
	/* hmac the key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, signer, VERIFY_SIGNER), err);
	ASSERT_ZERO(ret = olclient_getsub_entry(hmac_key64, param, extra, callback, subscribe), err);
	extra = NULL;
err:
	olclient_extra_free(extra);
	freez(hmac_key64);
	return ret;
}

/* lookups something using a indexing key made from the shared secret
   and that is encrypted by someone using our public key, and signed
   within the encryption */
int 
olclient_getsub_anonymous_signed_for_someone_with_secret(const char *key, buddy_t *signer, ident_t *receiver, const char *shared_secret,
						      void *param, olclient_get_cb callback, const int subscribe)
{	
	/* decrypt using priv, verify internal sig */
	char *hmac_key64 = NULL;
	int ret = -1;
	olclient_extra_t *extra = NULL;
	
	/* hmac the key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, signer, VERIFY_INTERNAL_SIGNER), err);
	ASSERT_TRUE(ret = olclient_getsub_entry(hmac_key64, param, extra, callback, subscribe) != -1, err);
	extra = NULL;
err:
	olclient_extra_free(extra);
	freez(hmac_key64);
	return ret;
}



/***************** here begins the kingdom of Put *********************/

struct olclient_put_entry_s {
	char *key; 
	char *data; 
	ident_t *signer;
	int add_cert;
	int timeout;
	char *secret;
	int cached;
};

static int
olclient_put_entry_do(void *data, processor_task_t **wait, int wait_for_code)
{
	struct olclient_module *mod;
	void *ptr = 0;
	struct olclient_put_entry_s *e = (struct olclient_put_entry_s*)data;
	int ret = -1;

	LOG_DEBUG("putting %d bytes: for key '%s'\n", strlen(e->data), e->key);
	LOG_VDEBUG("putting %d bytes: '%s'->'%s'\n", strlen(e->data), e->key, e->data);
	ship_lock(olclient_modules);
	while ((mod = ship_list_next(olclient_modules, &ptr))) {
		if (e->signer) {
			if (e->add_cert || !mod->put_signed ||
			    (ret = mod->put_signed(e->key, e->data, e->signer, 
						   e->timeout, e->secret, e->cached, mod))) {
				char *wrap_data = NULL;
				if ((wrap_data = olclient_create_signed_wrap(e->key, e->data, 
									     e->signer, e->add_cert, e->timeout))) {
					ret = mod->put(e->key, wrap_data, e->timeout, e->secret, e->cached, mod);
					free(wrap_data);
				}
			}
		} else {
			ret = mod->put(e->key, e->data, e->timeout, e->secret, e->cached, mod);
		}
	}
	ship_unlock(olclient_modules);
	
	return ret;
}

static void
olclient_put_entry_done(void *data, int code)
{
	struct olclient_put_entry_s *e = (struct olclient_put_entry_s*)data;
	if (e) {
		freez(e->key);
		freez(e->data);
		freez(e->secret);
		ship_obj_unref(e->signer);
		freez(e);
	}
}

static int
olclient_put_entry(const char *key, const char *data, ident_t *signer, const int add_cert, 
		   const int timeout, const char *secret, const int cached)
{
	struct olclient_put_entry_s *e = 0;

	ASSERT_TRUE(e = mallocz(sizeof(*e)), err);
	ASSERT_TRUE(e->key = strdupz(key), err);
	ASSERT_TRUE(e->data = strdupz(data), err);
	if (secret)
		ASSERT_TRUE(e->secret = strdupz(secret), err);
	e->signer = signer;
	ship_obj_ref(e->signer);
	e->add_cert = add_cert;
	e->timeout = timeout;
	e->cached = cached;
	
	if (processor_tasks_add(olclient_put_entry_do, e, 
				olclient_put_entry_done)) {
		e = NULL;
	}
 err:
	if (e)
		olclient_put_entry_done(e, -1);
	return 0;
}

/* plain put */
int
olclient_put(const char *key, const char *data, const int timeout, const char *secret)
{
	return olclient_put_entry(key, data, NULL, 0, timeout, secret, 0);
}

/* puts into local storage only, not the external (assume it is cached!) */
int
olclient_put_cached(const char *key, const char *data, const int timeout, const char *secret)
{
	return olclient_put_entry(key, data, NULL, 0, timeout, secret, 1);
}

/* plain immutable (no removal code) put. */
int
olclient_put_immute(const char *key, const char *data, const int timeout)
{
	return olclient_put(key, data, timeout, NULL);
}

/* sign data before put */
int 
olclient_put_signed(const char *key, const char *data, ident_t *signer, const int timeout, const char *secret) 
{
	return olclient_put_entry(key, data, signer, 0, timeout, secret, 0);
}

/* sign data, add cert */
int 
olclient_put_signed_cert(const char *key, const char *data, ident_t *signer, const int timeout, const char *secret) 
{
	return olclient_put_entry(key, data, signer, 1, timeout, secret, 0);
}

/* put, encrypted with, and index by shared secret */
int 
olclient_put_with_secret(const char *key, const char *data, const char *cipher_secret, const int timeout, const char *secret)
{
	int ret = -1;
	char *hmac_key64 = NULL;
	unsigned char *cipher_key = NULL;
	unsigned char *iv = NULL;
	unsigned char *cipher64 = NULL;
	
	/* hmac key and cipher secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, cipher_secret), err);
	
	/* encrypt the data with cipher_secret*/
	
	/* generate 16-bytes iv from a cipher_secret */
	ASSERT_TRUE(ship_hash("md5", (unsigned char*)cipher_secret, &iv), err);
	/* generate 32-bytes key from a cipher_secret */
	ASSERT_TRUE(ship_hash("sha256", (unsigned char*)cipher_secret, &cipher_key), err);
	
	ASSERT_TRUE(cipher64 = ship_encrypt64(CRYPT_ALGO, cipher_key, iv, (unsigned char*)data),err);
	
	ret = olclient_put(hmac_key64, (char*)cipher64, timeout, secret);
	free(cipher64);
err:
	freez(hmac_key64);
	freez(iv);
	freez(cipher_key);

	return ret;
}

/* put & encrypt for someone, use plain lookup key */
int 
olclient_put_for_someone(const char *key, const char *data, buddy_t *receiver, const int timeout, const char *secret)
{
	int ret = -1;
	unsigned char *value;
		
	/* encrypt the data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(data, receiver), err);
	
	ret = olclient_put(key, (char*)value, timeout, secret);
	free(value);	
err:
	return ret; 
}

/* encrypt, sign, put & use shared secret */
int 
olclient_put_signed_for_someone(const char *key, const char *data, ident_t *signer, buddy_t *receiver, 
				const char *shared_secret, const int timeout, const char *secret)
{
	int ret = -1;
	char *hmac_key64 = NULL;
	unsigned char *value = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	
	/* encrypt the data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(data, receiver), err);
	
	ret = olclient_put_signed(hmac_key64, (char*)value, signer, timeout, secret);
	free(value);
	
err:
	freez(hmac_key64);	
	
	return ret; 
}

/* sign, encrypt, put using shared secret */
int 
olclient_put_anonymous_signed_for_someone_with_secret(const char *key, const char *data, ident_t *signer, buddy_t *receiver, 
						      const char *shared_secret, const int timeout, const char *secret)
{
	int ret = -1;
	char *hmac_key64 = NULL;
	char *wrap_data = NULL;
	unsigned char *value = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	
	/* wrap data and append data signature */
	ASSERT_TRUE(wrap_data = olclient_create_signed_wrap((char*)hmac_key64, data, signer, 0, timeout), err);
	
	/* encrypt the wrap_data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(wrap_data, receiver), err);

	ret = olclient_put(hmac_key64, (char*)value, timeout, secret);	
	
err:
	freez(value);
	freez(hmac_key64);
	freez(wrap_data);
	
	return ret;
}

/* put unencrypted using shared secret */
int 
olclient_put_for_someone_with_secret(const char *key, const char *data, buddy_t *receiver, 
				     const char *shared_secret, const int timeout, const char *secret)
{
	int ret = -1;
	char *hmac_key64 = NULL;
	unsigned char *value = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	
	/* encrypt the wrap_data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(data, receiver), err);

	ret = olclient_put(hmac_key64, (char*)value, timeout, secret);	
err:
	freez(value);
	freez(hmac_key64);
	
	return ret;
}

/***********************'
 * the removes
 */

static int
olclient_remove_do(void *data, processor_task_t **wait, int wait_for_code)
{
	char *key, *secret;
        struct olclient_module *mod;
	void *ptr = 0;
	int ret = -1;
	
	ASSERT_TRUE(ship_unpack_keep(data, &key, &secret), err);
	LOG_VDEBUG("removing from dht key %s\n", key);
	//ship_lock(olclient_modules); // for python :(
	while ((mod = ship_list_next(olclient_modules, &ptr))) {
		if (!mod->remove(key, secret, mod)) {
			ret = 0;
		}
	}
	//ship_unlock(olclient_modules);
err:
	return ret;
}

static void
olclient_remove_done(void *qt, int code)
{
	ship_pack_free(qt);
}

/* plain remove .. */
int
olclient_remove(const char *key, const char* secret)
{
	ship_pack_t *pkg = NULL;
	int ret = -1;
	
	ASSERT_TRUE(pkg = ship_pack("ss", key, secret), err);
	ASSERT_TRUE(processor_tasks_add(olclient_remove_do, pkg,
					olclient_remove_done), err);
	
	pkg = NULL;
	ret = 0;
 err:
	ship_pack_free(pkg);
	return ret;
}

/* remove, with secret .. */
int
olclient_remove_with_secret(const char *key, const char *shared_secret, const char* secret)
{
	int ret = -1;
	char *hmac_key64 = NULL;
	
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	ret = olclient_remove(hmac_key64, secret);
 err:
	freez(hmac_key64);
	return ret;
}



/************************ crypto wrappers **********************/

int
olclient_parse_xml_record(char *data, char **res, char **key, time_t *expires)
{
	int ret = -1;

	char *result = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	
	ASSERT_TRUE(doc = xmlParseMemory(data, strlen(data)), err);
	ASSERT_TRUE(cur = xmlDocGetRootElement(doc), err);
	
	ASSERT_TRUE(*res = ship_xml_get_child_field(cur, "data"), err);
	ASSERT_TRUE(*key = ship_xml_get_child_field(cur, "key"), err);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "expires"), err);
	*expires = ship_parse_time(result);
	ret = 0;
 err:
	if (doc) xmlFreeDoc(doc);
	if (result) xmlFree(result);
	//xmlCleanupParser();
	return ret;
}

/*  */
int 
olclient_parse_signed_xml_record(const char *data, X509 **cert, char **signature, char **algo, char **data2)
{
	int ret = -1;
	char *result = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	
	*signature = 0;
	*algo = 0;
	*data2 = 0;
	*cert = 0;

	ASSERT_TRUE(strlen(data), err, "Empty data record!\n");
	ASSERT_TRUE(data[0] == '<', err, "Data is not XML!\n");
	ASSERT_TRUE(doc = xmlParseMemory(data, strlen(data)), err);
	ASSERT_TRUE(cur = xmlDocGetRootElement(doc), err);
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)OLCLIENT_PKG), err);
	
	/* certificate */
	if ((result = ship_xml_get_child_field(cur, "certificate"))) {
		ASSERT_TRUE(*cert = ship_parse_cert(result), err);
	} else {
		LOG_DEBUG("packet did not contain signer cert\n");
	}

	ASSERT_TRUE(*data2 = ship_xml_get_child_field(cur, "data"), err);

	ASSERT_TRUE(cur = ship_xml_get_child(cur, "signature"), err);
	ASSERT_TRUE(*signature = ship_xml_get_child_field(cur, "value"), err);
	ASSERT_TRUE(*algo = ship_xml_get_child_field(cur, "algorithm"), err);
	
	ret = 0;
	goto end;
 err:
	freez(*signature);
	freez(*algo);
	freez(*data2);
	if (*cert)
		X509_free(*cert);
 end:
	if (doc) xmlFreeDoc(doc);
	if (result) xmlFree(result);
	//xmlCleanupParser();
	return ret;
}

/* get a RSA public key, verify data signature, and returns the
   internal, un-wrapped data as a result */
static char*
olclient_verify_data_sig(olclient_signer_t *cert, const char *data, char **signer)
{
	EVP_PKEY *pkey = 0;
	RSA *pu_key = 0;
	char *res = NULL, *key = 0;
	time_t expires;
	char *data2 = 0, *data3 = 0, *signature = 0, *algo = 0;
	X509 *cert2 = 0;
	int len;

	/* remove the wrapper */
	ASSERT_ZEROS(olclient_parse_signed_xml_record(data, &cert2, &signature, &algo, &data2), err, "Record not XML or in right format!\n");
	if (!cert) {
		/* check that the signer is trusted */
		ASSERT_TRUE(cert = cert2, err);
		ASSERT_TRUE(ident_remote_cert_is_acceptable(cert), err);
	}
	
	/* check that the signature matches */
	ASSERT_ZERO(strcmp(algo, SIGN_ALGO), err);
	freez(algo);
	
	ASSERT_TRUE(pkey = X509_get_pubkey(cert), err);
	ASSERT_TRUE(pu_key = EVP_PKEY_get1_RSA(pkey), err);
	ASSERT_TRUE(algo = (char *)mallocz(SHA_DIGEST_LENGTH), err);
	ASSERT_TRUE(SHA1((unsigned char*)data2, strlen(data2), (unsigned char*)algo), err);
	ASSERT_TRUE(data3 = ship_decode_base64(signature, strlen(signature), &len), err);
	ASSERT_TRUE(RSA_verify(NID_sha1, (unsigned char*)algo, SHA_DIGEST_LENGTH, (unsigned char*)data3, len, pu_key), err, "signature mis-match!\n");
	
	/* store the signer into the signer_aor field */
	freez(data3);
	ASSERT_TRUE(data3 = ident_data_x509_get_cn(X509_get_subject_name(cert)), err);
	ASSERT_ZERO(ident_set_aor(signer, data3), err);
	
	/* parse the data */
	ASSERT_ZERO(olclient_parse_xml_record(data2, &res, &key, &expires), err);
	
	/* should we check expires / key ?? */
	
 err:
	freez(data2);
	freez(data3);
	freez(signature);
	freez(algo);
	freez(key);
	if (cert2)
		X509_free(cert2);
	
	if (pu_key)
		RSA_free(pu_key);	
	if (pkey)
		EVP_PKEY_free(pkey);
	return res;
}

static int
olclient_decrypt_for_someone(olclient_verifier_t *pr_key, const char *value, char **res_value)
{	
	int ret = -1, k = 0, key_and_iv64_len = 0, value64_len = 0, data64_len = 0;
	unsigned char *v = NULL, *t = NULL;
	unsigned char *key_and_iv64 = NULL;
	unsigned char *key_and_iv = NULL;
	unsigned char *data64 = NULL;
	unsigned char *tmp = NULL;
	unsigned char *cipher_key = NULL;
	unsigned char *iv = NULL;	
	
	/* get an RSA key size */
	ASSERT_TRUE(k = RSA_size(pr_key), err);
	
	/* calculate the size of encrypted cipher key and iv (base64 format) */
	value64_len = strlen(value);
	key_and_iv64_len = ((k + 2)/3) * 4; 
	data64_len = value64_len - key_and_iv64_len;
	if (data64_len < 0) {
		LOG_DEBUG("not enough data to contain what was expected!\n");
		goto err;
	}

	/* extract the cipher key & iv ,and data */
	key_and_iv64 = mallocz(key_and_iv64_len + 1);
	data64 = mallocz(data64_len + 1);
	v = (unsigned char*)value;
	memcpy(key_and_iv64, v, key_and_iv64_len);
	v += key_and_iv64_len;
	memcpy(data64, v, data64_len);
	
	/* decode & decrypt cipher key and iv */
	ASSERT_TRUE(key_and_iv = (unsigned char*)ship_decode_base64((char*)key_and_iv64, key_and_iv64_len, &k), err);	
	ASSERT_TRUE((k=ship_rsa_private_decrypt(pr_key, key_and_iv, &tmp))>0, err);
 
	/* extract the cipher key */
	t = tmp;
	ASSERT_TRUE(cipher_key = mallocz(EVP_MAX_KEY_LENGTH + 1), err);
	memcpy(cipher_key, t, EVP_MAX_KEY_LENGTH);
	t += EVP_MAX_KEY_LENGTH;

	/* extract the iv */
	ASSERT_TRUE(iv = mallocz(EVP_MAX_IV_LENGTH + 1), err);
	memcpy(iv, t, EVP_MAX_IV_LENGTH);

	/* decrypte the data */
	ASSERT_TRUE(*res_value = (char*)ship_decrypt64(CRYPT_ALGO, cipher_key, iv, data64), err);
	
	ret = 0;	
err: 
	freez(key_and_iv);
	freez(key_and_iv64);
	freez(data64);
	freez(tmp);
	freez(cipher_key);
	freez(iv);
	
	return ret;
}


/* this just creates a simple record */
static char*
olclient_create_wrap_xml_record(const char *key, const char *data, const int timeout)
{
	xmlDocPtr doc= NULL;
	xmlNodePtr root= NULL;
	xmlNodePtr node= NULL;
	xmlChar *buf = NULL;
	int blen = 0;
	char tmp[64];
	
	ASSERT_TRUE(doc = xmlNewDoc((const xmlChar*)"1.0"), err);
	ASSERT_TRUE(root = xmlNewNode(NULL, (const xmlChar*)"record"), err);
	xmlDocSetRootElement(doc, root);
	ASSERT_TRUE(xmlNewTextChild(root, NULL, (const xmlChar*)"key", (const xmlChar*)key), err);
	ASSERT_TRUE(node = xmlNewTextChild(root, NULL, (const xmlChar*)"data", NULL), err);
	ASSERT_TRUE(node->children = xmlNewCDataBlock(doc, (const xmlChar*)data, strlen(data)), err);
	ship_format_time(timeout + time(0), tmp, sizeof(tmp));
	ASSERT_TRUE(xmlNewTextChild(root, NULL, (const xmlChar*)"expires", (const xmlChar*)tmp), err);
	xmlDocDumpFormatMemory(doc, (xmlChar **)&buf, &blen, 1);
 err:
	if (doc) xmlFreeDoc(doc);
	//xmlCleanupParser();
	
	return (char*)buf;
}

static char*
olclient_sign_xml_record(const char *data, ident_t *ident, const int addcert)
{
	BIO *bio = NULL;
	xmlDocPtr doc = NULL;
	xmlChar *xmlbuf = NULL;
	xmlNodePtr tree = NULL;
	char *digest = NULL;
	char *sign = NULL;
	char *sign_64e = NULL;
	char *cert = NULL;
	int bufsize;
	unsigned int siglen = 0;
	char *ret = 0;
	
	ASSERT_TRUE(doc = xmlNewDoc((const xmlChar *)"1.0"), err);
	ASSERT_TRUE(doc->children = xmlNewDocNode(doc, NULL, (const xmlChar *)OLCLIENT_PKG, NULL), err);

	ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar *)"data", NULL), err);
	ASSERT_TRUE(tree->children = xmlNewCDataBlock(doc, (const xmlChar *)data, strlen(data)), err);

	/* signature */
	if (ident->private_key 
#ifdef CONFIG_OP_ENABLED
	    || ident_is_op_ident(ident)
#endif
	    ) {
		ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar *)"signature", NULL), err);
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (const xmlChar *)"algorithm", (const xmlChar *)SIGN_ALGO), err);
		
#ifdef CONFIG_OP_ENABLED
		if (ident_is_op_ident(ident)) {
			ASSERT_ZERO(opconn_sign(data, "p2pship", &sign_64e), err);
		} else {
#endif
			ASSERT_TRUE(digest = (char *)mallocz(SHA_DIGEST_LENGTH), err);
			ASSERT_TRUE(SHA1((unsigned char *)data, strlen(data), (unsigned char *)digest), err);
			ASSERT_TRUE(sign = (char *)mallocz(1024), err);	
			ASSERT_TRUE(RSA_sign(NID_sha1, (unsigned char *)digest, SHA_DIGEST_LENGTH, (unsigned char *)sign, &siglen, ident->private_key), err);
			ASSERT_TRUE(sign_64e = ship_encode_base64(sign, siglen), err);
#ifdef CONFIG_OP_ENABLED
		}
#endif
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (const xmlChar *)"value", (const xmlChar *)sign_64e), err);
	}

	/* certificate, if present! */
	if (addcert) {
		ASSERT_ZERO(ident_data_check_cert(ident), err);
		ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
		ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
		//cert[bufsize] = 0;
		//ASSERT_TRUE(xmlNewTextChild(doc->children, NULL, (const xmlChar *)"certificate", (const xmlChar *)cert), err);
		ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar *)"certificate", (const xmlChar *)""), err);
		xmlNodeAddContentLen(tree, (xmlChar*)cert, bufsize);
	}

	xmlDocDumpFormatMemory(doc, &xmlbuf, &bufsize, 1);
	ASSERT_TRUE(xmlbuf, err);
	ASSERT_TRUE(ret = (char *)mallocz(bufsize+1), err);
	strcpy(ret, (const char *)xmlbuf);
 err:	
	freez(digest);
	freez(sign);
	freez(sign_64e);

	if (bio) BIO_free(bio);
	if (xmlbuf) xmlFree(xmlbuf);
	if (doc) xmlFreeDoc(doc);
	//xmlCleanupParser();
	
	return ret;
}

static char*
olclient_create_signed_wrap(const char *key, const char *data, ident_t *signer, const int add_cert, const int timeout)
{
	char *tmp = NULL;
	char *value = NULL;
		
	ASSERT_TRUE(tmp = olclient_create_wrap_xml_record(key, data, timeout), err);
	ASSERT_TRUE(value = olclient_sign_xml_record(tmp, signer, add_cert), err);
 err:
	freez(tmp);
	return value;
}

static unsigned char*
olclient_encrypt_for_someone(const char *data, buddy_t *receiver)
{
	EVP_PKEY *pkey = NULL;
	RSA *pu_key = NULL;
	unsigned char *cipher_key = NULL;
	unsigned char *iv = NULL;
	unsigned char *key_and_iv = NULL;
	unsigned char *encrypted_key_and_iv = NULL;
	unsigned char *encrypted_key_and_iv64 = NULL;
	unsigned char *encrypted_data64 = NULL;
	unsigned char *k = NULL;
	unsigned char *value = NULL;
	unsigned char *v = NULL;
	int len = 0, total_len = 0;
	unsigned char *ret = NULL;
	
	/* generate 32-bytes key */
	ASSERT_TRUE(cipher_key = mallocz(EVP_MAX_KEY_LENGTH + 1), err);
	ASSERT_ZERO(ship_get_random (cipher_key, EVP_MAX_KEY_LENGTH), err);
	
	/* generate 16-bytes iv */
	ASSERT_TRUE(iv = mallocz(EVP_MAX_IV_LENGTH + 1), err);
	ASSERT_ZERO(ship_get_random (iv, EVP_MAX_IV_LENGTH), err);
	
	/* encrypt the data */
	ASSERT_TRUE(encrypted_data64 = ship_encrypt64(CRYPT_ALGO, cipher_key, iv, (unsigned char *)data), err);
	
	/* concatenate cipher_key + iv */
	ASSERT_TRUE(key_and_iv = mallocz(EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH + 1), err);
	k = key_and_iv;
	memcpy(k, cipher_key, EVP_MAX_KEY_LENGTH);
	k += EVP_MAX_KEY_LENGTH;
	memcpy(k, iv, EVP_MAX_IV_LENGTH);
	
	/* fetch the receiver's public key */
	ASSERT_TRUE(pkey = X509_get_pubkey(receiver->cert), err);
	ASSERT_TRUE(pu_key = EVP_PKEY_get1_RSA(pkey), err);
	
	/* encrypt the key and iv using a receiver's public key */
	ASSERT_TRUE((len=ship_rsa_public_encrypt(pu_key, key_and_iv, (EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH), &encrypted_key_and_iv))>0, err);
	ASSERT_TRUE(encrypted_key_and_iv64 = (unsigned char*)ship_encode_base64((char *)encrypted_key_and_iv, len), err);
	
	/* concatenate encryped key + encrypted data */
	total_len = strlen((char*)encrypted_key_and_iv64) + strlen((char*)encrypted_data64) + 1;
	
	ASSERT_TRUE(value = mallocz(total_len * sizeof(unsigned char)), err);
	v = value;
	memcpy(v, encrypted_key_and_iv64, strlen((char*)encrypted_key_and_iv64));
	v += strlen((char*)encrypted_key_and_iv64);
	memcpy(v, encrypted_data64, strlen((char*)encrypted_data64));

	ret = value;
	
err:
	freez(iv);
	freez(cipher_key);
	freez(encrypted_data64);
	freez(key_and_iv);
	freez(encrypted_key_and_iv);
	freez(encrypted_key_and_iv64);
	if (pkey) EVP_PKEY_free(pkey);
	if (pu_key) RSA_free(pu_key);
	
	return ret; 
}

/* the olclient register */
static struct processor_module_s processor_module = 
{
	.init = olclient_init,
	.close = olclient_close,
	.name = "olclient",
	.depends = "netio,netio_ff,netio_man,ident",
};

/* register func */
void
olclient_register() {
	processor_register(&processor_module);
}


/********* the storage backend api **********/

void
olclient_storage_entry_free(olclient_storage_entry_t* e)
{
	if (e) {
		freez(e->key);
		freez(e->data);
		freez(e->secret);
		freez(e);
	}
}

static olclient_storage_entry_t* 
olclient_storage_entry_new(char *key, char *data, int data_len, int timeout, char *secret)
{
	olclient_storage_entry_t* ret = NULL;
	ASSERT_TRUE(ret = mallocz(sizeof(olclient_storage_entry_t)), err);
	ASSERT_TRUE(ret->key = strdup(key), err);
	ASSERT_TRUE(ret->data = mallocz(data_len +1), err);
	memcpy(ret->data, data, data_len);
	ret->data_len = data_len;
	if (secret) {
		ASSERT_TRUE(ret->secret = strdup(secret), err);
	}
	ret->timeout = timeout;
	ret->created = time(0);
	return ret;
 err:
	olclient_storage_entry_free(ret);
	return NULL;
}

int 
olclient_storage_remove(char *key, char* secret)
{
	olclient_storage_entry_t* e = NULL;
	void *ptr = 0, *last = 0;
	int ret = -1;

	LOG_DEBUG("removing entry for key '%s'\n", key);
	ship_lock(entries);
	while ((e = ship_list_next(entries, &ptr))) {
		if (!strcmp(e->key, key) && 
		    ((!e->secret && !secret) ||
		     (e->secret && secret && !strcmp(e->secret, secret)))) {
			ship_list_remove(entries, e);
			olclient_storage_entry_free(e);
			ptr = last;
			ret = 0;
		} else {
			last = ptr;
		}
	}
	ship_unlock(entries);
	
	return ret;
}

static olclient_storage_entry_t*
olclient_storage_entry_dup(olclient_storage_entry_t *e)
{
	olclient_storage_entry_t* ret = olclient_storage_entry_new(e->key, e->data, e->data_len, 0, e->secret);
	if (ret) {
		ret->timeout = e->timeout;
		ret->created = e->created;
	}
	return ret;
}

/* the ownership of the entries passed is given to the caller */
int
olclient_storage_find_entries(char *key, ship_list_t *list)
{
	olclient_storage_entry_t* e = NULL;
	void *ptr = 0, *last = 0;
	int ret = 0;
	time_t now;
	ship_lock(entries);
	now = time(0);
	while ((e = ship_list_next(entries, &ptr))) {
		if (now > (e->created + e->timeout)) {
			ship_list_remove(entries, e);
			olclient_storage_entry_free(e);
			e = 0;
			ptr = last;
		}
			
		if (e && !strcmp(e->key, key)) {
			olclient_storage_entry_t *dup = olclient_storage_entry_dup(e);
			if (dup) {
				ship_list_add(list, dup);
				ret++;
			}
		}
		last = ptr;
	}
	ship_unlock(entries);
	LOG_DEBUG("found %d entries for key '%s'\n", ret, key);
	
	return ret;
}

int 
olclient_storage_put(char *key, char *data, int data_len, int timeout, char *secret)
{
	olclient_storage_entry_t* e = NULL;
	int ret = -1;
	
	/* replace old with same secret? */
	ship_lock(entries);
	e = olclient_storage_entry_new(key, data, data_len, timeout, secret);
	if (e) {
		LOG_DEBUG("storing %d bytes for key '%s' in olclient storage\n", data_len, key);
		ship_list_add(entries, e);
		ret = 0;
	}
	ship_unlock(entries);
	
	return ret;
}
