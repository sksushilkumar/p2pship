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

/* the crypt functions */
static unsigned char* olclient_encrypt_for_someone(char *key, char *data, buddy_t *receiver);
static char* olclient_create_signed_wrap(char *key, char *data, ident_t *signer, int add_cert, int timeout);
static char* olclient_sign_xml_record(char *data, RSA *pr_key, X509 *cert);
static char* olclient_create_wrap_xml_record(char *key, char *data, int timeout);
static int olclient_decrypt_for_someone(olclient_verifier_t *pr_key, char *value, char **res_value);
static char *olclient_verify_data_sig(olclient_signer_t *cert, char *data, char **signer);

static ship_obj_list_t *olclient_lookups = 0;
static ship_list_t *olclient_modules = 0;

static ship_list_t *entries = NULL;

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
	processor_event_generate("ol_state_update", NULL, NULL);
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
	ship_obj_list_free(l->tasks);
	olclient_extra_free(l->extra);
	freez(l->key);
	freez(l->signer_aor);
}

static olclient_extra_t *
olclient_extra_new(char *cipher_secret, ident_t *receiver, 
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
	if (receiver)
		ret->receiver = RSAPrivateKey_dup(receiver->private_key);
	return ret;
 err:
	olclient_extra_free(ret);
	return NULL;
}

static int 
olclient_lookup_init(olclient_lookup_t *ret, char *key)
{
        ASSERT_TRUE(ret->key = strdup(key), err);
        ASSERT_TRUE(ret->tasks = ship_obj_list_new(), err);
        ASSERT_TRUE(ret->results = ship_list_new(), err);
	ret->status = -1;
        return 0;
     err:
        return -1;
}

/* registers a new module */
int
olclient_register_module(struct olclient_module* mod /*, const char *name, void *module_data */)
{
	ship_list_remove(olclient_modules, mod);
	ship_list_add(olclient_modules, mod);
	return 0;

	/*
	int ret = -1;
	struct olclient_module *copy = mallocz(sizeof(*copy));
	memcpy(copy, mod, sizeof(*copy));
	ASSERT_TRUE(copy->name = strdup(name), err);
	copy->module_data = module_data;
	ship_list_add(olclient_modules, copy);
	copy = 0;
	ret = 0;
 err:
	freez(copy);
	return ret;
	*/
}

/* de-registers a new module */
void
olclient_unregister_module(struct olclient_module* mod /*const char *name, void *module_data*/)
{
	ship_list_remove(olclient_modules, mod);

	/* todo: go through the unfinished calls, remove this from those also! */

	/*
	void *ptr = 0;
	struct olclient_module *m = 0;
	ship_lock(olclient_modules);
	while (m = ship_list_next(olclient_modules, &ptr)) {
		if (!strcmp(name, m->name) && (m->module_data == module_data)) {
			ship_list_remove(olclient_modules, m);
			break;
		}
	}
	ship_unlock(olclient_modules);
	*/
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
}

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
			ship_list_add(l->results, value);  
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
	}

	ship_obj_list_clear(l->tasks);
	ship_unlock(l);
	processor_tasks_add(olclient_notify_complete, l, olclient_notify_complete_done);
	return 0;
}



static void olclient_get_entry_done(void *qt, int code);
static int olclient_get_entry_do(void *data, processor_task_t **wait, int wait_for_code);


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
olclient_get_entry(char *key, void *param,  olclient_extra_t *extra, 
		   void (*callback) (char *key, char *data, char *signer, void *param, int status))
{
	/* do this async */
	void **arr = mallocz(4 * sizeof(void *));
	ASSERT_TRUE(arr && (arr[0] = strdup(key)), err);
	arr[1] = param;
	arr[2] = extra;
	arr[3] = callback;

	ASSERT_TRUE(processor_tasks_add(olclient_get_entry_do,
					arr, 
					olclient_get_entry_done), err);
	return 0;
 err:
	if (arr)
		freez(arr[1]);
	freez(arr);
	return -1;
}

static void 
olclient_get_entry_done(void *data, int code)
{
	void **arr = data;
	char *key = arr[0];
	void *param = arr[1];
	void (*callback) (char *key, char *data, char *signer, void *param, int status) = arr[3];

	if (code) {
		callback(key, 0, 0, param, -1);
	}
	freez(key);
	freez(arr);
}
 
static int 
olclient_get_entry_do(void *data, processor_task_t **wait, int wait_for_code)
{
	int ret = -1;
	void *ptr = 0;
	struct olclient_module *mod;
	olclient_lookup_t *l;

	void **arr = data;
	char *key = arr[0];
	void *param = arr[1];
	olclient_extra_t *extra = arr[2];
	void (*callback) (char *key, char *data, char *signer, void *param, int status) = arr[3];

	ASSERT_TRUE(l = (olclient_lookup_t *)ship_obj_new(TYPE_olclient_lookup, key), err);
	l->param = param;
	l->extra = extra;
	l->callback = callback;
	while ((mod = (struct olclient_module*)ship_list_next(olclient_modules, &ptr))) {    	    			    
		olclient_get_task_t *task = (olclient_get_task_t *)ship_obj_new(TYPE_olclient_get_task, l);
		if (!task)
			continue;

		task->callback = olclient_cb_get;
		task->mod = mod;
		ship_obj_list_add(l->tasks, task);
		
		// todo: ! this needs to be refd in get_task's constructor
		//ship_obj_ref(l);
		
		/* for functions .. get_signed, get_signed_for_someone */ 
		if (l->extra->verify_flags & VERIFY_SIGNER) {
			if (l->extra->signer && // if no signer, then just verify that it is someone trusted!
			    mod->get_signed && 
			    !mod->get_signed(key, l->extra->signer, task))
				ret = 0;
			/* module doesn't support get_signed, we call mod->get and
			 * ask cb_get_signed to verify the data signature instead */
			else {
				task->callback = olclient_cb_get_signed;
				if (!mod->get(key, task))
					ret = 0;
			} 
		} else if (!mod->get(key, task))
			ret = 0;
		
		if (ret)
			ship_obj_list_remove(l->tasks, task);
		ship_obj_unref(task);
	}

	/* todo: should we actually just store the tasks and put timeouts on those instead? */

	if (!ret) {
		ship_obj_list_add(olclient_lookups, l);
		/* add a global timeout for all the lookup modules */

		ship_obj_ref(l);
		processor_tasks_add_timed(olclient_get_to, l, NULL, 5000);
	}
 err:
	ship_obj_unref(l);
	return ret;
}

int 
olclient_get(char *key, void *param, 
             void (*callback) (char *key, char *data, char *signer, void *param, int status))
{
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, NULL, NULL, VERIFY_NONE), err);
	return olclient_get_entry(key, param, extra, callback);	
 err:
	return -1;
}

int
olclient_get_signed(char *key, buddy_t *signer, void *param, 
		    void (*callback) (char *key, char *data, char *signer, void *param, int status))
{
	/* verify sig */
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, NULL, signer, VERIFY_SIGNER), err);
	return olclient_get_entry(key, param, extra, callback);	
 err:
	return -1;
}

int 
olclient_get_signed_trusted(char *key, void *param, 
			    void (*callback) (char *key, char *data, char *signer, void *param, int status))
{
	/* verify sig */
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, NULL, NULL, VERIFY_SIGNER), err);
	return olclient_get_entry(key, param, extra, callback);
 err:
	return -1;
}
 
int 
olclient_get_with_secret(char *key, char *cipher_secret, void *param, 
			 void (*callback) (char *key, char *data, char *signer, void *param, int status))
{	
	/* decrypt using symm key */
	unsigned char *hmac_key = NULL;
	unsigned char *hmac_key64 = NULL;	
	int klen = 0;
	int ret = -1;
	olclient_extra_t *extra;
	
	/* hmac the key and cipher secret */
	ASSERT_TRUE(hmac_key = mallocz(SHA_DIGEST_LENGTH * sizeof(unsigned char) + 1), err);
	ASSERT_TRUE(HMAC(EVP_sha1(), cipher_secret, strlen(cipher_secret), (unsigned char*)key, strlen(key), hmac_key, (unsigned int*)&klen), err);
	ASSERT_TRUE(hmac_key64 = (unsigned char*)ship_encode_base64((char *)hmac_key, klen), err);
	
	ASSERT_TRUE(extra = olclient_extra_new(cipher_secret, NULL, NULL, VERIFY_NONE), err);
	ret = olclient_get_entry((char *)hmac_key64, param, extra, callback);
 err:
	freez(hmac_key);
	return ret;
}

int
olclient_get_for_someone(char *key, ident_t *receiver, void *param, 
			 void (*callback) (char *key, char *data, char *signer, void *param, int status))
{
	/* decrypt using priv key */
	olclient_extra_t *extra;
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, NULL, VERIFY_NONE), err);
	return olclient_get_entry(key, param, extra, callback);	
 err:
	return -1;
}

int 
olclient_get_for_someone_with_secret(char *key, ident_t *receiver, char *shared_secret,
				     void *param, void (*callback) (char *key, char *data, char *signer, void *param, int status))
{	
	/* decrypt using priv */
	unsigned char *hmac_key = NULL;
	unsigned char *hmac_key64 = NULL;
	int klen = 0;
	int ret = -1;
	olclient_extra_t *extra;

	/* hmac the key and shared secret */
	ASSERT_TRUE(hmac_key = mallocz(SHA_DIGEST_LENGTH * sizeof(unsigned char) + 1), err);
	ASSERT_TRUE(HMAC(EVP_sha1(), shared_secret, strlen(shared_secret), (unsigned char*)key, strlen(key), hmac_key, (unsigned int*)&klen), err);
	ASSERT_TRUE(hmac_key64 = (unsigned char*)ship_encode_base64((char*)hmac_key, klen), err);
	
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, NULL, VERIFY_NONE), err);
	ret = olclient_get_entry((char*)hmac_key64, param, extra, callback);
 err:
	freez(hmac_key);
	return ret;
}

int 
olclient_get_signed_for_someone_with_secret(char *key, buddy_t *signer, ident_t *receiver, char *shared_secret,
					    void *param, void (*callback) (char *key, char *data, char *signer, void *param, int status))
{	
	/* verify sig, decrypt using priv */
	unsigned char *hmac_key = NULL;
	unsigned char *hmac_key64 = NULL;
	int klen = 0;
	int ret = -1;
	olclient_extra_t *extra;
	
	/* hmac the key and shared secret */
	ASSERT_TRUE(hmac_key = mallocz(SHA_DIGEST_LENGTH * sizeof(unsigned char) + 1), err);
	ASSERT_TRUE(HMAC(EVP_sha1(), shared_secret, strlen(shared_secret), (unsigned char*)key, strlen(key), hmac_key, (unsigned int*)&klen), err);
	ASSERT_TRUE(hmac_key64 = (unsigned char*)ship_encode_base64((char*)hmac_key, klen), err);
	
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, signer, VERIFY_SIGNER), err);
	ret = olclient_get_entry((char*)hmac_key64, param, extra, callback);
err:
	freez(hmac_key);
	return ret;
}

int 
olclient_get_anonymous_signed_for_someone_with_secret(char *key, buddy_t *signer, ident_t *receiver, char *shared_secret,
						      void *param, void (*callback) (char *key, char *data, char *signer, void *param, int status))
{	
	/* decrypt using priv, verify internal sig */
	unsigned char *hmac_key = NULL;
	unsigned char *hmac_key64 = NULL;
	int klen = 0;
	int ret = -1;
	olclient_extra_t *extra;
	
	/* hmac the key and shared secret */
	ASSERT_TRUE(hmac_key = mallocz(SHA_DIGEST_LENGTH * sizeof(unsigned char) + 1), err);
	ASSERT_TRUE(HMAC(EVP_sha1(), shared_secret, strlen(shared_secret), (unsigned char*)key, strlen(key), hmac_key, (unsigned int*)&klen), err);
	ASSERT_TRUE(hmac_key64 = (unsigned char*)ship_encode_base64((char *)hmac_key, klen), err);
	
	ASSERT_TRUE(extra = olclient_extra_new(NULL, receiver, signer, VERIFY_INTERNAL_SIGNER), err);
	ret = olclient_get_entry((char *)hmac_key64, param, extra, callback);
err:
	freez(hmac_key);
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
olclient_put_entry(char *key, char *data, ident_t *signer, int add_cert, int timeout, char *secret, int cached)
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

int
olclient_put(char *key, char *data, int timeout, char *secret)
{
	return olclient_put_entry(key, data, NULL, 0, timeout, secret, 0);
}

/* this isn't used right now (should be tied to the autoreg_load thing) */
/*
int
olclient_put_cached(char *key, char *data, int timeout, char *secret)
{
	return olclient_put_entry(key, data, NULL, 0, timeout, secret, 1);
}
*/

int
olclient_put_immute(char *key, char *data, int timeout)
{
	return olclient_put(key, data, timeout, NULL);
}

int 
olclient_put_signed(char *key, char *data, ident_t *signer, int timeout, char *secret) 
{
	return olclient_put_entry(key, data, signer, 0, timeout, secret, 0);
}

int 
olclient_put_signed_cert(char *key, char *data, ident_t *signer, int timeout, char *secret) 
{
	return olclient_put_entry(key, data, signer, 1, timeout, secret, 0);
}

int 
olclient_put_with_secret(char *key, char *data, char *cipher_secret, int timeout, char *secret)
{
	int ret = -1;
	unsigned char *hmac_key64 = NULL;
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
	
	ret = olclient_put((char*)hmac_key64, (char*)cipher64, timeout, secret);
	free(cipher64);
err:
	freez(hmac_key64);
	freez(iv);
	freez(cipher_key);

	return ret;
}

int 
olclient_put_for_someone(char *key, char *data, buddy_t *receiver, int timeout, char *secret)
{
	int ret = -1;
	unsigned char *value;
		
	/* encrypt the data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(key, data, receiver), err);
	
	ret = olclient_put(key, (char*)value, timeout, secret);
	free(value);	
err:
	return ret; 
}

int 
olclient_put_signed_for_someone(char *key, char *data, ident_t *signer, buddy_t *receiver, 
				char *shared_secret, int timeout, char *secret)
{
	int ret = -1;
	unsigned char *hmac_key64 = NULL;
	unsigned char *value = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	
	/* encrypt the data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(key, data, receiver), err);
	
	ret = olclient_put_signed((char*)hmac_key64, (char*)value, signer, timeout, secret);
	free(value);
	
err:
	freez(hmac_key64);	
	
	return ret; 
}

int 
olclient_put_anonymous_signed_for_someone_with_secret(char *key, char *data, ident_t *signer, buddy_t *receiver, 
						      char *shared_secret, int timeout, char *secret)
{
	int ret = -1;
	unsigned char *hmac_key64 = NULL;
	char *wrap_data = NULL;
	unsigned char *value = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	
	/* wrap data and append data signature */
	ASSERT_TRUE(wrap_data = olclient_create_signed_wrap((char*)hmac_key64, data, signer, 0, timeout), err);
	
	/* encrypt the wrap_data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(key, wrap_data, receiver), err);

	ret = olclient_put((char*)hmac_key64, (char*)value, timeout, secret);	
	
err:
	freez(value);
	freez(hmac_key64);
	freez(wrap_data);
	
	return ret;
}

int 
olclient_put_for_someone_with_secret(char *key, char *data, buddy_t *receiver, 
				     char *shared_secret, int timeout, char *secret)
{
	int ret = -1;
	unsigned char *hmac_key64 = NULL;
	unsigned char *value = NULL;
	
	/* hmac key and shared secret */
	ASSERT_TRUE(hmac_key64 = ship_hmac_sha1_base64(key, shared_secret), err);
	
	/* encrypt the wrap_data with receiver's public key */
	ASSERT_TRUE(value = olclient_encrypt_for_someone(key, data, receiver), err);

	ret = olclient_put((char*)hmac_key64, (char*)value, timeout, secret);	
err:
	freez(value);
	freez(hmac_key64);
	
	return ret;
}

int
olclient_remove(char *key, char* secret)
{
        struct olclient_module *mod;
	void *ptr = 0;
	int ret = -1;
	
	LOG_VDEBUG("removing from dht key %s\n", key);
	ship_lock(olclient_modules);
	while ((mod = ship_list_next(olclient_modules, &ptr))) {
		if (!mod->remove(key, secret, mod)) {
			ret = 0;
		}
	}
	ship_unlock(olclient_modules);
	
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
olclient_parse_signed_xml_record(char *data, X509 **cert, char **signature, char **algo, char **data2)
{
	int ret = -1;
	BIO *bio_cert = NULL;
	char *result = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	
	*signature = 0;
	*algo = 0;
	*data2 = 0;
	*cert = 0;

	ASSERT_TRUE(doc = xmlParseMemory(data, strlen(data)), err);
	ASSERT_TRUE(cur = xmlDocGetRootElement(doc), err);
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)OLCLIENT_PKG), err);
	
	/* certificate */
	if ((result = ship_xml_get_child_field(cur, "certificate"))) {
		ASSERT_TRUE(bio_cert = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(BIO_puts(bio_cert, result) > 0, err);
		ASSERT_TRUE(*cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL), err);
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
	if (bio_cert) BIO_free(bio_cert);
	if (doc) xmlFreeDoc(doc);
	if (result) xmlFree(result);
	//xmlCleanupParser();
	return ret;
}

/* get a RSA public key, verify data signature, and returns the
   internal, un-wrapped data as a result */
static char*
olclient_verify_data_sig(olclient_signer_t *cert, char *data, char **signer)
{
	EVP_PKEY *pkey = 0;
	RSA *pu_key = 0;
	char *res = NULL, *key = 0;
	time_t expires;
	char *data2 = 0, *data3 = 0, *signature = 0, *algo = 0;
	X509 *cert2 = 0;
	int len;

	/* remove the wrapper */
	ASSERT_ZERO(olclient_parse_signed_xml_record(data, &cert2, &signature, &algo, &data2), err);
	if (!cert) {
		/* check that the signer is trusted */
		ASSERT_TRUE(cert = cert2, err);
		ASSERT_TRUE(ident_cert_is_trusted(cert), err);
		ASSERT_TRUE(ident_cert_is_valid(cert), err);
	}
	
	/* check that the signature matches */
	ASSERT_ZERO(strcmp(algo, SIGN_ALGO), err);
	freez(algo);
	
	ASSERT_TRUE(pkey = X509_get_pubkey(cert), err);
	ASSERT_TRUE(pu_key = EVP_PKEY_get1_RSA(pkey), err);
	ASSERT_TRUE(algo = (char *)mallocz(SHA_DIGEST_LENGTH), err);
	ASSERT_TRUE(SHA1((unsigned char*)data2, strlen(data2), (unsigned char*)algo), err);
	ASSERT_TRUE(data3 = ship_decode_base64(signature, strlen(signature), &len), err);
	ASSERT_TRUE(RSA_verify(NID_sha1, (unsigned char*)algo, SHA_DIGEST_LENGTH, (unsigned char*)data3, len, pu_key), err);
	
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
olclient_decrypt_for_someone(olclient_verifier_t *pr_key, char *value, char **res_value)
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
olclient_create_wrap_xml_record(char *key, char *data, int timeout)
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
olclient_sign_xml_record(char *data, RSA *pr_key, X509 *xcert)
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
	if (pr_key) {
		ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar *)"signature", NULL), err);
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (const xmlChar *)"algorithm", (const xmlChar *)SIGN_ALGO), err);
		
		ASSERT_TRUE(digest = (char *)mallocz(SHA_DIGEST_LENGTH), err);
		ASSERT_TRUE(SHA1((unsigned char *)data, strlen(data), (unsigned char *)digest), err);
		ASSERT_TRUE(sign = (char *)mallocz(1024), err);	
		ASSERT_TRUE(RSA_sign(NID_sha1, (unsigned char *)digest, SHA_DIGEST_LENGTH, (unsigned char *)sign, &siglen, pr_key), err);
		ASSERT_TRUE(sign_64e = ship_encode_base64(sign, siglen), err);
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (const xmlChar *)"value", (const xmlChar *)sign_64e), err);
	}

	/* certificate, if present! */
	if (xcert) {
		ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(PEM_write_bio_X509(bio, xcert), err);
		ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
		cert[bufsize] = 0;
		ASSERT_TRUE(xmlNewTextChild(doc->children, NULL, (const xmlChar *)"certificate", (const xmlChar *)cert), err);
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
olclient_create_signed_wrap(char *key, char *data, ident_t *signer, int add_cert, int timeout)
{
	char *tmp = NULL;
	char *value = NULL;
		
	ASSERT_TRUE(tmp = olclient_create_wrap_xml_record(key, data, timeout), err);
	value = olclient_sign_xml_record(tmp, signer->private_key, (add_cert? signer->cert : NULL));
 err:
	freez(tmp);
	return value;
}

static unsigned char*
olclient_encrypt_for_someone(char *key, char *data, buddy_t *receiver)
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

