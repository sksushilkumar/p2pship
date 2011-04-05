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
 * Module containing the overlay client interface. This in turn
 * controls the dht peer (if present)
 */
#ifndef __OLCLIENT_H__
#define __OLCLIENT_H__

#include "processor_config.h"
#include "ident.h"

/* this provide some sort of abstraction.. */
typedef X509 olclient_signer_t;
typedef RSA olclient_verifier_t;

#define OLCLIENT_PKG "p2pship_olclient"

/* the verification flags */
#define VERIFY_NONE 0
#define VERIFY_SIGNER 1
#define VERIFY_INTERNAL_SIGNER 2

/* callbacks */
typedef void (*olclient_get_cb) (char *key, char *data, char *signer, void *param, int status);

struct olclient_module;

/* struct describing how to process data received from the overlay */
typedef struct olclient_extra_s
{ 
	/* encrypted w/symmetric key */
	char *cipher_secret;
	
	/* encrypted for this (private) key */
	olclient_verifier_t *receiver;

	/* signed by this (public) key */
	olclient_signer_t *signer;
	
	/* flags for how this should be verified */
	int verify_flags;

} olclient_extra_t;

typedef struct olclient_lookup_s
{ 
	ship_obj_t parent;
	
        char *key;
        void *param;
        olclient_extra_t *extra;
        olclient_get_cb callback;
	int status;

	/* this is where the signer's AOR will be stored after its
	   been verified .. */
	char *signer_aor;

	/* the to-be-reported results */
	ship_list_t *results;

	/* a cache of previous results, to prevent duplicate responses */
	ship_list_t *cache;

	/* the individual lookup tasks */
	ship_obj_list_t *tasks;

	/* whether this is a ordinary get or a subscribe */
	int is_subscribe;

} olclient_lookup_t;

SHIP_INCLUDE_TYPE(olclient_lookup);

typedef struct olclient_get_task_s olclient_get_task_t;
struct olclient_get_task_s {
	ship_obj_t parent;

	void (*callback) (char *val, int status, olclient_get_task_t *task);
	olclient_lookup_t *lookup;
	struct olclient_module* mod;
	char *id;
};

SHIP_INCLUDE_TYPE(olclient_get_task);

/* local cache  */
typedef struct olclient_storage_entry_s 
{
	char *key;
	char *data;
	int data_len;

	char *secret;
	
	time_t created;
	int timeout;
} olclient_storage_entry_t;

/* struct for the dht / storage modules */
struct olclient_module {
	
	/* the callback for the get will return with the following statuses:
	   0 ok, over & out
	   < 0 some error
	   1 ok, here's one result. more [maybe] to come
	*/
	int (*put) (char *key, char *data, int timeout, char *secret, int cached, struct olclient_module* mod);
	int (*get) (char *key, olclient_get_task_t *task);
	int (*remove) (char *key, char* secret, struct olclient_module* mod);

	int (*put_signed) (char *key, char *data, ident_t *signer, int timeout, char *secret, int cached, struct olclient_module* mod);
	int (*get_signed) (char *key, olclient_signer_t *signer, olclient_get_task_t *task);

	int (*subscribe) (char *key, olclient_get_task_t *task);
	int (*subscribe_signed) (char *key, olclient_signer_t *signer, olclient_get_task_t *task);
	int (*unsubscribe) (char *key, olclient_get_task_t *task);

	void (*close) (struct olclient_module* mod);

	/* the name for the module */
	char* name;
	/* extra data used by the lookupmodule itself */
	void *module_data;
};


/* inits the system */
int olclient_init(processor_config_t *config);
void olclient_register();

/* shuts down */
void olclient_close();

/* adding new modules to the overlay management. the ownership of the modules are kept by the caller! */
int olclient_register_module(struct olclient_module* mod /*, const char *name, void *module_data*/);
void olclient_unregister_module(struct olclient_module* mod);

/* for creating module instances from a template */
struct olclient_module* olclient_module_new(const struct olclient_module mod, const char *name, void *module_data);
void olclient_module_free(struct olclient_module* mod);

/* overlay funcs */
int olclient_remove(const char *key, const char* secret);
int olclient_remove_with_secret(const char *key, const char *shared_secret, const char* secret);

/*
 * The puts
 */

/* normal put */
int olclient_put(const char *key, const char *data, const int timeout, const char *secret);
int olclient_put_cached(const char *key, const char *data, const int timeout, const char *secret);
/* immut - cannot change afterwards */
int olclient_put_immute(const char *key, const char *data, const int timeout);
/* sign & put */
int olclient_put_signed(const char *key, const char *data, ident_t *local_user, const int timeout, const char *secret);
/* sign & put, include your cert in the package! */
int olclient_put_signed_cert(const char *key, const char *data, ident_t *local_user, const int timeout, const char *secret);
/* put, encrypt with secret */
int olclient_put_with_secret(const char *key, const char *data, const char *cipher_secret, const int timeout, const char *secret);
/* put, encrypt with public key */
int olclient_put_for_someone(const char *key, const char *data, buddy_t *receiver, const int timeout, const char *secret);
/* sign, encrypt with public key, put */
int olclient_put_signed_for_someone(const char *key, const char *data, ident_t *signer, buddy_t *receiver, 
				    const char *shared_secret, const int timeout, const char *secret);
/* sign, encrypt & use secret to scramble key */
int olclient_put_anonymous_signed_for_someone_with_secret(const char *key, const char *data, ident_t *signer, buddy_t *receiver, 
							  const char *shared_secret, const int timeout, const char *secret);

/*
 * The gets and publish
 */

int olclient_getsub(const char *key, void *param, olclient_get_cb callback, const int subscribe);
int olclient_getsub_signed(const char *key, buddy_t *signer, void *param,
			olclient_get_cb callback, const int subscribe);
/* this is gets for signed_cert-type packages */
int olclient_getsub_signed_trusted(const char *key, void *param, 
				   olclient_get_cb callback, const int subscribe);
int olclient_getsub_with_secret(const char *key, const char *cipher_secret, void *param, 
				olclient_get_cb callback, const int subscribe);
int olclient_getsub_for_someone(const char *key, ident_t *receiver, void *param, 
				olclient_get_cb callback, const int subscribe);
int olclient_getsub_signed_for_someone(const char *key, buddy_t *signer, ident_t *receiver, const char *shared_secret, void *param, 
				       olclient_get_cb callback, const int subscribe);
int olclient_getsub_anonymous_signed_for_someone_with_secret(const char *key, buddy_t *signer, 
							     ident_t *receiver, const char *shared_secret,
							     void *param, olclient_get_cb callback, const int subscribe);
void olclient_cb_state_change(struct olclient_module* module, int status, char *info);

/* macros */
#define olclient_get(key, param, callback) olclient_getsub(key, param, callback, 0)
#define olclient_get_signed(key, signer, param, callback) olclient_getsub_signed(key, signer, param, callback, 0)
#define olclient_get_signed_trusted(key, param, callback) olclient_getsub_signed_trusted(key, param, callback, 0)
#define olclient_get_with_secret(key, shared_secret, param, callback) olclient_getsub_with_secret(key, shared_secret, param, callback, 0)
#define olclient_get_for_someone(key, receiver, param, callback) olclient_getsub_for_someone(key, receiver, param, callback, 0)
#define olclient_get_signed_for_someone(key, signer, receiver, shared_secret, param, callback) olclient_getsub_signed_for_someone(key, signer, receiver, shared_secret, param, callback, 0)
#define olclient_get_anonymous_signed_for_someone_with_secret(key, signer, receiver, shared_secret, param, callback) olclient_getsub_anonymous_signed_for_someone_with_secret(key, signer, receiver, shared_secret, param, callback, 0)

#define olclient_subscribe(key, param, callback) olclient_getsub(key, param, callback, 1)
#define olclient_subscribe_signed(key, signer, param, callback) olclient_getsub_signed(key, signer, param, callback, 1)
#define olclient_subscribe_signed_trusted(key, param, callback) olclient_getsub_signed_trusted(key, param, callback, 1)
#define olclient_subscribe_with_secret(key, shared_secret, param, callback) olclient_getsub_with_secret(key, shared_secret, param, callback, 1)
#define olclient_subscribe_for_someone(key, receiver, param, callback) olclient_getsub_for_someone(key, receiver, param, callback, 1)
#define olclient_subscribe_signed_for_someone(key, signer, receiver, shared_secret, param, callback) olclient_getsub_signed_for_someone(key, signer, receiver, shared_secret, param, callback, 1)
#define olclient_subscribe_anonymous_signed_for_someone_with_secret(key, signer, receiver, shared_secret, param, callback) olclient_getsub_anonymous_signed_for_someone_with_secret(key, signer, receiver, shared_secret, param, callback, 1)

void olclient_unsubscribe(const char *key, void *param, olclient_get_cb callback);


/* 
 * the storage funcs 
 */
void olclient_storage_entry_free(olclient_storage_entry_t* e);
int olclient_storage_remove(char *key, char* secret);
int olclient_storage_find_entries(char *key, ship_list_t *list);
int olclient_storage_put(char *key, char *data, int data_len, int timeout, char *secret);

#endif
