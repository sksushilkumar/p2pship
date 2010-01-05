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

typedef struct olclient_extra_s
{ 
	char *cipher_secret;

	olclient_verifier_t *receiver;

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
        void (*callback) (char *, char *, char *, void *, int);
	int status;

	/* this is where the signer's AOR will be stored after its
	   been verified .. */
	char *signer_aor;

	ship_list_t *results;
	ship_list_t *modules;

} olclient_lookup_t;

SHIP_INCLUDE_TYPE(olclient_lookup);

/*  */
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
	int (*put) (char *key, char *data, int timeout, char *secret, int cached);
	int (*get) (char *key, void *param, 
		    void (*callback) (char *val, int status, olclient_lookup_t *lookup, struct olclient_module* mod), 
		    olclient_lookup_t *lookup);
	int (*remove) (char *key, char* secret);
	int (*put_signed) (char *key, char *data, ident_t *signer, int timeout, char *secret, int cached);
	int (*get_signed) (char *key, olclient_signer_t *signer, void *param, 
			   void (*callback) (char *val, int status, olclient_lookup_t *lookup, struct olclient_module* mod), 
			   olclient_lookup_t *lookup);
	
	void (*close) (void);

	/* returns the name for the module */
	const char* (*name) ();
};


/* inits the system */
int olclient_init(processor_config_t *config);

/* shuts down */
void olclient_close();

/* overlay funcs */
int olclient_remove(char *key, char* secret);

/*
 * The puts
 */

/* normal put */
int olclient_put(char *key, char *data, int timeout, char *secret);
/* immut - cannot change afterwards */
int olclient_put_immute(char *key, char *data, int timeout);
/* sign & put */
int olclient_put_signed(char *key, char *data, ident_t *local_user, int timeout, char *secret);
/* sign & put, include your cert in the package! */
int olclient_put_signed_cert(char *key, char *data, ident_t *local_user, int timeout, char *secret);
/* put, encrypt with secret */
int olclient_put_with_secret(char *key, char *data, char *cipher_secret, int timeout, char *secret);
/* put, encrypt with public key */
int olclient_put_for_someone(char *key, char *data, buddy_t *receiver, int timeout, char *secret);
/* sign, encrypt with public key, put */
int olclient_put_signed_for_someone(char *key, char *data, ident_t *signer, buddy_t *receiver, 
				    char *shared_secret, int timeout, char *secret);
/* sign, encrypt & use secret to scramble key */
int olclient_anonymous_put_signed_for_someone(char *key, char *data, ident_t *signer, buddy_t *receiver, 
					      char *shared_secret, int timeout, char *secret);

int olclient_get(char *key, void *param, void (*callback) (char *key, char *data, char *signer, void *param, int status));
int olclient_get_signed(char *key, buddy_t *signer, void *param, 
			void (*callback) (char *key, char *data, char *signer, void *param, int status));	
/* this is gets for signed_cert-type packages */
int olclient_get_signed_trusted(char *key, void *param, 
				void (*callback) (char *key, char *data, char *signer, void *param, int status));	
int olclient_get_with_secret(char *key, char *cipher_secret, void *param, 
			     void (*callback) (char *key, char *data, char *signer, void *param, int status));
int olclient_get_for_someone(char *key, ident_t *receiver, void *param, 
			     void (*callback) (char *key, char *data, char *signer, void *param, int status));
int olclient_get_signed_for_someone(char *key, buddy_t *signer, ident_t *receiver, char *shared_secret, void *param, 
				    void (*callback) (char *key, char *data, char *signer, void *param, int status));
int olclient_anonymous_get_signed_for_someone(char *key, buddy_t *signer, ident_t *receiver, char *shared_secret, void *param, 
					      void (*callback) (char *key, char *data, char *signer, void *param, int status));

/* adding new modules to the overlay management */
int olclient_register_module(struct olclient_module* mod);
void olclient_unregister_module(struct olclient_module* mod);

/* the storage funcs */
void olclient_storage_entry_free(olclient_storage_entry_t* e);
int olclient_storage_remove(char *key, char* secret);
int olclient_storage_find_entries(char *key, ship_list_t *list);
int olclient_storage_put(char *key, char *data, int data_len, int timeout, char *secret);

#endif
