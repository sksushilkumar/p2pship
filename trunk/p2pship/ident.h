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
#ifndef __IDENT_H__
#define __IDENT_H__
#include <stdio.h>

#include <dirent.h>
#include <fcntl.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dsa.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <netinet/in.h>

#include "processor_config.h"
#include "ship_utils.h"
#include "ident_addr.h"
#include "ship_debug.h"
#include "processor.h"

#ifdef CONFIG_BLOOMBUDDIES_ENABLED
/* how many levels of bloombuddies do we store .. */
#define BLOOMBUDDY_MAX_LEVEL 5

/* defines the size of the bloom filters in use */
#define BLOOMBUDDIES_BLOOM_SIZE 2048
#endif

/* how ca / idents may have been modified */
#define MODIF_NONE 0
#define MODIF_NEW 1
#define MODIF_CHANGED 2
#define MODIF_DELETED 3

/* dirs. todo: set these during ./configure */
#define REG_PKG "reg-pkg"
#define SIGN_ALGO "sha1WithRSAEncryption"

enum {
        IDENT_UNKNOWN = 0,
        IDENT_UNREGISTERED,
        IDENT_REGISTERED
};

/* sipp ua mode */
enum {
        OPEN = 0,
        RELAX,
        PARANOID
};

/* how much skew to forgive between the clocks of different devices */
#define TIME_APPROX (60 * 15)


/* 
   Parsing of normal strings to addr_t types. Accepted type of
   strings:

   192.23.23.12 (inet4, no port, no type)
   192.23.23.12:1234 (inet4, no type)
   192.23.23.12:1234;type=tcp (inet4, tcp with port)

   the.long.host.name.or.horror.com:1234;type=udp (inet4, udp, port 1234)
   [the.long.host.name.or.horror.com]:1234;type=udp (inet6, udp, port 1234)
   
   [3ffe::1]:1234;type=tcp (inet6, tcp, port 1234)
   
   not acceptable:

   192.23.23.12;type=tcp (inet4, tcp but no port!)
*/

/* functions for converting between formats: */
SHIP_INCLUDE_TYPE(ident_addr_lookup);
int ident_addr_sa_to_addr(struct sockaddr *sa, socklen_t sa_len, addr_t *addr);
int ident_addr_str_to_addr(char *str, addr_t* addr);
int ident_addr_addr_to_str(addr_t *addr, char **str);
int ident_addr_addr_to_sa(addr_t *addr, struct sockaddr **sa, socklen_t *sa_len);
int ident_addr_str_to_sa(char *str, struct sockaddr **sa, socklen_t *sa_len);
int ident_addr_sa_to_str(struct sockaddr *sa, socklen_t sa_len, char *str);
int ident_load_ident_xml(xmlNodePtr cur, void *ptr);
int ident_addr_str_to_addr_lookup(char *str, addr_t* addr);

/* more: */
void ident_addr_in6_to_addr(struct in6_addr*, addr_t*);
int ident_addr_cmp(addr_t*, addr_t*);


/* a contact */
typedef struct contact_s
{
	char *name;
	char *sip_aor;

	/* params */
	ship_ht_t *params;

	char *db_id;
	time_t added;
}
contact_t;

/* a CA */
typedef struct ca_s
{
	ship_lock_t lock;

	char *name;
	char *digest;

	X509 *cert;

	/* indicates that the ident has changed after being saved /
	   loaded from file */
	int modified;
}
ca_t;

/* A registration package - local or remote */
typedef struct reg_package_s
{
  	ship_lock_t lock;

	char *sip_aor;

	ship_list_t *ip_addr_list;
	ship_list_t *rvs_addr_list;
	ship_list_t *hit_addr_list;

	/* validity */	
	time_t created;
	time_t valid;

	/* when it was imported */
	time_t imported;

	X509 *cert;

	/* the name extracted from the cert */
	char *name;

	/* a small field with some status information */
	char *status;

	/* mark indicating that although the info can be used, this
	   really should be updated.. */
	int need_update;
}
reg_package_t;

/* the data needed for a single port listener */
typedef struct conn_listener_s
{
	/* includes whether we use tcp / udp */
	addr_t addr;
        int socket;

	char *queued_data;
	int queued_data_len;
} conn_listener_t;

/* A buddy */

typedef struct buddy_s
{
	char *name;
	char *sip_aor;
	X509 *cert;
	char *shared_secret;

	/* this defines whether we should query for a secret or not 
	   0 - query
	   1 - do not query
	   2 - query everytime ?
	*/
	//int query_secret;

	/* this is used when trying to agree on a secret */ 
	char *my_suggestion;
	//char *got_suggestion;

	/* validity of subscribes. Yes, these are highly sip-specific,
	   but ok for now ..  */	
	time_t created;
	int expire;

	char *callid;

#ifdef CONFIG_BLOOMBUDDIES_ENABLED
	/* the bloomfilters of this guy's friends */
	ship_bloom_t *friends[BLOOMBUDDY_MAX_LEVEL];

	/* is this is a buddy we trust (or we have initiated the
	   contact) or some random person that has called us */
	int is_friend;
#endif

}
buddy_t;

/* whether this is a on-the-fly ident, not to be saved in the xml
   file */
#define IDENT_FLAG_NO_SAVE 2
/* is an identity whose keys are managed by the op system */

#ifdef CONFIG_OP_ENABLED
#define IDENT_FLAG_OP_IDENT 4
/* is an identity that should use the op system as additional
   credentials */
#define IDENT_FLAG_OP_VERIFY 8
#endif

/* if the ident has a self-signed cert (do not save the cert and
   possible to re-create it */
#define IDENT_FLAG_SELF_SIGNED 16

#define IDENT_HAS_FLAG(ident, flag) ((ident)->flags & flag)
#define IDENT_SET_FLAG(ident, flag) ((ident)->flags |= flag)
#define IDENT_CLEAR_FLAG(ident, flag) ((ident)->flags &= ~flag)

#define ident_is_modified(ident) IDENT_HAS_FLAG(ident, IDENT_FLAG_MODIFIED)
#define ident_is_no_save(ident) IDENT_HAS_FLAG(ident, IDENT_FLAG_NO_SAVE)
#ifdef CONFIG_OP_ENABLED
#define ident_is_op_ident(ident) IDENT_HAS_FLAG(ident, IDENT_FLAG_OP_IDENT)
#define ident_is_op_verify(ident) IDENT_HAS_FLAG(ident, IDENT_FLAG_OP_VERIFY)
#endif
#define ident_is_self_signed(ident) IDENT_HAS_FLAG(ident, IDENT_FLAG_SELF_SIGNED)

/* An local identity */
typedef struct ident_s
{
	ship_obj_t parent;

	char *sip_aor;
	char *username;
	char *password;

	/* todo op: we should have some sort of flag here indicating
	   whether the key should be taken from op */

	unsigned int flags;

	RSA *private_key;
	X509 *cert;
	ship_list_t *buddy_list;

	/* the following are actually service-specific */
	ship_ht_t *services;

	/* the status for this user */
	char *status;

        /* 
	   The reg package for this identity, created when getting the
	   register request.
        */
        reg_package_t *reg;

	/* indicates that the ident has changed after being saved /
	   loaded from file */
	int modified;
	
	/* the last time the registration was published */
	time_t published;
}
ident_t;

SHIP_INCLUDE_TYPE(ident);

#include "services.h"

typedef struct ident_service_s
{
	/* the service type and service obj */
	service_type_t service_type;
	
	/* the service handler - when loading from the autosave, it
	   will only be the service handler id which should be mapped
	   to a real handler */
	char *service_handler_id;
	
	service_t *service;

	/* for how long, < 0 for 'forever' */
	int expire;
	
	/* when registered. this+expire-now() = timeleft */
	time_t reg_time;

        /* this is the contact address which the sip application gives,
           indicating where it wants to be contacted. udp, ipv4 */
	addr_t contact_addr;

        /* service-specific data.. */
	void *pkg;

} ident_service_t;

/* functions for converting from xml to struct and back */
int ident_get_reg_pkg_xml(reg_package_t *reg, ident_t *ident, char **text);
int ident_get_reg_pkg_struct_file(reg_package_t **reg, const char *docname);
int ident_get_reg_pkg_struct_memory(reg_package_t **reg, const char *data);

/* ident package handling */
int ident_get_ident_xml(ident_t *ident, char **text);
int ident_get_ident_struct_file(ident_t **ident, const char *docname);
int ident_get_ident_struct_memory(ident_t **ident, const char *data);

/* returns the reg xml document as a asciiz */
char *ident_get_regxml(ident_t *ident);
int ident_reg_is_valid(reg_package_t *reg);

/* inits & closes the identity manager */
void ident_register();

int ident_load_identities();
int ident_save_identities();
void ident_save_identities_async();
ship_list_t *ident_get_identities();
ship_list_t *ident_get_cas();

/* service stuff */
service_t *ident_get_service(ident_t *ident, service_type_t service_type);
addr_t *ident_get_service_addr(ident_t *ident, service_type_t service_type);
void *ident_get_service_data(ident_t *ident, service_type_t service_type);
int ident_process_register(char *aor, service_type_t service_type, service_t *service, 
			   addr_t *addr, int expire, void *pkg);
ident_service_t *ident_service_new();
void ident_service_close(ident_service_t *s, ident_t *ident);
int ident_service_register(service_t *service);

/* returns own reg package for AOR */
char * ident_get_cached_reg_str(char *sip_aor);
ident_t *_ident_find_by_aor(const char *aor);
ident_t * ident_get_default_ident();

#ifdef LOCK_DEBUG
ident_t *__ident_find_by_aor(const char *aor, const char *file, const char *func, const int line);
#define ident_find_by_aor(aor) __ident_find_by_aor(aor, __FILE__, __FUNCTION__, __LINE__)
#else
#define ident_find_by_aor(aor) _ident_find_by_aor(aor)
#endif
ident_t *ident_register_new(char *sip_aor);
ident_t *ident_register_new_empty_ident(char *sip_aor);

service_t *ident_get_default_service(service_type_t service_type);
int ident_register_default_service(service_type_t service_type, service_t *s);
int ident_registration_is_valid(ident_t *ident, service_type_t service);
int ident_lookup_registration(ident_t *ident, char *remote_aor, 
			      reg_package_t **pkg, processor_task_t **wait);
time_t ident_registration_timeleft(ident_t *ident);

reg_package_t *ident_find_foreign_reg(char *sip_aor);
void ident_reset_foreign_regs();
int ident_import_foreign_reg(reg_package_t *reg);

char *ident_get_status(char *aor);

/* reg package data type handling */
void ident_reg_free(reg_package_t *reg) ;
reg_package_t *ident_reg_new(ident_t *ident);
int ident_reg_xml_to_struct(reg_package_t **__reg, const char *data);
int ident_ca_xml_to_struct(ca_t **__ca, xmlNodePtr cur);
int ident_contact_xml_to_struct(contact_t **__contact, xmlNodePtr cur);

/* ident data type handling */
int ident_set_aor(char **target, char *result);
/* void ident_ident_free(ident_t *ident); */
/* ident_t *ident_ident_new(char *sip_aor); */

/* contacts */
contact_t *ident_contact_new();
void ident_contact_free(contact_t *contact);

/* ca data type handling */
void ident_ca_free(ca_t *ca);
ca_t* ident_ca_new(char *name);

int ident_data_check_cert(ident_t *ident);

char *ident_data_x509_get_serial(X509 *cert);
char *ident_data_x509_get_name_digest(X509_NAME *name);
int ident_data_x509_check_signature(X509 *cert, X509 *ca);
ca_t *ident_get_issuer_ca(X509 *cert);

#define ident_data_x509_get_issuer_digest(cert) \
           ident_data_x509_get_name_digest(X509_get_issuer_name(cert))
#define ident_data_x509_get_subject_digest(cert) \
           ident_data_x509_get_name_digest(X509_get_subject_name(cert))

void ident_data_print_cas(ship_list_t* cas);
int ident_remove_ca(char *name);
void ident_data_print_idents(ship_list_t* idents);
void ident_data_print_cert(char *prefix, X509* cert);
int ident_remove_ident(char *name);
int ident_remove_ident_query(char *name, int query);
int ident_import_file(char *file, int query);
int ident_import_mem(char *data, int datalen, int query, int modif);
int ident_import_ident_cas(ship_list_t *newi, ship_list_t *newc, int query, int modif, int *icount, int *ccount);
int ident_autoreg_load();
int ident_create_ident_xml(ship_list_t *idents, ship_list_t *cas, char **text);
int ident_create_reg_xml(reg_package_t *reg, ident_t *ident, char **text);

int ident_cert_is_valid(X509 *cert);
int ident_remote_cert_is_acceptable(X509 *cert);


/* buddy */
buddy_t *ident_buddy_find(ident_t *ident, const char *sip_aor);
buddy_t *ident_buddy_new(char *name, char *sip_aor, char *shared_secret);
buddy_t *ident_buddy_find_or_create(ident_t *ident, char *sip_aor);

/* '********** */

char *ident_data_x509_get_cn(X509_NAME* name);
int ident_data_x509_get_validity(X509 *cert, time_t *start, time_t *end);
char *ident_data_get_pkey_base64(X509 *cert);

#ifdef CONFIG_BLOOMBUDDIES_ENABLED
int ident_data_bb_encode(ship_list_t *buddy_list, buddy_t *buddy, char **buf, int *buflen, int level);
int ident_data_bb_decode(char *data, int data_len, ship_bloom_t **bloom, int *level);
int ident_data_bb_load_ascii(char *buf, ship_bloom_t *friends[]);
int ident_data_bb_dump_ascii(ship_bloom_t *friends[], char **buf);
int ident_data_bb_get_first_level(ship_list_t *buddy_list, char *to_aor);
int ident_data_bb_get_first_level_cert(ship_list_t *buddy_list, X509 *cert);
int ident_data_bb_find_connections_on_level(ship_list_t *buddy_list, char *remote_aor, int level, ship_list_t *list);
#endif

void ident_data_dump_identities_json(ship_list_t *identities, char **msg);
void ident_data_dump_cas_json(ship_list_t *cas, char **msg);

void ident_set_status(char *aor, char *status);
int ident_has_ident(const char* aor, const char *password);

/** overlay puts / gets with regards to buddies & privacy policies **/
int ident_put_open(ident_t *ident, const char *key, const char *value, const int timeout);
int ident_put_for_all_buddies(ident_t *ident, const char *key, const char *value, const int timeout);
int ident_put_for_buddy_by_aor(ident_t *ident, const char *buddy_aor, const char *key, const char *value, const int timeout);

int ident_remove_open(ident_t *ident, const char* key);
int ident_remove_for_buddy_by_aor(ident_t *ident, const char *buddy_aor, const char *key);
int ident_remove_for_all_buddies(ident_t *ident, const char *key);

/* ident_get_cb == olclient_get_cb */
typedef void (*ident_get_cb) (char *key, char *data, char *signer, void *param, int status);
int ident_getsub_for_buddy_by_aor(ident_t *ident, const char *buddy_aor, const char *key,
				  void *param, ident_get_cb callback, const int subscribe);
int ident_getsub_open(ident_t *ident, const char *key, 
		      void *param, ident_get_cb callback, const int subscribe);

#define ident_get_for_buddy_by_aor(ident, buddy_aor, key, param, callback) ident_getsub_for_buddy_by_aor(ident, buddy_aor, key, param, callback, 0)
#define ident_get_open(ident, key, param, callback) ident_getsub_open(ident, key, param, callback, 0)
#define ident_subscribe_for_buddy_by_aor(ident, buddy_aor, key, param, callback) ident_getsub_for_buddy_by_aor(ident, buddy_aor, key, param, callback, 1)
#define ident_subscribe_open(ident, key, param, callback) ident_getsub_open(ident, key, param, callback, 1)

#endif
