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
#define _GNU_SOURCE
#include "ship_utils.h"
#include <time.h>
#include <string.h>
#ifdef CONFIG_OP_ENABLED
#include <opconn.h>
#endif
#include "ident.h"
#include "processor.h"
#include "ship_debug.h"
#include "ident.h"
#include "p2pship_version.h"
#include "conn.h"

static void ident_free(ident_t *ident);
static int ident_init(ident_t *ret, char *sip_aor);

static void ident_data_bb_add_buddy_to_bloom(ship_bloom_t *bloom, buddy_t *buddy);
static int ident_ident_xml_to_struct(ident_t **__ident, xmlNodePtr cur);
#define ident_service_remove_param(s, k) ident_service_set_param(s, k, NULL)
static int ident_service_set_param(ident_service_t *s, const char *key, const char *data);
static const char *ident_service_get_param(ident_service_t *s, const char *key);

SHIP_DEFINE_TYPE(ident);

char *ident_data_x509_get_cn(X509_NAME* name);

#define ident_data_x509_get_issuer_digest(cert) \
           ident_data_x509_get_name_digest(X509_get_issuer_name(cert))
#define ident_data_x509_get_subject_digest(cert) \
           ident_data_x509_get_name_digest(X509_get_subject_name(cert))


static const char *__str_modif_none = "";
static const char *__str_modif_changed = "changed";
static const char *__str_modif_deleted = "deleted";
static const char *__str_modif_new = "new";

/* returns a short string describing the modified state of ident / ca */
const char *
ident_modif_state_str(int nr) 
{
	switch (nr) {
	case MODIF_NEW:
		return __str_modif_new;
	case MODIF_CHANGED:
		return __str_modif_changed;
	case MODIF_DELETED:
		return __str_modif_deleted;
	default:
	case MODIF_NONE:
		return __str_modif_none;		
	}
}


static void
ident_buddy_free(buddy_t *buddy) 
{
    if (buddy) {
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
	    int i = 0;
	    while (i < BLOOMBUDDY_MAX_LEVEL)
		    ship_bloom_free(buddy->friends[i++]);
#endif
	    freez(buddy->name);
	    freez(buddy->sip_aor);
	    freez(buddy->shared_secret);
	    freez(buddy->callid);
	    freez(buddy->my_suggestion);
	    if (buddy->cert) X509_free(buddy->cert);
	    buddy->cert = NULL;
	    free(buddy);
    }
}

static void
ident_buddy_list_free(ship_list_t *buddy_list) 
{
	ship_list_empty_with(buddy_list, ident_buddy_free);
    	ship_list_free(buddy_list);
}

buddy_t *
ident_buddy_new(char *name, char *sip_aor, char *shared_secret)
{
	buddy_t *ret;
	ASSERT_TRUE(ret = (buddy_t*)mallocz(sizeof(buddy_t)), err);
	ASSERT_TRUE(ret->sip_aor = strdup(sip_aor), err);
	if (name)		
		ASSERT_TRUE(ret->name = strdup(name), err);
	if (shared_secret)
		ASSERT_TRUE(ret->shared_secret = strdup(shared_secret), err);
	return ret;
	
 err:
 	ident_buddy_free(ret);
    return 0;
}

buddy_t *
ident_buddy_find_or_create(ident_t *ident, char *sip_aor)
{
	buddy_t * buddy = 0;
	if (!(buddy = ident_buddy_find(ident, sip_aor))) {
		ASSERT_TRUE(buddy = ident_buddy_new(NULL, sip_aor, NULL), err);
		ship_list_add(ident->buddy_list, buddy);

		/* announce this new 'friendship' */
		processor_event_generate_pack("ident_buddy_new", "Is", ident, sip_aor);
	}
 err:
	return buddy;
}

buddy_t *
ident_buddy_find(ident_t *ident, const char *sip_aor)
{
	void *ptr = 0;
	buddy_t *ret = 0;
	while ((ret = ship_list_next(ident->buddy_list, &ptr)) &&
	       strcmp(ret->sip_aor, sip_aor));
	return ret;
}


static const char *RELATIONSHIP_FRIEND_STR = "friend";
static const char *RELATIONSHIP_NONE_STR = "none";

static int
ident_buddy_str_to_relationship(const char *str)
{
	int ret = RELATIONSHIP_NONE;

	if (!strcmp(str, RELATIONSHIP_FRIEND_STR))
		ret = RELATIONSHIP_FRIEND;
	// add more ..

	return ret;
}

static const char*
ident_buddy_relationship_to_str(const int rel)
{
	const char *ret = NULL;
	
	switch (rel) {
	case RELATIONSHIP_FRIEND:
		ret = RELATIONSHIP_FRIEND_STR;
		break;
		// add more..
	case RELATIONSHIP_NONE:
	default:
		ret = RELATIONSHIP_NONE_STR;
	}
	return ret;
}


static int
ident_buddy_xml_to_struct(buddy_t **__buddy, xmlNodePtr cur)
{
	char *name = NULL, *sip_aor = NULL, *shared_secret = NULL, *certificate = NULL;
   	int ret = -1;
   	buddy_t *buddy = NULL;
   		
   	(*__buddy) = NULL;
   	   	
   	ASSERT_ZERO(xmlStrcmp(cur->name, (const xmlChar*)"buddy"), err);
   	ASSERT_TRUE(sip_aor = ship_xml_get_child_field(cur, "sip-aor"), err);
	
   	name = ship_xml_get_child_field(cur, "name");
	shared_secret = ship_xml_get_child_field(cur, "shared-secret");

   	ASSERT_TRUE(buddy = ident_buddy_new(name, sip_aor, shared_secret), err);

   	if ((certificate = ship_xml_get_child_field(cur, "certificate"))) {
		ASSERT_TRUE(buddy->cert = ship_parse_cert(certificate), err);
   	}
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
	freez(name);
   	if ((name = ship_xml_get_child_field(cur, "bloombuddies"))) {
		ident_data_bb_load_ascii(name, buddy->friends);
	}
#endif
	freez(name);
   	if ((name = ship_xml_get_child_field(cur, "relationship"))) {
		trim(name);
		buddy->relationship = ident_buddy_str_to_relationship(name);
	}
   	(*__buddy) = buddy;
   	buddy = NULL;
   	ret = 0;
 
 err:
    	
	freez(name);
	freez(sip_aor);
	freez(shared_secret);
	freez(certificate);
	if (buddy) ident_buddy_free(buddy);
	return ret;
}


void
ident_reg_free(reg_package_t *reg) 
{
        if (reg) {
		ship_list_empty_free(reg->ip_addr_list);
		ship_list_free(reg->ip_addr_list);
		ship_list_empty_free(reg->rvs_addr_list);
		ship_list_free(reg->rvs_addr_list);
		ship_list_empty_free(reg->hit_addr_list);
		ship_list_free(reg->hit_addr_list);
		ship_lock_free(&(reg->lock));
		
		ship_ht_empty_free(reg->app_data);
		ship_ht_free(reg->app_data);

		freez(reg->xml);
		freez(reg->name);
		freez(reg->status);
                freez(reg->sip_aor);
		if (reg->cert) X509_free(reg->cert);
		reg->cert = NULL;
                free(reg);
        }
}

reg_package_t *
ident_reg_new(ident_t *ident)
{
        reg_package_t *ret = NULL;
        ASSERT_TRUE(ret = (reg_package_t*)mallocz(sizeof(reg_package_t)), err);
	ASSERT_ZERO(ship_lock_new(&ret->lock), err);
	ret->imported = time(NULL);
        ASSERT_TRUE(ret->ip_addr_list = ship_list_new(), err);
        ASSERT_TRUE(ret->rvs_addr_list = ship_list_new(), err);
        ASSERT_TRUE(ret->hit_addr_list = ship_list_new(), err);
        ASSERT_TRUE(ret->app_data = ship_ht_new(), err);
        if (ident) {
                ASSERT_TRUE(ret->sip_aor = strdup(ident->sip_aor), err);
                if (ident->status) {
			ASSERT_TRUE(ret->status = strdup(ident->status), err);
		}
        }
        return ret;
 err:
        ident_reg_free(ret);
        return NULL;
}

int
ident_set_name(char **target, char *result)
{
	char *pos = 0;
	
	/* if < > exists, use only up until the first < */
	if ((pos = strchr(result, '<')) && strchr(pos, '>')) {
		(*target) = strndup(result, pos-result);
	} else {
		(*target) = strdup(result);
	}

	if (((*target) = trim(*target)))
		return 0;
	else
		return -1;
}

int
ident_set_aor(char **target, char *result)
{
        int i;

	/* if < > exists, use only what's inside the last < .. or : */
        for (i=strlen(result)-1; i > -1 && result[i] != '<' && result[i] != ':'; i--);
	result = &result[i+1];
	
	/* cut off at first > */
	for (i = 0; result[i] && result[i] != '>'; i++);

        freez(*target);
        if ((*target = (char*)mallocz(i+1))) {
		memcpy(*target, result, i);
		return 0;
	} else
                return -1;
}

ident_service_t*
ident_service_new() 
{
	ident_service_t* ret = NULL;

	ASSERT_TRUE(ret = mallocz(sizeof(ident_service_t)), err);
	ASSERT_TRUE(ret->params = ship_ht_new(), err);
	return ret;
 err:
	ident_service_close(ret, NULL);
	return NULL;
}

void
ident_service_close(ident_service_t *s, ident_t *ident)
{
	if (!s)
		return;
	
	if (s->service && s->service->service_closed) {
		s->service->service_closed(s->service_type, ident, s->pkg);
	}
	ship_ht_empty_free(s->params);
	ship_ht_free(s->params);

	freez(s->service_handler_id);
	freez(s);
}


/* tries to set a value, removes old if unsuccessful. NULL can be set
   to only remove */
static int
ident_service_set_param(ident_service_t *s, const char *key, const char *data)
{
	int ret = -1;
	char *val = NULL;
	if ((val = ship_ht_remove_string(s->params, key)))
		free(val);
	if (data) {
		ASSERT_TRUE(val = strdup(data), err);
		ship_ht_put_string(s->params, key, val);
	}	
	ret = 0;
 err:
	return ret;
}

static const char *
ident_service_get_param(ident_service_t *s, const char *key)
{
	return ship_ht_get_string(s->params, key);
}


int
ident_set_service_param(ident_t *ident, const service_type_t service_type, const char *key, const char *data)
{
	ident_service_t *s;
	int ret = -1;

	s = ship_ht_get_int(ident->services, service_type);
	if (!s) {
		ASSERT_TRUE(s = ident_service_new(), err);
		ship_ht_put_int(ident->services, service_type, s);
	}
	
	ASSERT_ZERO(ret = ident_service_set_param(s, key, data), err);
	ident_update_registration(ident);
 err:
	return ret;
}

const char*
ident_get_service_param(ident_t *ident, const service_type_t service_type, const char *key)
{
	ident_service_t *s;
	s = ship_ht_get_int(ident->services, service_type);
	if (!s)
		return NULL;
	return ident_service_get_param(s, key);
}

/* frees an ident_ident_t */
static void
ident_free(ident_t *ident)
{
	ident_service_t *s;

	/* 		ship_lock_free(&ident->lock); */
	freez(ident->sip_aor);
	freez(ident->username);
	freez(ident->password);
	freez(ident->status);
	ident_buddy_list_free(ident->buddy_list);
	ident->buddy_list = NULL;
	
	if (ident->services) {
		while ((s = ship_ht_pop(ident->services))) {
			ident_service_close(s, ident);
		}
		ship_ht_free(ident->services);
	}
	
	/* free cryptostuff */
	if (ident->private_key) RSA_free(ident->private_key);
	ident->private_key = NULL;
	if (ident->cert) X509_free(ident->cert);
	ident->cert = NULL;
}

/* creates a new identity */
static int
ident_init(ident_t *ret, char *sip_aor)
{
	ASSERT_TRUE(ret->sip_aor = strdup(sip_aor), err);
	ASSERT_TRUE(ret->services = ship_ht_new(), err);
	ASSERT_TRUE(ret->buddy_list = ship_list_new(), err);
        return 0;
 err:
        return -1;
}

/* frees an ca_t */
void
ident_ca_free(ca_t *ca)
{
        if (ca) {
		ship_lock_free(&ca->lock);
                freez(ca->name);
                freez(ca->digest);
		if (ca->cert) X509_free(ca->cert);
		ca->cert = NULL;
                free(ca);
        }
}

/* new ca */
ca_t *
ident_ca_new(char *name)
{
        ca_t *ret;
        ASSERT_TRUE(ret = (ca_t*)mallocz(sizeof(ca_t)), err);
	ASSERT_ZERO(ship_lock_new(&ret->lock), err);
	if (name) {
		ASSERT_TRUE(ret->name = strdup(name), err);
	}
        return ret;
 err:
        ident_ca_free(ret);
        return 0;
}

/* frees an contact_t */
void
ident_contact_free(contact_t *contact)
{
        if (contact) {
                freez(contact->name);
                freez(contact->sip_aor);
                freez(contact->db_id);
		
		ship_ht_free(contact->params);
                free(contact);
        }
}

/* new ca */
contact_t *
ident_contact_new()
{
        contact_t *ret;
        ASSERT_TRUE(ret = (contact_t*)mallocz(sizeof(contact_t)), err);
	ASSERT_TRUE(ret->params = ship_ht_new(), err);
        return ret;
 err:
        ident_contact_free(ret);
        return 0;
}

/* checks that our local certificate is still ok. called when it is
   going to be put somewhere (reg packet etc). If not ok, then try to
   create a new one */
int
ident_data_check_cert(ident_t *ident)
{
	char *data = 0;
	int ret = -1;
	if (!ident->cert || !ident_cert_is_valid(ident->cert)) {
		if (!ident_is_self_signed(ident)) {
			LOG_ERROR("The certificate for %s is not valid!\n", ident->sip_aor);
			/* we don't want no trouble .. */
#ifdef CONFIG_OP_ENABLED
		} else if (ident_is_op_ident(ident)) {
			/* get the op system to create a self-signed cert with me as subject */
			if (ident->cert) X509_free(ident->cert);
			ident->cert = NULL;
			ASSERT_ZERO(opconn_init(), err);
			ASSERT_ZERO(opconn_request_cert(ident->sip_aor, &data), err);
			ASSERT_TRUE(ident->cert = ship_parse_cert(data), err);
		} else {
#endif
			if (ident->cert) X509_free(ident->cert);
			ident->cert = NULL;
			ASSERT_TRUE(ident->cert = ship_create_selfsigned_cert(ident->sip_aor,
									      365*60*60*24, ident->private_key), err);
		}
	}
	ret = 0;
 err:
	freez(data);
	return ret;
}

/* Add addr-fields to a reg package */
static int
ident_fill_reg_addr_field(xmlNodePtr cur, void *key, ship_list_t *temp_list)
{
	int i, ret = -1;
	xmlNodePtr subtree;
	
	i=0;
	while (i < ship_list_length(temp_list)){
		addr_t *temp_addr = (addr_t *)ship_list_get(temp_list, i);
		char *str = 0;
		
		ASSERT_ZERO(ident_addr_addr_to_str(temp_addr, &str), err);
		subtree = xmlNewTextChild(cur, NULL, key, (const xmlChar*)str);
		freez(str);
		
		ASSERT_TRUE(subtree, err);
		i++;
	}
	ret = 0;
 err:
	return ret;
}

/* reg_pkg -> xml (reg info only) */
static int
ident_reg_struct_to_xml(reg_package_t *reg, char **text)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL, apps = NULL;
	xmlChar *xmlbuf = NULL;
	int bufsize = 0;
	int ret = -1;
	char timebuf[50];
	void *ptr = NULL;
	char *appkey = NULL, *appdata = NULL;

	ASSERT_TRUE((doc = xmlNewDoc((const xmlChar*)"1.0")), err);
	ASSERT_TRUE((doc->children = xmlNewDocNode(doc, NULL, (const xmlChar*)"registration", NULL)), err);
	ASSERT_TRUE(cur = doc->children, err);

	/* sip-aor */
	ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"sip-aor", (const xmlChar*)reg->sip_aor), err);
	
	/* the addr lists */
	ASSERT_ZERO(ident_fill_reg_addr_field(cur, "ip", reg->ip_addr_list), err);
	ASSERT_ZERO(ident_fill_reg_addr_field(cur, "hit", reg->hit_addr_list), err);
	ASSERT_ZERO(ident_fill_reg_addr_field(cur, "rvs", reg->rvs_addr_list), err);

	/* add date time info */
	ship_format_time(reg->created, timebuf, 50);
	ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"created", (const xmlChar*)timebuf), err);
	ship_format_time(reg->valid, timebuf, 50);
	ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"valid-until", (const xmlChar*)timebuf), err);

	/* add client version */
	sprintf(timebuf, "%s:%s", VERSION, P2PSHIP_BUILD_VERSION);
	ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"client-version", (const xmlChar*)timebuf), err);
	
	/** application data **/
	ASSERT_TRUE(apps = xmlNewTextChild(cur, NULL, (const xmlChar*)"applications", NULL), err);
	while ((appdata = ship_ht_next_with_key(reg->app_data, &ptr, &appkey))) {
		ASSERT_TRUE(xmlNewTextChild(apps, NULL, (const xmlChar*)appkey, (const xmlChar*)appdata), err);
	}

	/* status, if present */
	if (reg->status) {
		ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"status", (const xmlChar*)reg->status), err);
	}

	xmlDocDumpFormatMemory(doc, &xmlbuf, &bufsize, 1);
	ASSERT_TRUE(xmlbuf, err);
	ASSERT_TRUE((*text) = (char *)malloc(bufsize+1), err);
	strcpy(*text, (char *)xmlbuf);
	ret = 0;
 err:
	if (xmlbuf) xmlFree(xmlbuf);
	if (doc) xmlFreeDoc(doc);
	//xmlCleanupParser();
	return ret;
}

extern ship_list_t *cas;

/* reg_pkg -> xml with signature and server-issued cert */
int 
ident_create_reg_xml(reg_package_t *reg, ident_t *ident, char **text)
{
	BIO *bio = NULL;
	xmlDocPtr doc = NULL;
	xmlChar *xmlbuf = NULL;
	xmlNodePtr tree = NULL;
	char *reg_data = NULL;
	char *digest = NULL;
	char *sign = NULL;
	char *sign_64e = NULL;
	char *cert = NULL;
	int bufsize, ret = -1;
	unsigned int siglen = 0;

	ASSERT_ZERO(ident_reg_struct_to_xml(reg, &reg_data), err);

	ASSERT_TRUE(doc = xmlNewDoc((const xmlChar*)"1.0"), err);
	ASSERT_TRUE(doc->children = xmlNewDocNode(doc, NULL, (const xmlChar*)REG_PKG, NULL), err);

	ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar*)"data", NULL), err);
	ASSERT_TRUE(tree->children = xmlNewCDataBlock(doc, (const xmlChar*)reg_data, strlen(reg_data)), err);

	/* signature */
	if (ident->private_key
#ifdef CONFIG_OP_ENABLED
	    || ident_is_op_ident(ident)
#endif
	    ) {
		/* signature algorithm */
		ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar*)"signature", NULL), err);
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (const xmlChar*)"algorithm", (const xmlChar*)SIGN_ALGO), err);
#ifdef CONFIG_OP_ENABLED
		if (ident_is_op_ident(ident)) {
			ASSERT_ZERO(opconn_sign(reg_data, "p2pship", &sign_64e), err);
		} else {
#endif
			/* signature value */
			ASSERT_TRUE(digest = (char *)mallocz(SHA_DIGEST_LENGTH), err);
			ASSERT_TRUE(SHA1((unsigned char*)reg_data, strlen(reg_data), (unsigned char*)digest), err);
			
			ASSERT_TRUE(sign = (char *)mallocz(1024), err);	
			ASSERT_TRUE(RSA_sign(NID_sha1, (unsigned char*)digest, SHA_DIGEST_LENGTH, (unsigned char*)sign, &siglen, ident->private_key), err);			
			ASSERT_TRUE(sign_64e = ship_encode_base64(sign, siglen), err);
#ifdef CONFIG_OP_ENABLED
		}
#endif
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (xmlChar*)"value", (xmlChar*)sign_64e), err);
	}
	
	ASSERT_ZERO(ident_data_check_cert(ident), err);
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
	cert[bufsize] = 0;
	ASSERT_TRUE(xmlNewTextChild(doc->children, NULL, (xmlChar*)"certificate", (xmlChar*)cert), err);

	/* done. dump the xml */
	xmlDocDumpFormatMemory(doc, &xmlbuf, &bufsize, 1);
	ASSERT_TRUE(xmlbuf, err);

	ASSERT_TRUE((*text) = (char *)mallocz(bufsize+1), err);
	strcpy(*text, (const char *)xmlbuf);

	ret = 0;
 err:	
	freez(digest);
	freez(sign);
	freez(reg_data);
	freez(sign_64e);

	if (bio) BIO_free(bio);
	if (xmlbuf) xmlFree(xmlbuf);
	if (doc) xmlFreeDoc(doc);
	//xmlCleanupParser();
	
	return ret;
}

static int 
ident_cb_openssl_pass(char *buf, int size, int rwflag, void *u)
{
        int len = 0;

	/* todo: why doesn't openssl call this callback? it should. */
   
        USER_ERROR("Pass phrase required for \"%s\": ", u);
	//len = getline(&buf, size, stdin);
        return len;
}


/* Converts in-memory xml char* to the reg-package structure */
int 
ident_reg_xml_to_struct(reg_package_t **__reg, const char *data)
{
	int ret = -1, len;
	char *digest = NULL;
	char *cdata = NULL;
	char *sign = NULL;
	char *sign_64e = NULL;
	char *sign_algo = NULL;
	EVP_PKEY *pkey = NULL;
	RSA *public_key = NULL;
	char *result = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr cur = NULL;
	reg_package_t *reg = NULL;
	xmlDocPtr datadoc = NULL;

	(*__reg) = NULL;
	ASSERT_TRUE(data, err);
	ASSERT_TRUE(strlen(data), err);
	ASSERT_TRUE(data[0] == '<', err); // try to avoid libxml2 bugs.. :(
	
	ASSERT_TRUE(reg = ident_reg_new(NULL), err);
	ASSERT_TRUE(doc = xmlParseMemory(data, strlen(data)), err);
	ASSERT_TRUE(cur = xmlDocGetRootElement(doc), err);
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)REG_PKG), err);
	
	/* certificate */
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "certificate"), err);
	ASSERT_TRUE(reg->cert = ship_parse_cert(result), err);
	
	/* get key into public_key */
	ASSERT_TRUE(pkey = X509_get_pubkey(reg->cert), err);
	ASSERT_TRUE(public_key = EVP_PKEY_get1_RSA(pkey), err);
	
	/* compute digest of reg-package cdata & verify the base encoded signature */
	ASSERT_TRUE(cdata = ship_xml_get_child_field(cur, "data"), err);
	ASSERT_TRUE(digest = (char *)mallocz(SHA_DIGEST_LENGTH), err);
	ASSERT_TRUE(SHA1((unsigned char*)cdata, strlen(cdata), (unsigned char*)digest), err);
	
	/* verify (we support only one algo..) */
	ASSERT_TRUE(cur = ship_xml_get_child(cur, "signature"), err);
	ASSERT_TRUE(sign_64e = ship_xml_get_child_field(cur, "value"), err);
	ASSERT_TRUE(sign_algo = ship_xml_get_child_field(cur, "algorithm"), err);
	if (strcmp(sign_algo, SIGN_ALGO)) {
		LOG_WARN("Registration package signed with unknown algorithm\n");
		goto err;
	}

	ASSERT_TRUE(sign = ship_decode_base64(sign_64e, strlen(sign_64e), &len), err);
	if (!RSA_verify(NID_sha1, (unsigned char*)digest, SHA_DIGEST_LENGTH, (unsigned char*)sign, len, public_key)) {
		LOG_WARN("Signature not verified\n");
		goto err;
	}

	/* parse the internal, signed, reg-doc */
	ASSERT_TRUE(datadoc = xmlParseMemory(cdata, strlen(cdata)), err);
	ASSERT_TRUE(cur = xmlDocGetRootElement(datadoc), err);
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)"registration"), err);

	ASSERT_ZERO(ship_xml_get_child_addr_list(cur, "ip", reg->ip_addr_list), err);
	ASSERT_ZERO(ship_xml_get_child_addr_list(cur, "hit", reg->hit_addr_list), err);
	ASSERT_ZERO(ship_xml_get_child_addr_list(cur, "rvs", reg->rvs_addr_list), err);

	/* read sip aor from cert, compare & require them to be the same */
	freez(sign);
	ASSERT_TRUE(sign = ident_data_x509_get_cn(X509_get_subject_name(reg->cert)), err);
	ASSERT_ZERO(ident_set_aor(&(reg->sip_aor), sign), err);
	ASSERT_ZERO(ident_set_name(&(reg->name), sign), err);
	
	freez(sign);
	xmlFree(result); result = NULL;		
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "sip-aor"), err);
	ASSERT_ZERO(ident_set_aor(&sign, result), err);	

	ASSERT_ZERO(strcmp(sign, reg->sip_aor), err);

	/* status, if present */
	xmlFree(result); result = NULL;		
	if ((result = ship_xml_get_child_field(cur, "status"))) {
		freez(reg->status);
		reg->status = strdup(result);
	}
	
	/* date & time */
	if (result) xmlFree(result);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "created"), err);
	reg->created = ship_parse_time(result);
	xmlFree(result);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "valid-until"), err);
	reg->valid = ship_parse_time(result);

	/* application parameters */
	if ((cur = ship_xml_get_child(cur, "applications"))) {
		xmlNodePtr cur_node = NULL;
		for (cur_node = cur->children; cur_node; cur_node = cur_node->next) {
			char *str = NULL;
			if ((str = (char*)xmlNodeListGetString(cur_node->doc, cur_node->xmlChildrenNode, 1))) {
				ship_ht_put_string(reg->app_data, (char*)cur_node->name, str);
			}
		}
	}

	ASSERT_TRUE(reg->xml = strdup(data), err);
	(*__reg) = reg;
	reg = NULL;
	ret = 0;
 err:
	if (datadoc) xmlFreeDoc(datadoc);
	freez(sign);
	freez(cdata);
	freez(digest);
	freez(sign_64e);
	freez(sign_algo);
	if (pkey) EVP_PKEY_free(pkey);
	if (public_key) RSA_free(public_key);
	if (doc) xmlFreeDoc(doc);
	freez(result);
	if (reg) ident_reg_free(reg);
	
	//xmlCleanupParser();
	return ret;
}


////////////////////////////////////////////////// data handling


/* reads an ident xml into a bunch of idents & ca's */
int
ident_load_ident_xml(xmlNodePtr cur, void *ptr)
{
	int ret = -1;
	xmlNodePtr node = NULL;
	ship_list_t *idents, *cas, *contacts;
	void **arr = ptr;
	idents = arr[0]; cas = arr[1]; contacts = arr[2];
	
	/* go through the children, re-loop */
	/* this makes multiple-nested p2pship-ident's possible, but .. */
	if (!xmlStrcmp(cur->name, (xmlChar*)"p2pship-ident") ||
	    !xmlStrcmp(cur->name, (xmlChar*)"trusted-ca") ||
	    !xmlStrcmp(cur->name, (xmlChar*)"identities") ||
	    !xmlStrcmp(cur->name, (xmlChar*)"contacts")) {
		for (node = cur->children; node; node = node->next) {
			if ((ret = ident_load_ident_xml(node, arr)))
				return ret;
		}
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"identity")) {
		ident_t *ident = NULL;			
		if ((ret = ident_ident_xml_to_struct(&ident, cur))) {
			LOG_WARN("Invalid identity fragment!\n");
		} else {
			LOG_INFO("Loaded identity %s\n", ident->sip_aor);
			ship_obj_list_add(idents, ident);
			ship_obj_unref(ident);
		}
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"ca")) {
		ca_t *ca = NULL;			
		if ((ret = ident_ca_xml_to_struct(&ca, cur))) {
			LOG_WARN("Invalid CA fragment!\n");
		} else {
			LOG_INFO("Loaded CA %s\n", ca->name);
			ship_list_add(cas, ca);
		}
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"contact")) {
		contact_t *contact = NULL;			
		if ((ret = ident_contact_xml_to_struct(&contact, cur))) {
			LOG_WARN("Invalid contact fragment!\n");
		} else {
			LOG_INFO("Loaded contact %s\n", contact->name);
			ship_list_add(contacts, contact);
		}
	}
	
	return 0;
}

/* reads an ident xml char* into the ident-structure */
static int
ident_ident_xml_to_struct(ident_t **__ident, xmlNodePtr cur)
{
	char *result = NULL;
	char *cn = NULL;
	BIO *bio_key = NULL;
	BIO *bio_cert = NULL;
	int ret = -1;
	ident_t *ident = NULL;
	xmlNodePtr keyelm = NULL;
	xmlNodePtr buddies = NULL, b = NULL;
	buddy_t *buddy = NULL;
	
	(*__ident) = NULL;
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)"identity"), err);
	ASSERT_TRUE(ident = (ident_t*)ship_obj_new(TYPE_ident, ""), err);
		
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "username"), err);
	ASSERT_TRUE(ident->username = strdup(result), err);

	/* we use the name on the sip-aor label. although it might
	   differ from the certificate */
	freez(result);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "sip-aor"), err);
	ASSERT_ZERO(ident_set_aor(&(ident->sip_aor), result), err);

	/* see if we have a key and check the flags */
	freez(result);
	ASSERT_TRUE(keyelm = ship_xml_get_child(cur, "private-key"), err);
	
	/* check attributes */ 
#ifdef CONFIG_OP_ENABLED
	if (ship_xml_attr_is(keyelm, "src", "op")) {
		IDENT_SET_FLAG(ident, IDENT_FLAG_OP_IDENT);
		IDENT_SET_FLAG(ident, IDENT_FLAG_SELF_SIGNED);
	}
		
	if (ship_xml_attr_is(keyelm, "verify", "op"))
		IDENT_SET_FLAG(ident, IDENT_FLAG_OP_VERIFY);
	if (!ident_is_op_ident(ident)) {
#endif 
		ASSERT_TRUE(result = ship_xml_get_child_field(cur, "private-key"), err);
		ASSERT_TRUE(bio_key = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(BIO_puts(bio_key, result) > 0, err);
		BIO_flush(bio_key);
		
		/* why doesn't this work?? the callback is never called, the key-read just fails */
		/* todo: do a ERR_get_error etc to get the error code */
		ASSERT_TRUE(ident->private_key = PEM_read_bio_RSAPrivateKey(bio_key, NULL, 
									    ident_cb_openssl_pass, 
									    "private key"), err);
#ifdef CONFIG_OP_ENABLED
	}
#endif 
	freez(result);

	if ((result = ship_xml_get_child_field(cur, "certificate"))) {
		ASSERT_TRUE(ident->cert = ship_parse_cert(result), err);

		/* read sip aor from cert, compare */
		freez(result);
		ASSERT_TRUE(result = ident_data_x509_get_cn(X509_get_subject_name(ident->cert)), err);
		ASSERT_ZERO(ident_set_aor(&cn, result), err);
		if (strcmp(cn, ident->sip_aor)) {
			LOG_WARN("Identity's specified SIP AOR (%s) differs from the issued (%s)\n",
				 ident->sip_aor, cn);
		}
	} else if (ident->private_key) {
		/* generate a self-signed certificate */
		LOG_DEBUG("self-signing certificate for %s..\n", ident->sip_aor);
		ASSERT_TRUE(ident->cert = ship_create_selfsigned_cert(ident->sip_aor,
								      365*60*60*24, ident->private_key), err);
		IDENT_SET_FLAG(ident, IDENT_FLAG_SELF_SIGNED);
	}

	/* get buddies from buddylist */
	if ((buddies = ship_xml_get_child(cur, "buddies"))) {
		for (b = buddies->children; b; b = b->next) {
			if (!strcmp((char *)b->name, "buddy")) {
				ASSERT_ZERO(ident_buddy_xml_to_struct(&buddy, b), err);
				ship_list_add(ident->buddy_list, buddy);
			}
		}		
	}
	
	(*__ident) = ident;
	ident = NULL;
	ret = 0;
 err:
	if (bio_cert) BIO_free(bio_cert);
	if (bio_key) BIO_free(bio_key);
	if (result) xmlFree(result);
	ship_obj_unref(ident);
	freez(cn);
	
	return ret;
}

/* reads an ca xml char* into the ca-structure */
int
ident_ca_xml_to_struct(ca_t **__ca, xmlNodePtr cur)
{
	char *result = NULL;
	int ret = -1;
	ca_t *ca = NULL;

	(*__ca) = NULL;
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)"ca"), err);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "name"), err);
	ASSERT_TRUE(ca = ident_ca_new(result), err);
	freez(result);

	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "certificate"), err);
	ASSERT_TRUE(ca->cert = ship_parse_cert(result), err);
	
	/* extract key id */
	ASSERT_TRUE(ca->digest = ident_data_x509_get_subject_digest(ca->cert), err);

	(*__ca) = ca;
	ca = NULL;
	ret = 0;
 err:
	
	freez(result);
	if (ca) ident_ca_free(ca);
	
	return ret;
}

/* reads an contact xml char* into the structure */
int
ident_contact_xml_to_struct(contact_t **__contact, xmlNodePtr cur)
{
	int ret = -1;
	contact_t *contact = NULL;
	xmlNodePtr node = NULL;

	(*__contact) = NULL;
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)"contact"), err);
	ASSERT_TRUE(contact = ident_contact_new(), err);

	/* required */
	ASSERT_TRUE(contact->sip_aor = ship_xml_get_child_field_dup(cur, "sip-aor"), err);
	ASSERT_TRUE(contact->name = ship_xml_get_child_field_dup(cur, "name"), err);

	/* optional */
	for (node = cur->children; node; node = node->next) {
		if (strcmp((char*)node->name, "sip-aor") && strcmp((char*)node->name, "name")) {
			char *val = (char*)xmlNodeListGetString(node->doc, node->xmlChildrenNode, 1);
			if (val) {
				ASSERT_TRUE(ship_ht_put_string(contact->params, (char*)node->name, strdup(val)), err);
			}
		}
	}

	(*__contact) = contact;
	contact = NULL;
	ret = 0;
 err:
	if (contact) ident_contact_free(contact);
	return ret;
}


/* converts a list of idents & ca's to a complete doc */
int
ident_create_ident_xml(ship_list_t *idents, ship_list_t *cas, char **text)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr tree, node, pkey;
	xmlChar *xmlbuf = NULL;
	BIO *bio = NULL;
	char *tmp = NULL;
	int ret = -1;
	void *ptr;
	ident_t *ident = 0;
	ca_t *ca;
	int bufsize = 0;
	
	ASSERT_TRUE(doc = xmlNewDoc((xmlChar*)"1.0"), err);
	ASSERT_TRUE(doc->children = xmlNewDocNode(doc, NULL, (xmlChar*)"p2pship-ident", NULL), err);

	ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (xmlChar*)"identities", NULL), err);
	for (ptr = 0; (ident = (ident_t*)ship_list_next(idents, &ptr));) {
		ship_lock(ident);

		/* skip the tmp idents */
		if (ident_is_no_save(ident)) {
			ship_unlock(ident);
			continue;
		}

		ASSERT_TRUE(node = xmlNewTextChild(tree, NULL, (xmlChar*)"identity", NULL), err);
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"sip-aor", (xmlChar*)ident->sip_aor), err);
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"username", (xmlChar*)ident->username), err);
		
#ifdef CONFIG_OP_ENABLED
		if (ident_is_op_ident(ident)) {
			ASSERT_TRUE(pkey = xmlNewTextChild(node, NULL, (xmlChar*)"private-key", (xmlChar*)""), err);
			xmlSetProp(pkey, (xmlChar*)"src", (xmlChar*)"op");
		} else {
#endif
			ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
			ASSERT_TRUE(PEM_write_bio_RSAPrivateKey(bio, ident->private_key, NULL, NULL, 0, NULL, NULL), err);
			ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
			tmp[bufsize] = 0;
			ASSERT_TRUE(pkey = xmlNewTextChild(node, NULL, (xmlChar*)"private-key", (xmlChar*)tmp), err);
			BIO_free(bio);
			bio = NULL;
#ifdef CONFIG_OP_ENABLED
		}
		
		if (ident_is_op_verify(ident))
			xmlSetProp(pkey, (xmlChar*)"verify", (xmlChar*)"op");
#endif		

		if (!ident_is_self_signed(ident)) {
			ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
			ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
			ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
			tmp[bufsize] = 0;
			ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"certificate", (xmlChar*)tmp), err);
			
			BIO_free(bio);
			bio = NULL;
		}
		
		/* save buddy list */
		if (ship_list_first(ident->buddy_list)) {
			xmlNodePtr buddynode, buddychildnode;
			buddy_t *buddy;
			void *ptr;
			
			ASSERT_TRUE(buddynode = xmlNewTextChild(node, NULL, (xmlChar*)"buddies", NULL), err);
			for (ptr = 0; (buddy = (buddy_t*)ship_list_next(ident->buddy_list, &ptr));) {
				ASSERT_TRUE(buddychildnode = xmlNewTextChild(buddynode, NULL, (xmlChar*)"buddy", NULL), err);
				ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"sip-aor", (xmlChar*)buddy->sip_aor), err);
				
				/* we don't always have these other parameters .. */
				if (buddy->name)
					ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"name", (xmlChar*)buddy->name), err);
				if (buddy->shared_secret)
					ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"shared-secret", (xmlChar*)buddy->shared_secret), err);
				
				if (buddy->cert) {
					ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
					ASSERT_TRUE(PEM_write_bio_X509(bio, buddy->cert), err);
					ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
					tmp[bufsize] = 0;
					ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"certificate", (xmlChar*)tmp), err);
					
					BIO_free(bio);
					bio = NULL;
				}

#ifdef CONFIG_BLOOMBUDDIES_ENABLED
				if (!ident_data_bb_dump_ascii(buddy->friends, &tmp)) {
					ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"bloombuddies", (xmlChar*)tmp), err);
					freez(tmp);
				}
#endif
				ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"relationship", 
							    (xmlChar*)(ident_buddy_relationship_to_str(buddy->relationship))), err);
			}
		}
		ship_unlock(ident);
		ident = 0;
	}
	
	ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (xmlChar*)"trusted-ca", (xmlChar*)NULL), err);
	for (ptr = 0; (ca = (ca_t*)ship_list_next(cas, &ptr));) {
		ASSERT_TRUE(node = xmlNewTextChild(tree, NULL, (xmlChar*)"ca", NULL), err);
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"name", (xmlChar*)ca->name), err);
		
		ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(PEM_write_bio_X509(bio, ca->cert), err);
		ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
 		tmp[bufsize] = 0;
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"certificate", (xmlChar*)tmp), err);

		BIO_free(bio);
		bio = NULL;
	}
	
	/* done. dump the xml */
	xmlDocDumpFormatMemory(doc, &xmlbuf, &bufsize, 1);
	ASSERT_TRUE(xmlbuf > 0, err);
	ASSERT_TRUE((*text = (char *)mallocz(bufsize+1)), err);
	strcpy(*text, (const char *)xmlbuf);
	
	ret = 0;
 err:
	if (bio) BIO_free(bio);
	if (xmlbuf) xmlFree(xmlbuf);
	if (doc) xmlFreeDoc(doc);
	//xmlCleanupParser();
	ship_unlock(ident);
		
	return ret;
}


/////////////////////// printing

char *
ident_data_x509_get_name_digest(X509_NAME *name)
{
	unsigned int i = 0;
	unsigned char md[EVP_MAX_MD_SIZE];
	char *ret = NULL;

	if (X509_NAME_digest(name, EVP_sha1(), md, &i)) {
		int r;
		ret = (char*)mallocz((i*2) + 1);
		for (r=0; r < i*2; r++) {
			int v=(r%2? 0xf&(md[r/2] >> 4) : 0xf&md[r/2]);
			if (v > 9)
				ret[r] = 'A' + v - 10;
			else
				ret[r] = '0' + v;
		}
	}

	return ret;
}

char *
ident_data_x509_get_serial(X509 *cert)
{
	char *ret = 0, *tmp = 0;
	int len;
	BIO *bio = NULL;

	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	if (i2a_ASN1_INTEGER(bio, X509_get_serialNumber(cert)) == -1)
		goto err;
	ASSERT_TRUE(len = BIO_get_mem_data(bio, &tmp), err);
	ASSERT_TRUE(ret = (char*)mallocz(len+1), err);
	memcpy(ret, tmp, len);
 err:	
	if (bio) BIO_free(bio);
	return ret;
}


static int
ident_data_x509_asn1time_to_time(ASN1_TIME *tm, time_t *t)
{
	int ret = -1;
	char *v;
	int gmt=0;
	int i, ofs;
	struct tm ttm;

	memset(&ttm, 0, sizeof(ttm));

	i=tm->length;
	v=(char *)tm->data;

	if (tm->type == V_ASN1_UTCTIME) {
		ttm.tm_year= (v[0]-'0')*10+(v[1]-'0');
		if (ttm.tm_year < 50) ttm.tm_year+=100;
		ofs = 0;
	} else if(tm->type == V_ASN1_GENERALIZEDTIME) {
		ttm.tm_year= (v[0]-'0')*1000+(v[1]-'0')*100 + (v[2]-'0')*10+(v[3]-'0');
		ttm.tm_year -= 1900;
		ofs = 2;
	} else
		goto err;
	
	if (i < 10+ofs) goto err;

	if (v[i-1] == 'Z') gmt=1;
	for (i=0; i<10+ofs; i++)
		if ((v[i] > '9') || (v[i] < '0')) goto err;

	if (tm->type == V_ASN1_UTCTIME) {
	} else {
	}

	ttm.tm_mon = (v[2+ofs]-'0')*10+(v[3+ofs]-'0')-1;
	if ((ttm.tm_mon > 11) || (ttm.tm_mon < 0)) goto err;
	ttm.tm_mday= (v[4+ofs]-'0')*10+(v[5+ofs]-'0');
	ttm.tm_hour= (v[6+ofs]-'0')*10+(v[7+ofs]-'0');
	ttm.tm_min= (v[8+ofs]-'0')*10+(v[9+ofs]-'0');
	if (	(v[10+ofs] >= '0') && (v[10+ofs] <= '9') &&
		(v[11+ofs] >= '0') && (v[11+ofs] <= '9'))
		ttm.tm_sec =  (v[10+ofs]-'0')*10+(v[11+ofs]-'0');
	
	if (gmt) {
		*t = timegm(&ttm);
	} else {
		*t = mktime(&ttm);
	}
	
	ret = 0;
 err:
	return ret;
}

int
ident_data_x509_get_validity(X509 *cert, time_t *start, time_t *end)
{
	if (!ident_data_x509_asn1time_to_time(X509_get_notBefore(cert), start) &&
	    !ident_data_x509_asn1time_to_time(X509_get_notAfter(cert), end)) {
		return 0;
	} else {
		return -1;
	}
}

char *
ident_data_x509_get_cn(X509_NAME* name)
{
	int i;
	for (i=0; i < sk_X509_NAME_ENTRY_num(name->entries); i++) {
		X509_NAME_ENTRY *ne;
		
		ne=sk_X509_NAME_ENTRY_value(name->entries,i);
		if (OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne)) == NID_commonName) {
			ASN1_STRING *str = X509_NAME_ENTRY_get_data(ne);
			return strdup((char*)str->data);
		}
	}

	return NULL;
}

void
ident_data_print_cert(char *prefix, X509* cert)
{
	char *cn;
	time_t start, end;
	char buf[128];

	cn = ident_data_x509_get_cn(X509_get_subject_name(cert));
	if (cn) {
		USER_PRINT("%sCertified-name: %s\n", prefix, cn);
	} else {
		USER_PRINT("%sUNKNOWN SUBJECT\n", prefix);
	}
	freez(cn);

	cn = ident_data_x509_get_cn(X509_get_issuer_name(cert));
	if (cn) {
		USER_PRINT("%sIssued by %s\n", prefix, cn);
	} else {
		USER_PRINT("%sUNKNOWN ISSUER\n", prefix);
	}
	freez(cn);
	
	/* validity */
	if (!ident_data_x509_get_validity(cert, &start, &end)) {
		ship_format_time_human(start, buf, 500);
		USER_PRINT("%sValid not before %s\n", prefix, buf);
		ship_format_time_human(end, buf, 500);
		USER_PRINT("%sValid not after %s\n", prefix, buf);
	}

	/* serial of signer's & own key */
	if ((cn = ident_data_x509_get_serial(cert))) {
		USER_PRINT("%sSerial %s\n", prefix, cn);
		freez(cn);
	}

	if ((cn = ident_data_x509_get_issuer_digest(cert))) {
		USER_PRINT("%sSigner digest %s\n", prefix, cn);
		freez(cn);
	}

	if ((cn = ident_data_x509_get_subject_digest(cert))) {
		USER_PRINT("%sOwn digest %s\n", prefix, cn);
		freez(cn);
	}
}

void
ident_data_print_idents(ship_list_t* idents)
{
	ident_t *ident;
	void *ptr;

	USER_PRINT("List of identities (%d total):\n", ship_list_length(idents));
	for (ptr = 0; (ident = (ident_t*)ship_list_next(idents, &ptr));) {
		USER_PRINT("\t%s <%s>:\n", ident->username, ident->sip_aor);
		if (ident_is_self_signed(ident))
			USER_PRINT("\t\tIdentity is self-signed");
		else
			ident_data_print_cert("\t\t", ident->cert);
		USER_PRINT("\n");
	}
}

void
ident_data_print_cas(ship_list_t* cas)
{
	ca_t *ca;
	void *ptr;

	USER_PRINT("List of CAs (%d total):\n", ship_list_length(cas));
	for (ptr = 0; (ca = (ca_t*)ship_list_next(cas, &ptr));) {
		USER_PRINT("\t%s:\n", ca->name);
		ident_data_print_cert("\t\t", ca->cert);
		USER_PRINT("\n");
	}
}

int
ident_data_x509_check_signature(X509 *cert, X509 *ca)
{
	EVP_PKEY *pkey=NULL;
	int ret = 0;
	
	/* check validity..? */
	ASSERT_TRUE(pkey = X509_get_pubkey(ca), err);
	ASSERT_POSITIVE(X509_verify(cert, pkey), err);
	ret = 1;
 err:
	if (pkey) {
		EVP_PKEY_free(pkey);
	}
	
	return ret;
}

char *
ident_data_get_pkey_base64(X509 *cert)
{
	EVP_PKEY *pkey = NULL;
	BIO *bio = NULL;
	char *ret = 0, *tmp = 0;
	int bufsize = 0;
	
	/* get key into public_key */
	ASSERT_TRUE(pkey = X509_get_pubkey(cert), err);

	/* transform the key to base64.. */
	ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(PEM_write_bio_PUBKEY(bio, pkey), err);
	ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
	tmp[bufsize] = 0;

	LOG_DEBUG("got pkey '%s'\n", tmp);
	ret = ship_encode_base64(tmp, bufsize);
 err:
	if (bio) BIO_free(bio);
	if (pkey) EVP_PKEY_free(pkey);
	return ret;
}

/************************* json data handling *****************************/


void
ident_data_dump_identities_json(ship_list_t *identities, char **msg)
{
	ident_t *ident = 0, *def = 0;
	void *ptr = 0;
	char *buf = 0;
	int buflen = 0, datalen = 0;
	char *tmp = 0, *tmp2 = 0, *service_str = 0;
	
	if ((def = ident_get_default_ident()))
		ship_unlock(def);

	ASSERT_TRUE(buf = append_str("var p2pship_idents = {\n", buf, &buflen, &datalen), err);
	ship_lock(identities);
	while ((ident = ship_list_next(identities, &ptr))) {
		int len;
		ident_service_t *s;
		void *ptr2 = 0;
		
		ship_lock(ident);

		freez(service_str);
		freez(tmp);
		freez(tmp2);
		while ((s = ship_ht_next(ident->services, &ptr2))) {
			freez(tmp2);
			freez(tmp);
			ident_addr_addr_to_str(&s->contact_addr, &tmp2);
			ASSERT_TRUE(tmp = mallocz(64 + zstrlen(tmp2)), err);
			sprintf(tmp, "\"%s,%d,%u,%d,%s\", ",
				s->service_handler_id,
				s->service_type, (unsigned int)s->reg_time, s->expire, tmp2);
			ASSERT_ZERO(append_str2(&service_str, tmp), err);
		}
		ASSERT_ZERO(append_str2(&service_str, "\"\""), err);

		len = strlen(ident->sip_aor) + 128;
		freez(tmp2);
		freez(tmp);
		if ((tmp = ident_get_status(ident->sip_aor)))
			tmp2 = ship_urlencode(tmp);
		
		if (ident->username) len += strlen(ident->username);
		if (tmp2) len += strlen(tmp2);
		if (service_str) len += strlen(service_str);
		
		freez(tmp);
		ASSERT_TRUE(tmp = mallocz(len), err);
		sprintf(tmp, "     \"%s\" : [ \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", [ %s ] ],\n",
			ident->sip_aor, 
			(ident->username? ident->username:""),
			(ident_registration_timeleft(ident)? "online" : "offline"),
			ident_modif_state_str(ident->modified),
			(tmp2? tmp2:""),
			(ident == def? "default": ""),
			(service_str? service_str: ""));
		
		ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
		ship_unlock(ident);
		ident = 0;
	}

	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("};\n", buf, &buflen, &datalen), err);
	*msg = buf;
	buf = 0;
 err:
	ship_obj_unref(def);
	ship_unlock(ident);
	ship_unlock(identities);
	freez(buf);
	freez(tmp);
	freez(tmp2);
	freez(service_str);
}

void
ident_data_dump_cas_json(ship_list_t *cas, char **msg)
{
	ca_t *ca;
	void *ptr = 0;
	char *buf = 0;
	int buflen = 0, datalen = 0;
	char *tmp = 0;
	
	ASSERT_TRUE(buf = append_str("var p2pship_cas = [\n", buf, &buflen, &datalen), err);
	while ((ca = ship_list_next(cas, &ptr))) {
		int len = strlen(ca->name) + strlen(ca->digest) + 128;
		ASSERT_TRUE(tmp = mallocz(len), err);
		sprintf(tmp, "     [ \"%s\", \"%s\", \"%s\" ],\n",
			ca->name, ca->digest, 
			ident_modif_state_str(ca->modified));
		ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
		freez(tmp);
	}
	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("];\n", buf, &buflen, &datalen), err);
	*msg = buf;
	buf = 0;
 err:
	freez(buf);
	freez(tmp);
}

void
ident_data_dump_remote_regs_json(ship_list_t *regs, char **msg)
{
	reg_package_t *reg = NULL;
	void *ptr = 0;
	char *buf = 0;
	int buflen = 0, datalen = 0;
	char *tmp = 0;
		
	/* format: aor: name, created, valid, imported, valid(1|0), status, { app : data } */

	ASSERT_TRUE(buf = append_str("var p2pship_remote_regs = {\n", buf, &buflen, &datalen), err);
	while ((reg = ship_list_next(regs, &ptr))) {
		int len = strlen(reg->name) + strlen(reg->sip_aor) + 128;
		ASSERT_TRUE(tmp = mallocz(len), err);
		sprintf(tmp, "     \"%s\" : [ \"%s\", \"%d\", \"%d\", \"%d\", \"%d\", \"%s\" ],\n",
			reg->sip_aor, reg->name, 
			(int)reg->created, (int)reg->valid, (int)reg->imported, 1, 
			reg->status);
		ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
		freez(tmp);
	}
	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("};\n", buf, &buflen, &datalen), err);
	*msg = buf;
	buf = 0;
 err:
	freez(buf);
	freez(tmp);
}

#ifdef CONFIG_BLOOMBUDDIES_ENABLED

/* encodes a given level of the bloombuddies for a given user. 0 is
   the buddies in the buddy list (friends). 1 their first blooms. 2
   their second and so on. The level number is prepended. 

   return 0 on alles ok. -1 on error or if the filter was to be empty!
*/
int
ident_data_bb_encode(ship_list_t *buddy_list, buddy_t *buddy, char **buf, int *buflen, int level)
{
	int ret = -1;
	ship_bloom_t *bloom = NULL;
	void *ptr = 0;
	buddy_t *bud = 0;
	char *tmp = 0;
	
	/* what is the optimal size for these bloom filters? 

	- assume 100 or less friends
	- 2 hash functions
	- > 1% false
	
	=> m/n should be around 18-19
	= 1800-1900 bits

	We use 2048, which is 256 bytes, 32 words, 16 dwords.
	Sending 5 of these is 1280 of data, under a MTU.
	
	+ whatever encoding is needed..
	*/

	ASSERT_TRUE(level < BLOOMBUDDY_MAX_LEVEL, err);
	ASSERT_TRUE(bloom = ship_bloom_new(BLOOMBUDDIES_BLOOM_SIZE), err);
	if (level == 0) {
		while ((bud = ship_list_next(buddy_list, &ptr))) {
			if (bud->relationship != RELATIONSHIP_FRIEND || (buddy && !strcmp(bud->sip_aor, buddy->sip_aor)))
				continue;
			ident_data_bb_add_buddy_to_bloom(bloom, bud);
		}
	} else {
		while ((bud = ship_list_next(buddy_list, &ptr))) {
			if (bud->relationship != RELATIONSHIP_FRIEND || (buddy && !strcmp(bud->sip_aor, buddy->sip_aor)))
				continue;

			if (bud->friends[level]) {
				ship_bloom_combine_bloom(bloom, bud->friends[level]);
			}
		}
	}
	
	*buflen = ship_bloom_dump_size(bloom) + 1;
	ASSERT_TRUE(tmp = mallocz(*buflen), err);
	ship_inroll(level, tmp, 1);
	ship_bloom_dump(bloom, &(tmp[1]));
	
	*buf = tmp;
	tmp = 0;
	ret = 0;
 err:
	freez(tmp);
	ship_bloom_free(bloom);
	return ret;
}

/* decodes one bloomfilter, returning the level at which it is. */
int
ident_data_bb_decode(char *data, int data_len, ship_bloom_t **bloom, int *level)
{
	int ret = -1;
	ship_bloom_t *b = NULL;
	
	ASSERT_TRUE(data_len > 0, err);
	ship_unroll(*level, data, 1);
	ASSERT_TRUE(b = ship_bloom_load(&(data[1]), data_len-1), err);
	*bloom = b;
	ret = 0;
 err:
	return ret;
}

/* adds a buddy to a bloom filter */
static void
ident_data_bb_add_buddy_to_bloom(ship_bloom_t *bloom, buddy_t *buddy)
{
	/* Add both the key and the name. */
	ship_bloom_add_cert(bloom, buddy->cert);
	ship_bloom_add(bloom, buddy->sip_aor);
}

/* return the first level in any of the buddy list where the give aor
   might exist. */
int
ident_data_bb_get_first_level_cert(ship_list_t *buddy_list, X509 *cert)
{
	int ret = -1;
	buddy_t *buddy;
	void *ptr = 0;

	while ((buddy = (buddy_t*)ship_list_next(buddy_list, &ptr)) &&
	       (ret != 0)) {
		int i;

		if (buddy->relationship != RELATIONSHIP_FRIEND)
			continue;
		if (buddy->cert && !ship_cmp_pubkey(cert, buddy->cert))
			return 1;
		for (i=0; i < BLOOMBUDDY_MAX_LEVEL && (ret < 0 || i < ret); i++) {
			if (ship_bloom_check_cert(buddy->friends[i], cert))
				ret = i;
		}
	}
	if (ret > -1)
		ret += 2;
	return ret;
}

/* return the first level in any of the buddy list where the give aor
   might exist. < 1: sorry.. . 1 - your friend! 2 friend-of-friend. 3 - friend-of-friend-of-friend. */
int
ident_data_bb_get_first_level(ship_list_t *buddy_list, char *to_aor)
{
	int ret = -1;
	buddy_t *buddy;
	void *ptr = 0;

	while ((buddy = (buddy_t*)ship_list_next(buddy_list, &ptr)) &&
	       (ret != 0)) {
		int i;
		if (buddy->relationship != RELATIONSHIP_FRIEND)
			continue;
		if (!strcmp(buddy->sip_aor, to_aor))
			return 1;
		for (i=0; i < BLOOMBUDDY_MAX_LEVEL && (ret < 0 || i < ret); i++) {
			if (ship_bloom_check(buddy->friends[i], to_aor))
				ret = i;
		}
	}
	if (ret > -1)
		ret += 2;
	return ret;
}

/* checks the buddylists buddies' bloom filters for a level. the
   buddies with matching filters are returned. */
int
ident_data_bb_find_connections_on_level(ship_list_t *buddy_list, char *remote_aor, int level, ship_list_t *list)
{
	int ret = -1;
	buddy_t *buddy;
	void *ptr = 0;

	/* todo: we should check the key also (or only!): get the reg
	   package from foreign_regs, extract the key, check. */
	
	ASSERT_TRUE(level < BLOOMBUDDY_MAX_LEVEL, err);
	while ((buddy = (buddy_t*)ship_list_next(buddy_list, &ptr))) {
		if (buddy->relationship != RELATIONSHIP_FRIEND && ship_bloom_check(buddy->friends[level], remote_aor))
			ship_list_add(list, buddy);
	}
	ret = 0;
 err:
	return ret;
}

/* dumps all bloomfilters ascii-compatibly encoded (base64 actually)
   which can be used in xmls or other text-based outputs */
int
ident_data_bb_dump_ascii(ship_bloom_t *friends[], char **buf) 
{
	int ret = -1;
	char *tmp = 0;
	int len = 0, i, p = 0;
	
	/* format:
	(level byte, len word, data)*
	*/
	
	for (i = 0; i < BLOOMBUDDY_MAX_LEVEL; i++)
		len += ship_bloom_dump_size(friends[i]);
	len += (BLOOMBUDDY_MAX_LEVEL*3) + 16;

	ASSERT_TRUE(tmp = mallocz(len), err);
	for (i = 0; i < BLOOMBUDDY_MAX_LEVEL; i++) {
		int s = ship_bloom_dump_size(friends[i]);
		ship_inroll(i, &(tmp[p]), 1);
		ship_inroll(s, &(tmp[p+1]), 2);
		ship_bloom_dump(friends[i], &(tmp[p+3]));
		p += 3 + s;
	}

	if (((*buf) = ship_encode_base64(tmp, len)))
		ret = 0;
 err:
	freez(tmp);
	return ret;
}

/* loads bloomfilters from a dump */
int
ident_data_bb_load_ascii(char *buf, ship_bloom_t *friends[])
{
	int ret = -1;
	char *tmp = 0;
	int len = 0, p = 0;
	
	ASSERT_TRUE(tmp = ship_decode_base64(buf, strlen(buf), &len), err);
	while (p+3 < len) {
		int level, size;
		ship_unroll(level, &(buf[p]), 1);
		ship_unroll(size, &(buf[p+1]), 2);

		len -= 3;
		if (level >= BLOOMBUDDY_MAX_LEVEL || size > len) {
			ASSERT_TRUE(0, err);
		} else {
			ship_bloom_free(friends[level]);
			ASSERT_TRUE(friends[level] = ship_bloom_load(&(buf[p+3]), size), err);
			len -= size;
		}
	}
	ret = 0;
 err:
	freez(tmp);
	return ret;
}

#endif
