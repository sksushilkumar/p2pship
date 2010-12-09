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
#include "ident.h"
#include "ship_utils.h"
#include "processor.h"
#include "ship_debug.h"
#include "ident.h"
#include <time.h>
#include <string.h>
#include "p2pship_version.h"
#include "conn.h"

static void ident_free(ident_t *ident);
static int ident_init(ident_t *ret, char *sip_aor);

static void ident_data_bb_add_buddy_to_bloom(ship_bloom_t *bloom, buddy_t *buddy);

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
	}
 err:
	return buddy;
}

buddy_t *
ident_buddy_find(ident_t *ident, char *sip_aor)
{
	void *ptr = 0;
	buddy_t *ret = 0;
	while ((ret = ship_list_next(ident->buddy_list, &ptr)) &&
	       strcmp(ret->sip_aor, sip_aor));
	return ret;
}


static int
ident_buddy_xml_to_struct(buddy_t **__buddy, xmlNodePtr cur)
{
	char *name = NULL, *sip_aor = NULL, *shared_secret = NULL, *certificate = NULL;
   	BIO *bio_cert = NULL;
   	int ret = -1;
   	buddy_t *buddy = NULL;
   		
   	(*__buddy) = NULL;
   	   	
   	ASSERT_ZERO(xmlStrcmp(cur->name, (const xmlChar*)"buddy"), err);
   	ASSERT_TRUE(sip_aor = ship_xml_get_child_field(cur, "sip-aor"), err);
	
   	name = ship_xml_get_child_field(cur, "name");
	shared_secret = ship_xml_get_child_field(cur, "shared-secret");

   	ASSERT_TRUE(buddy = ident_buddy_new(name, sip_aor, shared_secret), err);

   	if ((certificate = ship_xml_get_child_field(cur, "certificate"))) {
		ASSERT_TRUE(bio_cert = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(BIO_puts(bio_cert, certificate) > 0, err);
		ASSERT_TRUE(buddy->cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL), err);
   	}
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
	freez(name);
   	if ((name = ship_xml_get_child_field(cur, "bloombuddies"))) {
		ident_data_bb_load_ascii(name, buddy->friends);
	}
	freez(name);
   	if ((name = ship_xml_get_child_field(cur, "friend"))) {
		trim(name);
		if (ship_is_true(name))
			buddy->is_friend = 1;
	}
#endif
   	(*__buddy) = buddy;
   	buddy = NULL;
   	ret = 0;
 
 err:
    	
 	if (bio_cert) BIO_free(bio_cert);
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
		
		freez(reg->name);
		freez(reg->status);
		freez(reg->cached_xml);
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
        ASSERT_TRUE(ret->ip_addr_list = ship_list_new(), err);
        ASSERT_TRUE(ret->rvs_addr_list = ship_list_new(), err);
        ASSERT_TRUE(ret->hit_addr_list = ship_list_new(), err);
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
	return mallocz(sizeof(ident_service_t));
}

void
ident_service_close(ident_service_t *s, ident_t *ident)
{
	if (!s)
		return;
	
	if (s->service && s->service->service_closed) {
		s->service->service_closed(s->service_type, ident, s->pkg);
	}
	freez(s->service_handler_id);
	freez(s);
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
	ident_reg_free(ident->reg);
	ident_buddy_list_free(ident->buddy_list);
	ident->buddy_list = NULL;
	ident->reg = NULL;
	
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
	xmlNodePtr cur = NULL;
	xmlChar *xmlbuf = NULL;
	int bufsize = 0;
	int ret = -1;
	char timebuf[50];

	ASSERT_TRUE((doc = xmlNewDoc((const xmlChar*)"1.0")), err);
	ASSERT_TRUE((doc->children = xmlNewDocNode(doc, NULL, (const xmlChar*)"registration", NULL)), err);
	ASSERT_TRUE(cur = doc->children, err);

	/* sip-aor */
	ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"sip-aor", (const xmlChar*)reg->sip_aor), err);
	
	/* status, if present */
	if (reg->status) {
		ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"status", (const xmlChar*)reg->status), err);
	}

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
	ASSERT_TRUE(xmlNewTextChild(cur, NULL, (const xmlChar*)"client-version", (const xmlChar*)P2PSHIP_BUILD_VERSION), err);

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
	if (ident->private_key) {
		ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (const xmlChar*)"signature", NULL), err);
		
		/* signature algorithm */
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (const xmlChar*)"algorithm", (const xmlChar*)SIGN_ALGO), err);
		
		/* signature value */
		ASSERT_TRUE(digest = (char *)mallocz(SHA_DIGEST_LENGTH), err);
		ASSERT_TRUE(SHA1((unsigned char*)reg_data, strlen(reg_data), (unsigned char*)digest), err);
		
		ASSERT_TRUE(sign = (char *)mallocz(1024), err);	
		ASSERT_TRUE(RSA_sign(NID_sha1, (unsigned char*)digest, SHA_DIGEST_LENGTH, (unsigned char*)sign, &siglen, ident->private_key), err);
		
		ASSERT_TRUE(sign_64e = ship_encode_base64(sign, siglen), err);
		ASSERT_TRUE(xmlNewTextChild(tree, NULL, (xmlChar*)"value", (xmlChar*)sign_64e), err);
	}

	if (ident->cert) {
		/* certificate */
		ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
		ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &cert), err);
		cert[bufsize] = 0;
		ASSERT_TRUE(xmlNewTextChild(doc->children, NULL, (xmlChar*)"certificate", (xmlChar*)cert), err);
	}

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
	BIO *bio_cert = NULL;
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
	ASSERT_TRUE(bio_cert = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(BIO_puts(bio_cert, result) > 0, err);
	ASSERT_TRUE(reg->cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL), err);
	
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
		LOG_DEBUG("Signature not verified\n");
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
	if (bio_cert) BIO_free(bio_cert);
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
		if ((ret = ident_ident_xml_to_struct(&ident, cur)))
			return ret;
		
		LOG_INFO("Loaded identity %s\n", ident->sip_aor);
		ship_obj_list_add(idents, ident);
		ship_obj_unref(ident);
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"ca")) {
		ca_t *ca = NULL;			
		if ((ret = ident_ca_xml_to_struct(&ca, cur)))
			return ret;
		
		LOG_INFO("Loaded CA %s\n", ca->name);
		ship_list_add(cas, ca);
	} else if (!xmlStrcmp(cur->name, (xmlChar*)"contact")) {
		contact_t *contact = NULL;			
		if ((ret = ident_contact_xml_to_struct(&contact, cur)))
			return ret;
		
		LOG_INFO("Loaded contact %s\n", contact->name);
		ship_list_add(contacts, contact);
	}
	
	return 0;
}

/* reads an ident xml char* into the ident-structure */
int
ident_ident_xml_to_struct(ident_t **__ident, xmlNodePtr cur)
{
	char *result = NULL;
	char *cn = NULL;
	BIO *bio_key = NULL;
	BIO *bio_cert = NULL;
	int ret = -1;
	ident_t *ident = NULL;

	xmlNodePtr buddies = NULL, b = NULL;
	buddy_t *buddy = NULL;
	
	(*__ident) = NULL;
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)"identity"), err);
	ASSERT_TRUE(ident = (ident_t*)ship_obj_new(TYPE_ident, ""), err);
		
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "username"), err);
	ASSERT_TRUE(ident->username = strdup(result), err);

	freez(result);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "private-key"), err);
	ASSERT_TRUE(bio_key = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(BIO_puts(bio_key, result) > 0, err);
	BIO_flush(bio_key);
	
	/* why doesn't this work?? the callback is never called, the key-read just fails */
	/* todo: do a ERR_get_error etc to get the error code */
	ASSERT_TRUE(ident->private_key = PEM_read_bio_RSAPrivateKey(bio_key, NULL, 
								    ident_cb_openssl_pass, "private key"), err);
	
	freez(result);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "certificate"), err);

	ASSERT_TRUE(bio_cert = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(BIO_puts(bio_cert, result) > 0, err);
	ASSERT_TRUE(ident->cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL), err);
	
	/* read sip aor from cert, compare */
	ASSERT_TRUE(cn = ident_data_x509_get_cn(X509_get_subject_name(ident->cert)), err);
	ASSERT_ZERO(ident_set_aor(&(ident->sip_aor), cn), err);
	
	/* ..this is optional: */
	freez(cn);
	freez(result);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "sip-aor"), err);
	ASSERT_ZERO(ident_set_aor(&cn, result), err);	
	if (strcmp(cn, ident->sip_aor)) {
		LOG_WARN("Identity's specified SIP AOR (%s) differs from the issued (%s)\n",
			 cn, ident->sip_aor);
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
	BIO *bio_cert = NULL;
	int ret = -1;
	ca_t *ca = NULL;

	(*__ca) = NULL;
	ASSERT_ZERO(xmlStrcmp(cur->name, (xmlChar*)"ca"), err);
	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "name"), err);
	ASSERT_TRUE(ca = ident_ca_new(result), err);
	freez(result);

	ASSERT_TRUE(result = ship_xml_get_child_field(cur, "certificate"), err);
	ASSERT_TRUE(bio_cert = BIO_new(BIO_s_mem()), err);
	ASSERT_TRUE(BIO_puts(bio_cert, result) > 0, err);
	ASSERT_TRUE(ca->cert = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL), err);
	
	/* extract key id */
	ASSERT_TRUE(ca->digest = ident_data_x509_get_subject_digest(ca->cert), err);

	(*__ca) = ca;
	ca = NULL;
	ret = 0;
 err:
	
	if (bio_cert) BIO_free(bio_cert);
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
	xmlNodePtr tree, node;
	xmlChar *xmlbuf = NULL;
	BIO *bio = NULL;
	char *tmp = NULL;
	int ret = -1;
	void *ptr;
	ident_t *ident;
	ca_t *ca;
	int bufsize = 0;
	
	ASSERT_TRUE(doc = xmlNewDoc((xmlChar*)"1.0"), err);
	ASSERT_TRUE(doc->children = xmlNewDocNode(doc, NULL, (xmlChar*)"p2pship-ident", NULL), err);

	ASSERT_TRUE(tree = xmlNewTextChild(doc->children, NULL, (xmlChar*)"identities", NULL), err);
	for (ptr = 0; (ident = (ident_t*)ship_list_next(idents, &ptr));) {
		ship_lock(ident);

		/* skip the tmp idents */
		if (ident->do_not_save) {
			ship_unlock(ident);
			ident = 0;
			continue;
		}

		ASSERT_TRUE(node = xmlNewTextChild(tree, NULL, (xmlChar*)"identity", NULL), err);
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"sip-aor", (xmlChar*)ident->sip_aor), err);
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"username", (xmlChar*)ident->username), err);
		
		ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(PEM_write_bio_RSAPrivateKey(bio, ident->private_key, NULL, NULL, 0, NULL, NULL), err);
		ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
 		tmp[bufsize] = 0;
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"private-key", (xmlChar*)tmp), err);
		
		BIO_free(bio);
		bio = NULL;
		
		ASSERT_TRUE(bio = BIO_new(BIO_s_mem()), err);
		ASSERT_TRUE(PEM_write_bio_X509(bio, ident->cert), err);
		ASSERT_TRUE(bufsize = BIO_get_mem_data(bio, &tmp), err);
 		tmp[bufsize] = 0;
		ASSERT_TRUE(xmlNewTextChild(node, NULL, (xmlChar*)"certificate", (xmlChar*)tmp), err);

		BIO_free(bio);
		bio = NULL;
		
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
				ASSERT_TRUE(xmlNewTextChild(buddychildnode, NULL, (xmlChar*)"friend", (xmlChar*)(buddy->is_friend? "true":"false")), err);
#endif
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
	if ((pkey = X509_get_pubkey(ca))) {
		if (X509_verify(cert, pkey) > 0) {
			ret = 1;
		}
		EVP_PKEY_free(pkey);
	}
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
	char *tmp = 0;
	char *s1 = 0, *s2 = 0;
	
	ASSERT_TRUE(def = ident_get_default_ident(), err);
	ship_unlock(def);

	ASSERT_TRUE(buf = append_str("var p2pship_idents = {\n", buf, &buflen, &datalen), err);
	ship_lock(identities);
	while ((ident = ship_list_next(identities, &ptr))) {
		int len;
		addr_t *reg = 0;
		ship_lock(ident);
		len = strlen(ident->sip_aor) + 128;
		if ((s1 = ident_get_status(ident->sip_aor)))
			s2 = ship_urlencode(s1);
		
		/* todo: write better, show all services which the identity has registered .. */
		//if (ident->lis) reg = &(ident->lis->addr);
		if (ident->username) len += strlen(ident->username);
		if (s2) len += strlen(s2);
		//len += strlen(ident->contact_addr.addr);
		
		ASSERT_TRUE(tmp = mallocz(len), err);
		sprintf(tmp, "     \"%s\" : [ \"%s\", \"%d\", \"%s\", \"%s:%d\", \"%s:%d\", \"%s\", \"%s\", \"%s\" ],\n",
			ident->sip_aor, 
			(ident->username? ident->username:""), 0, //ident->reg_time, 
			(ident_registration_timeleft(ident)? "online" : "offline"),
			"", //ident->contact_addr.addr, 
			0, //ident->contact_addr.port,
			(reg? reg->addr:""), (reg? reg->port:0), 
			ident_modif_state_str(ident->modified),
			(s2? s2:""),
			(ident == def? "default": ""));
		
		ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
		freez(tmp);
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
	freez(s2);
	freez(s1);
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
			if (!bud->is_friend || (buddy && !strcmp(bud->sip_aor, buddy->sip_aor)))
				continue;
			ident_data_bb_add_buddy_to_bloom(bloom, bud);
		}
	} else {
		while ((bud = ship_list_next(buddy_list, &ptr))) {
			if (!bud->is_friend || (buddy && !strcmp(bud->sip_aor, buddy->sip_aor)))
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
	/* eh, we should use the key, not the aor, right? .. */
	/*
	if (buddy->cert) {
		EVP_PKEY *pkey = NULL;
		RSA *pu_key = NULL;
		ASSERT_TRUE(pkey = X509_get_pubkey(receiver->cert), err);
		ASSERT_TRUE(pu_key = EVP_PKEY_get1_RSA(pkey), err);
	}
	*/
	/* or .. both? */
	ship_bloom_add(bloom, buddy->sip_aor);
}


/* return the first level in any of the buddy list where the give aor
   might exist. 0 friend-of-friend. 1 - friend-of-friend-of-friend. */
int
ident_data_bb_get_first_level(ship_list_t *buddy_list, char *to_aor)
{
	int ret = -1;
	buddy_t *buddy;
	void *ptr = 0;

	/* todo: we should check the key also (or only!): get the reg
	   package from foreign_regs, extract the key, check. */

	while ((buddy = (buddy_t*)ship_list_next(buddy_list, &ptr)) &&
	       (ret != 0)) {
		int i;

		if (!buddy->is_friend)
			continue;
		
		for (i=0; i < BLOOMBUDDY_MAX_LEVEL && (ret < 0 || i < ret); i++) {
			if (ship_bloom_check(buddy->friends[i], to_aor))
				ret = i;
		}
	}
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
		if (buddy->is_friend && ship_bloom_check(buddy->friends[level], remote_aor))
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
