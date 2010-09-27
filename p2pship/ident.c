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
#include <sys/stat.h>

#include "ident.h"
#include "ship_utils.h"
#include "processor.h"
#include "ship_debug.h"
#include "conn.h"
#include "olclient.h"
#include "addrbook.h"
#include "ui.h"

/* the pp packets */
#define PP_MSG_ACK 1
#define PP_MSG_SUGGEST 2

ship_obj_list_t *identities = 0;
static ship_list_t *foreign_idents = 0;
static ship_list_t *cas = 0;

/* whether we have advertised our public profile */
static int public_put = 0;

/* the service handlers */
static ship_ht_t *ident_service_handlers = 0;

static void ident_clear_idents();
time_t ident_registration_timeleft(ident_t *ident);
static void ident_mark_foreign_regs_for_update();
static int ident_reregister_all();
static int ident_update_registration(ident_t *ident);
static void ident_cb_conn_events(char *event, void *data, void *eventdata);
static int ident_autoreg_save();

static char *idents_file = 0;
static char *autoreg_file = 0;
static int indent_allow_untrusted;
static int ident_allow_unknown_registrations;
static int ident_require_authentication;
static int sipp_ua_mode; /* 0=open 1=relax 2=paranoid */
static int renegotiate_secret = 0;

static int ident_handle_privacy_pairing_message(char *data, int data_len, 
						ident_t *target, char *source, 
						service_type_t service_type);

/* the default services */
static ship_ht_t *default_services = 0;

/* whether to ignore all validities for peer certs */
static int ignore_cert_validity = 0;

static struct service_s privacy_pairing_service =
{
 	.data_received = ident_handle_privacy_pairing_message,
	.service_closed = 0,
	.service_handler_id = "privacy_pairing_service"
};

#ifdef CONFIG_BLOOMBUDDIES_ENABLED

static int ident_handle_bloombuddy_message(char *data, int data_len, 
					   ident_t *target, char *source, 
					   service_type_t service_type);

static struct service_s bloombuddy_service =
{
 	.data_received = ident_handle_bloombuddy_message,
	.service_closed = 0,
	.service_handler_id = "bloombuddy_service"
};
#endif

static void
ident_cb_config_update(processor_config_t *config, char *k, char *v)
{
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_IDENT_ALLOW_UNTRUSTED, &indent_allow_untrusted), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_IDENT_ALLOW_UNKNOWN_REGISTRATIONS, 
					      &ident_allow_unknown_registrations), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_IDENT_REQUIRE_AUTHENTICATION, 
					      &ident_require_authentication), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_IDENT_IGNORE_CERT_VALIDITY,
					      &ignore_cert_validity), err);
	ASSERT_ZERO(processor_config_get_bool(config, P2PSHIP_CONF_IDENT_RENEGOTIATE_SECRET,
					      &renegotiate_secret), err);

	/* re-register all if ua mode change */
	ASSERT_ZERO(processor_config_get_enum(config, P2PSHIP_CONF_IDENT_UA_MODE, &sipp_ua_mode), err);
	if (k && !strcmp(k, P2PSHIP_CONF_IDENT_UA_MODE))
		ident_reregister_all();	
	return;
 err:
	PANIC("Could not get the needed configuration values!\n");
}


static void
ident_cb_events(char *event, void *data, void *eventdata)
{
	if (str_startswith(event, "net_")) {
		/* we don't want to discard all, but rather mark them
		   as should be updated. */
		ident_mark_foreign_regs_for_update();
	} else {
		/* do not re-register on network events. We well get
		   an event from the conn for a new listener anyway
		   soon.. */
		ident_reregister_all();
	}
}

/* inits the identity manager */
int
ident_module_init(processor_config_t *config)
{
	int ret = -1;
	
        LOG_INFO("Initing the identity module\n");

	OpenSSL_add_all_digests();
	OpenSSL_add_all_ciphers();

	ASSERT_TRUE(default_services = ship_ht_new(), err);
	ident_cb_config_update(config, NULL, NULL);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_ALLOW_UNTRUSTED, ident_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_ALLOW_UNKNOWN_REGISTRATIONS, ident_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_REQUIRE_AUTHENTICATION, ident_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_IGNORE_CERT_VALIDITY, ident_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_UA_MODE, ident_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_RENEGOTIATE_SECRET, ident_cb_config_update);
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_IDENTS_FILE, &idents_file), err);
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_AUTOREG_FILE, &autoreg_file), err);

	ASSERT_ZERO(ident_load_identities(), err);

 	ASSERT_ZERO(processor_event_receive("ol_*", 0, ident_cb_events), err);
 	ASSERT_ZERO(processor_event_receive("net_*", 0, ident_cb_events), err);
 	ASSERT_ZERO(processor_event_receive("conn_*", 0, ident_cb_conn_events), err);

	/* register the secret-negatiation protocol handler */
	ident_register_default_service(SERVICE_TYPE_PRIVACYPAIRING, &privacy_pairing_service);

#ifdef CONFIG_BLOOMBUDDIES_ENABLED
	ident_register_default_service(SERVICE_TYPE_BLOOMBUDDIES, &bloombuddy_service);
#endif
	
	ASSERT_TRUE(ident_service_handlers = ship_ht_new(), err);
	ret = 0;
 err:
	return ret;
}

/* 
 */
static void
ident_pp_send_message(char *from, char *to,
		      int msg_type, char *param)
{
	char *buf = 0;
	int blen = 2;
	if (param)
		blen += strlen(param) + 1;
	
	if ((buf = mallocz(blen))) {
		LOG_DEBUG("sending pp packet %s -> %s, type %d, param: %s..\n", from, to, msg_type, param);

		ship_inroll(msg_type, buf, 2);
		if (param)
			memcpy(buf+2, param, strlen(param));
		conn_send_simple(to, from,
				 SERVICE_TYPE_PRIVACYPAIRING,
				 buf, blen);
		freez(buf);
	}
}

/* create suggestion & send negotiation */
static void
ident_pp_start_negotiation(ident_t *ident, buddy_t *peer)
{
	const char *crypt_arr = "!#$%&()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";
	char *sugg = 0;
	int i;
	
	if (peer->my_suggestion) {
		sugg = peer->my_suggestion;
	} else {
		freez(peer->shared_secret);
		if ((sugg = mallocz(11))) {
			ship_get_random((unsigned char *)sugg, 10);
			
			/* convert those bytes into something readable.. */
			for (i = 0; i < 10; i++)
				sugg[i] = crypt_arr[sugg[i] % strlen(crypt_arr)];
			freez(peer->my_suggestion);
			peer->my_suggestion = sugg;
		}
	}
	
	if (sugg) {
		ident_pp_send_message(ident->sip_aor, peer->sip_aor,
				      PP_MSG_SUGGEST, sugg);
	}
}

#ifdef CONFIG_BLOOMBUDDIES_ENABLED
static void
ident_bb_send_buddies(ident_t *ident, buddy_t *buddy)
{
	int i;
	LOG_DEBUG("sending bloom buddies from %s to %s..\n", ident->sip_aor, buddy->sip_aor);
	
	for (i=0; i < BLOOMBUDDY_MAX_LEVEL; i++) {
		char *buf = NULL;
		int blen = 0;
		
		/* encode, IF we have any knowledge of that level.. */
		if (!ident_data_bb_encode(ident->buddy_list, buddy, &buf, &blen, i))
			conn_send_simple(buddy->sip_aor, ident->sip_aor,
					 SERVICE_TYPE_BLOOMBUDDIES,
					 buf, blen);
		freez(buf);
	}

	//ident_handle_bloombuddy_message(0, 1, 0, 0, 0);
}

static int
ident_handle_bloombuddy_message(char *data, int data_len, 
				ident_t *target, char *source, 
				service_type_t service_type)
{
	buddy_t *peer = NULL;
	ship_bloom_t *bloom = NULL;
	int level = 0;
	
	LOG_DEBUG("got bloom buddies from %s to %s..\n", target->sip_aor, source);
	ASSERT_TRUE(peer = ident_buddy_find(target, source), err);
	
	/* store only if we are friends? No, store all, decide later
	   how to handle each one */

	ASSERT_ZERO(ident_data_bb_decode(data, data_len, &bloom, &level), err);
	if (level < BLOOMBUDDY_MAX_LEVEL) {
		ship_bloom_free(peer->friends[level]);
		peer->friends[level] = bloom;
		bloom = NULL;
	}

	/* save these to disk */
	processor_run_async((void (*)(void))ident_save_identities);
 err:
	ship_bloom_free(bloom);
	return 0;
}
#endif

static void
ident_cb_conn_events(char *event, void *data, void *eventdata)
{
	LOG_DEBUG("got conn event %s\n", event);
	if (!strcmp(event, "conn_made") ||
	    !strcmp(event, "conn_got")) {
		conn_connection_t *conn = eventdata;
		ident_t *ident = 0;
		buddy_t *peer = 0;
		
		ASSERT_TRUE(ident = ident_find_by_aor(conn->local_aor), err);
		ship_lock(conn);
		ASSERT_TRUE(peer = ident_buddy_find(ident, conn->sip_aor), err);
		if (peer->shared_secret && strlen(peer->shared_secret) && !renegotiate_secret) {
			/* have secret, send ack package */
			ident_pp_send_message(conn->local_aor, conn->sip_aor,
					      PP_MSG_ACK, peer->shared_secret);
		} else if (strcmp(ident->sip_aor, peer->sip_aor) || !strcmp(event, "conn_made")) {
			/* no secret, start negotiation for a new one */
			freez(peer->my_suggestion);
			freez(peer->shared_secret);
			ident_pp_start_negotiation(ident, peer);
		}
#ifdef CONFIG_BLOOMBUDDIES_ENABLED
		/* send only to friends */
		if (peer->is_friend)
			ident_bb_send_buddies(ident, peer);
#endif
	err:
		ship_unlock(conn);
		ship_obj_unlockref(ident);
	} else if (!strcmp(event, "conn_new_listener")) {
		ident_reregister_all();
	}
}

static int
ident_handle_privacy_pairing_message(char *data, int data_len, 
				     ident_t *target, char *source, 
				     service_type_t service_type)
{
	int msg_type = -1;
	char *param = 0;
	buddy_t *peer = 0;
	int ret = -1;
	
	ASSERT_TRUE(data_len > 1, err);
	if (data_len > 2) {
		ASSERT_TRUE(param = mallocz(data_len-2+1), err);
		memcpy(param, data+2, data_len-2);
	}
	ship_unroll(msg_type, data, 2);
	
	LOG_DEBUG("got msg type %d, param: %s\n", msg_type, param);
	ASSERT_TRUE(peer = ident_buddy_find(target, source), err);
	
	switch (msg_type) {
	case PP_MSG_ACK:
		/* acks: if I have in use the same, do nothing, else
		   create suggest & send */
		
		/* if we do not have */
		
		if (!param || !peer->shared_secret || strcmp(peer->shared_secret, param)) {
			//printf("got ack .. but isn't working! '%s', when param was '%s'\n", peer->shared_secret, param);
			ident_pp_start_negotiation(target, peer);
		} else if (peer->my_suggestion) {
			/* save & use */
			LOG_DEBUG("got confirm for new secret for %s -> %s: %s\n",
				  target->sip_aor, source, peer->shared_secret);
			freez(peer->my_suggestion);
		} else {
			LOG_DEBUG("got confirm for old secret %s -> %s: %s\n",
				  target->sip_aor, source, peer->shared_secret);
		}
		ret = 0;
		break;
	case PP_MSG_SUGGEST:

		/* suggest: create my own suggest, send ack */
		
		ASSERT_TRUE(param, err);
		if (!peer->my_suggestion)
			ident_pp_start_negotiation(target, peer);
		ASSERT_TRUE(peer->my_suggestion, err);
		
		/* create whole secret, send ack */
		freez(peer->shared_secret);
		ASSERT_TRUE(peer->shared_secret = mallocz(strlen(peer->my_suggestion) + strlen(param) + 1), err);
		/* .. hm, which one was first now ? */
		if (strcmp(target->sip_aor, source) > 0) {
			strcpy(peer->shared_secret, peer->my_suggestion);
			strcat(peer->shared_secret, param);
		} else {
			strcpy(peer->shared_secret, param);
			strcat(peer->shared_secret, peer->my_suggestion);
		}

		/* send ack! */
		ident_pp_send_message(target->sip_aor, source,
				      PP_MSG_ACK, peer->shared_secret);
		/* save */
		LOG_DEBUG("using new secret for %s -> %s: %s, saving (async)\n",
			  target->sip_aor, source, peer->shared_secret);
		processor_run_async((void (*)(void))ident_save_identities);
		processor_run_async((void (*)(void))ident_reregister_all);
		ret = 0;
		break;
	default:
		break;
	}

 err:
	freez(param);
	return ret;
}

static int
ident_autoreg_save_do(void *data, processor_task_t **wait, int wait_for_code)
{
	int ret = -1;
	FILE *f = NULL;
	ident_t *ident;
	void *ptr = 0;
	char *buf = 0, *tmp = 0;
	int len = 0, size = 0;
	char *addr = 0;
	
	LOG_DEBUG("Saving autoreg identites\n");

	ship_lock(identities);
	while ((ident = ship_list_next(identities, &ptr))) {
		char tbuf[32];
		ident_service_t *s;
		void *p2 = 0;
		
		ship_lock(ident);
		
		/* save contact, expire date, state */
		ASSERT_TRUE((tmp = append_str(ident->sip_aor, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);

		/* these should be specified per-service: */
		while ((s = ship_ht_next(ident->services, &p2))) {
			if (s->service_handler_id) {
				sprintf(tbuf, "%d,", s->service_type);
				ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);

				ASSERT_TRUE((tmp = append_str(s->service_handler_id, buf, &size, &len)) && (buf = tmp), err);
				ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);
			
				ASSERT_ZERO(ident_addr_addr_to_str(&(s->contact_addr), &addr), err);
				ASSERT_TRUE((tmp = append_str(addr, buf, &size, &len)) && (buf = tmp), err);
				freez(addr);
				ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);
				sprintf(tbuf, "%d,", s->expire);
				ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);
				sprintf(tbuf, "%d,", (int)s->reg_time);
				ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);
			}
		}
		ASSERT_TRUE(replace_end(buf, &size, &len, ",", "\n"), err);
		ship_unlock(ident);
	}
	ship_unlock(identities);

	if (!(f = fopen(autoreg_file, "w"))) {
		LOG_ERROR("Could not open autoreg file %s\n", autoreg_file);
		goto err;
	}
	if (len != fwrite(buf, sizeof(char), len, f))
		goto err;
	
	ret = 0;
 err:
	if (f)
		fclose(f);
	freez(buf);
	freez(addr);

	/* done always, ignore errors */
	return 0;
	/* return ret; */
}

static int
ident_autoreg_save()
{
	processor_tasks_add(ident_autoreg_save_do, 
			    NULL, NULL);
	return 0;
}

static void 
_ident_autoreg_load_cb(void *data, int lc, char *key, char *value, char *line)
{
	char **tokens = 0;
	int toklen = 0;
	trim(line);
	if (!ship_tokenize(line, strlen(line), &tokens, &toklen, ',')) {
		ident_t *ident = 0;
		
		/* aor + n * ( service_type, service handler, address, expire, reg time) */
		if (((toklen - 1) % 5) == 0 && (ident = ident_find_by_aor(tokens[0]))) {
			int c = 1;
			while (c < toklen) {
				time_t now;
				ident_service_t *s = 0, *s2;
				if (!(s = ident_service_new())) {
					c += 5;
					continue;
				}
				
				s->service_type = atoi(tokens[c++]);
				s->service_handler_id = strdup(tokens[c++]);
				ident_addr_str_to_addr(tokens[c++], &(s->contact_addr));
				s->expire = atoi(tokens[c++]);
				s->reg_time = atoi(tokens[c++]);
				
				s2 = ship_ht_remove_int(ident->services, s->service_type);
				ident_service_close(s2, ident);
				ship_ht_put_int(ident->services, s->service_type, s);
				
				time(&now);
				LOG_INFO("Autoreg %s @ %s, port %d, expire in %d seconds..\n",
					 ident->sip_aor, s->contact_addr.addr,
					 s->contact_addr.port, s->reg_time + s->expire - now);
			}
			
			ident_update_registration(ident);
			ship_obj_unlockref(ident);
		}
		ship_tokens_free(tokens, toklen);
	}
}

int
ident_autoreg_load()
{
	int ret = -1;
	struct stat sdata;

	if (stat(autoreg_file, &sdata)) {
		LOG_WARN("Autoreg file %s does not exist\n", autoreg_file);
		return -2;
	}

	ASSERT_ZERO(ship_read_file(autoreg_file, NULL, _ident_autoreg_load_cb, NULL), err);
	ret = 0;
 err:
	return ret;
}

/* loads the identities */
int
ident_load_identities()
{
	int ret = -1;
	struct stat sdata;
	
	LOG_INFO("Loading identites & ca's from %s\n", idents_file);
        if (!identities) {
		ASSERT_TRUE(identities = ship_obj_list_new(), err);
	}
        if (!foreign_idents) {
		ASSERT_TRUE(foreign_idents = ship_list_new(), err);
	}
        if (!cas) {
		ASSERT_TRUE(cas = ship_list_new(), err);
	}

	ident_clear_idents();
	if (stat(idents_file, &sdata)) {
		LOG_WARN("Identity file %s does not exist\n", idents_file);
		ret = 0;
	} else {
		void *arr[3] = { identities, cas, NULL };
		ship_lock(identities);
		ship_lock(cas);
		if (ship_load_xml_file(idents_file, ident_load_ident_xml, arr)) {
			LOG_WARN("Could not load identity file %s\n", idents_file);
		} else {
			ret = 0;
		}
		ship_unlock(cas);
		ship_unlock(identities);
	}
 err:
	return ret;
}

ship_obj_list_t *
ident_get_identities()
{
	return identities;
}

ship_list_t *
ident_get_cas()
{
	return cas;
}

/* saves the identities */
void
ident_save_identities_async()
{
	ident_save_identities();
}

int
ident_save_identities()
{
	int ret = -1;
	char *data = NULL;
	int len;
	FILE *f = NULL;
	ca_t *ca;
	ident_t *ident;
	void *ptr = 0, *last = 0, *tmp_file = 0;
	
	LOG_INFO("Saving identites & ca's\n");

	ship_lock(identities);
	ship_lock(cas);

	/* remove all deleted identities, reset flags */
	while ((ca = ship_list_next(cas, &ptr))) {
		if (ca->modified == MODIF_DELETED) {
			ship_list_remove(cas, ca);
			ship_lock(ca);
			ship_unlock(ca);
			ident_ca_free(ca);
			ptr = last;
		} else
			ca->modified = MODIF_NONE;
		last = ptr;
	}
	ptr = 0;
	last = 0;
	while ((ident = ship_list_next(identities, &ptr))) {
		ship_lock(ident);
		if (ident->modified == MODIF_DELETED) {
			ship_unlock(ident);
			ship_obj_list_remove(identities, ident);
			ident = 0;
			ptr = last;
		} else
			ident->modified = MODIF_NONE;
		last = ptr;
		ship_unlock(ident);
	}

	ASSERT_ZERO(ident_create_ident_xml(identities, cas, &data), err);
	ASSERT_TRUE(len = strlen(data), err); // > 0

	// lets double check this ..
	ASSERT_TRUE(tmp_file = combine_str(idents_file, ".tmp"), err);
	if (!(f = fopen(tmp_file, "w"))) {
		LOG_ERROR("Could not open identity file %s\n", tmp_file);
		goto err;
	}
	ASSERT_TRUE(len == fwrite_all(data, len, f), err);
	ASSERT_ZERO(fclose(f), err);
	f = NULL;

	ASSERT_TRUE(rename(tmp_file, idents_file) != -1, err);
	ret = 0;
 err:
	if (f)
		fclose(f);
	freez(data);
	freez(tmp_file);
	ship_unlock(cas);
	ship_unlock(identities);
	return ret;
}

/* closes the identity manager */
void 
ident_module_close()
{
        LOG_INFO("closing the identity module\n");
	ident_clear_idents();
	ship_list_empty_with(foreign_idents, ident_reg_free);

	ship_obj_list_free(identities);
	ship_list_free(cas);
	ship_list_free(foreign_idents);
	ship_ht_free(ident_service_handlers);
	ship_ht_free(default_services);
	EVP_cleanup();
}

/* clears the idents & cas */
static void
ident_clear_idents()
{
	ca_t *ca;
	
	ship_obj_list_clear(identities);

	if (cas) {
		ship_lock(cas);
		while ((ca = ship_list_pop(cas))) {
			ship_lock(ca);
			ship_unlock(ca);
			ident_ca_free(ca);
		}
		ship_unlock(cas);
	}
}

static ca_t *
ident_find_ca_by_digest(char *dig)
{
	void *ptr = 0;
	ca_t *ca, *ret = NULL;
	
	ship_lock(cas);
	while (!ret && (ca = (ca_t*)ship_list_next(cas, &ptr))) {
		if (!strcmp(ca->digest, dig))
			ret = ca;
	}
	ship_lock(ret);
	ship_restrict_locks(ret, identities);
	ship_restrict_locks(ret, cas);
	ship_unlock(cas);
	
	return ret;
}

static ca_t *
ident_find_ca_by_serial(char *dig)
{
	void *ptr = 0;
	ca_t *ca, *ret = NULL;
	char *serial;

	ship_lock(cas);
		while (!ret && (ca = (ca_t*)ship_list_next(cas, &ptr))) {
			if ((serial = ident_data_x509_get_serial(ca->cert)) && !strcmp(serial, dig))
				ret = ca;
			freez(serial);
		}
		ship_lock(ret);
		ship_restrict_locks(ret, identities);
		ship_restrict_locks(ret, cas);
	ship_unlock(cas);

	return ret;
}

ca_t *
ident_get_issuer_ca(X509 *cert)
{
	char *key;
	ca_t *ret = 0;
	if ((key = ident_data_x509_get_issuer_digest(cert)))
		ret = ident_find_ca_by_digest(key);
	freez(key);
	return ret;
}

/* find a user identity by aor */
#ifdef LOCK_DEBUG
ident_t *
__ident_find_by_aor(const char *aor, const char *file, const char *func, const int line)
{
	ident_t *ret = 0;	
	char *l = mallocz(strlen(file) + strlen(func) + 75);
	sprintf(l, "%s:%s:%d", file, func, line);
	ship_wait(l);
	ret = _ident_find_by_aor(aor);
	ship_complete();
	freez(l);
	return ret;
}
#endif

static void 
ident_set_status_done(char *event, void *eventdata)
{
	ship_obj_unref(eventdata);
}


/* sets / gets the status */
void
ident_set_status(char *aor, char *status)
{
	ident_t *ident;
	void *ptr = 0;
	
	LOG_DEBUG("setting status for %s to %s\n", aor, status);
	ship_lock(identities);
	while ((ident = ship_list_next(identities, &ptr))) {
		ship_lock(ident);
		if (!aor || !strcmp(aor, ident->sip_aor)) {
			freez(ident->status);
			if (status)
				ident->status = strdup(status);

			/* send an event, cause conn's to be updated */
			ship_obj_ref(ident);
			processor_event_generate("ident_status", ident, ident_set_status_done);
			if (ship_list_length(ident->services))
				ident_update_registration(ident);
		}
		ship_unlock(ident);
	}
 	ship_unlock(identities);
	
}

/* gets / gets the status */
char *
ident_get_status(char *aor)
{
	ident_t *ident;
	void *ptr = 0;
	char *status = 0;
	
	/* just return the first one if there are many */
	ship_lock(identities);
	while (!status && (ident = ship_list_next(identities, &ptr))) {
		ship_lock(ident);
		if (!aor || !strcmp(aor, ident->sip_aor)) {
			if (ident->status)
				status = strdup(ident->status);
		}
		ship_unlock(ident);
	}
	
	ship_unlock(identities);
	return status;
}

int
ident_has_ident(const char* aor, const char *password)
{
        ident_t *ret = NULL;
	void *ptr = 0;
	
	ship_lock(identities);
	while (aor && !ret && (ret = (ident_t*)ship_list_next(identities, &ptr))) {
		if (strcmp(ret->sip_aor, aor))
			ret = NULL;
	}
	ship_unlock(identities);
        if (ret)
		return 1;
	else 
		return 0;
}

/* returns the current to-be-used 'default' aor - that is, one that is
   preferably registered, or then just the first one. this is somewhat
   uneccesarily used for the http forward */
ident_t *
ident_get_default_ident()
{
        ident_t *ret = NULL;
	void *ptr = 0;
	
        LOG_VDEBUG("should find default identity\n");
	ship_lock(identities);
	while (!ret && (ret = (ident_t*)ship_list_next(identities, &ptr))) {
		ship_lock(ret);
		if (ident_registration_timeleft(ret) < 1) {
			ship_unlock(ret);
			ret = 0;
		}
	}
	if (!ret) {
		ret = ship_list_first(identities);
		ship_lock(ret);
	}
	if (ret) {
		ship_obj_ref(ret);
		LOG_DEBUG("using as default identity %s..\n", ret->sip_aor);
	}
	
	ship_restrict_locks(ret, identities); 
	ship_unlock(identities);
        return ret;
}

ident_t *
_ident_find_by_aor(const char *aor)
{
        ident_t *ident, *ret = NULL;
	void *ptr = 0;
	
        LOG_VDEBUG("should find identity for aor %s\n", aor);
	ship_lock(identities);
	while (aor && !ret && (ident = (ident_t*)ship_list_next(identities, &ptr))) {
		ship_lock(ident);
		if (!strcmp(ident->sip_aor, aor)) // crash once
			ret = ident;
		else
			ship_unlock(ident);
	}
	ship_obj_ref(ret);
	ship_restrict_locks(ret, identities); 
	ship_unlock(identities);
        return ret;
}

ident_t *
ident_register_new_empty_ident(char *sip_aor)
{
	ident_t *ret = NULL;
	
	ship_lock(identities);
	ret = ident_find_by_aor(sip_aor);
	if (!ret) {
		ASSERT_TRUE(ret = (ident_t*)ship_obj_new(TYPE_ident, sip_aor), err);
		ASSERT_TRUE(ret->username = strdup(sip_aor), err);
		
		/* fill private key and certificate. */
		ASSERT_TRUE(ret->private_key = ship_create_private_key(), err);
		ASSERT_TRUE(ret->cert = ship_sign(sip_aor,
						  365*60*60*24, ret->private_key), err);
		
		
 		ship_lock(ret);
 		ship_restrict_locks(ret, identities);
		ship_obj_list_add(identities, ret);

		/* ..and flag it so that it doesn't get saved! */
		/* actually, we may want to save this after all! */
		//ret->do_not_save = 1;
		processor_run_async((void (*)(void))ident_save_identities);
	}
	goto end;
 err:
	ship_obj_unlockref(ret);
	ret = 0;
 end:
	ship_unlock(identities);
	return ret;
}

/* ident helpers */
static int
ident_update_service_registration(ident_t *ident, service_type_t service_type,
				  service_t *service, addr_t *addr, 
				  int expire, void *pkg)
{
	int ret = -1;
	ident_service_t *s;
	
	s = ship_ht_get_int(ident->services, service_type);
	if (expire == 0) {
		/* check that it is the same handler */
		if (s && s->service == service) {
			LOG_INFO("removing registration i have for %s, service type %u\n", ident->sip_aor, service_type);
			
			/* actually, we dont remove it, because we
			   need the contact address for sending any
			   reply to the un-register command! */
			s->expire = -1;
			/* ship_ht_remove_int(ident->services, service_type);
			   ident_service_close(s); */
		} else {
			LOG_WARN("ignoring service removal for %s, service type %u\n", ident->sip_aor, service_type);
		}
	} else {
		time_t now;

		LOG_INFO("Should update registration for %s (exp %d)\n", 
			 ident->sip_aor, expire);
		
		if (!s) {
			ASSERT_TRUE(s = ident_service_new(), err);
			ship_ht_put_int(ident->services, service_type, s);
		} else if (s->service && s->service->service_closed) {
			/* should we call the close here inbetween? */
			s->service->service_closed(s->service_type, ident, s->pkg);
		}

		now = time(0);
		s->service_type = service_type;
		s->service = service;
		freez(s->service_handler_id);
		if (service->service_handler_id)
			s->service_handler_id = strdup(service->service_handler_id);
		s->reg_time = now;
		s->expire = expire;
		s->pkg = pkg;

		/* translate to ip address here.. ? */
		if (addr)
			memcpy(&(s->contact_addr), addr, sizeof(addr_t));
	}

	ret = 0;
 err:
	return ret;
}

static int
_ident_process_register(char *aor, service_type_t service_type, service_t *service,
			addr_t *addr, int expire, void *pkg, int force_update)
{
	ident_t *ident = 0;
	int ret = 500;

	if (aor) {
		if (strcmp(aor, "@") == 0)
			ident = (ident_t *)ident_get_default_ident();
		else
			ident = (ident_t *)ident_find_by_aor(aor);
		
		/* check policy - can we register those that we have no account of? */ 
		if (!ident && ident_allow_unknown_registrations) {
			LOG_DEBUG("creating new, temporary identity for %s\n", aor);
			ident = ident_register_new_empty_ident(aor);
		}
		
		if (ident) {
			if (ident_require_authentication) {
				/* todo: how should we actually do this?? */
				ret = 401;
			} else if (!ident_update_service_registration(ident, service_type, service,
								      addr, expire, pkg)) {
				
				/* unless force update, update only if
				   the current ttl will not fit into
				   the one that has been assigned
				   .. */

				/* no, on second thought, never update
				   - we should always be directly
				   connected anyway. */
				if (force_update)
					ident_update_registration(ident);
				ret = 200;
			}
			ship_obj_unlockref(ident);
		} else {
			ret = 400;
		}
		
	} else {                        
		ret = 403;
	}

	return ret;
}

/* registers an ident for a certain contact address. Actually, this
   registers the 'sip' service for the given identity at the given
   contact address */
int
ident_process_register(char *aor, service_type_t service_type, service_t *service,
			addr_t *addr, int expire, void *pkg)
{
	return _ident_process_register(aor, service_type, service, addr, expire, pkg, 1);
}

/* like the real register, but doesn't update all the external data
   (puts etc..) unless necessary .. */
int
ident_process_response_register(char *aor, service_type_t service_type, service_t *service,
				addr_t *addr, int expire, void *pkg)
{
	return _ident_process_register(aor, service_type, service, addr, expire, pkg, 0);
}

char*
ident_get_regxml(ident_t *ident)
{
	char *ret = NULL;
	ship_lock(ident);
	if (!ident_create_new_reg(ident))
		ret = strdup(ident->reg->cached_xml);
	ship_unlock(ident);
	return ret;
}

int
ident_create_new_reg(ident_t *ident)
{
	int ret = -1;
	
	ident_reg_free(ident->reg);
	ident->reg = NULL;
	
	ASSERT_TRUE(ident->reg = ident_reg_new(ident), err);
	ASSERT_ZERO(conn_fill_reg_package(ident, ident->reg), err);
	
	/* set the validity and time-of-creation according to the reg */
	ident->reg->created = time(0);
	ident->reg->valid = time(0) + ident_registration_timeleft(ident);

	/* create new xml */
	ASSERT_ZERO(ident_create_reg_xml(ident->reg, ident, 
					 &(ident->reg->cached_xml)), err);
	ret = 0;
 err:
	return ret;
}

/* checks whether the ident has a valid registration */
int
ident_registration_is_valid(ident_t *ident, service_type_t service)
{
	time_t now;
	time(&now);
	if (ident) {
		ident_service_t *s = ship_ht_get_int(ident->services, service);

		if (s && ((s->expire < 0) ||
			  ((s->reg_time + s->expire) >= now)))
			return 1;
	}
	
	return 0;
}

time_t
ident_registration_timeleft(ident_t *ident)
{
	time_t timeleft, now;
	ident_service_t *s;
	void *ptr = 0;

	now = time(0);
	timeleft = 0;
	while ((s = ship_ht_next(ident->services, &ptr))) {
		int tl = s->reg_time + s->expire - now;
		if (s->expire < 0)
			tl = 3600; // default to indicate?
		if (tl > timeleft)
			timeleft = tl;
	}
	
	return timeleft;
}

/* registers a service handler. The point with calling this is that
   when saving / loading the state, only the ID of the service_handler
   gets restored. We need to find the actual object in that case. For
   normal operation, we don't need this, as the handler is (or could
   be) given when registering the handler for an ident. */
int
ident_service_register(service_t *service)
{
	ship_ht_put_string(ident_service_handlers, service->service_handler_id, service);
	return 0;
}

service_t *
ident_get_default_service(service_type_t service_type)
{
	return ship_ht_get_int(default_services, service_type);
}

int
ident_register_default_service(service_type_t service_type, service_t *s)
{
	LOG_DEBUG("registering default handler '%s' for type %d\n",
		  s->service_handler_id, service_type);
	ship_ht_put_int(default_services, service_type, s);
	return 0;
}

service_t *
ident_get_service(ident_t *ident, service_type_t service_type)
{
	ident_service_t *s = ship_ht_get_int(ident->services, service_type);
	if (s) {
		if (!s->service && s->service_handler_id) {
			/* find the service based on the service id */
			s->service = ship_ht_get_string(ident_service_handlers, s->service_handler_id);
		}
		return s->service;
	} else {
		/* find 'default' services */
		return ship_ht_get_int(default_services, service_type);
	}
	return NULL;
}

addr_t *
ident_get_service_addr(ident_t *ident, service_type_t service_type)
{
	ident_service_t *s = ship_ht_get_int(ident->services, service_type);
	if (s)
		return &(s->contact_addr);
	else
		return NULL;
}

void *
ident_get_service_data(ident_t *ident, service_type_t service_type)
{
	ident_service_t *s = 0;
	if (!ident)
		return NULL;
	
	if ((s = ship_ht_get_int(ident->services, service_type)))
		return s->pkg;
	else
		return NULL;
}

static
void ident_update_registration_done(void *qt, int code)
{
	freez(qt);
}

static int
ident_update_registration_do(void *data, processor_task_t **wait, int wait_for_code)
{
	int ret = -1;
	time_t timeleft;
	char *aor = data;
	ident_t *ident = 0;
	void *ptr = 0;
	buddy_t *buddy = NULL;
	
	ASSERT_TRUE(ident = ident_find_by_aor(aor), err);
	timeleft = ident_registration_timeleft(ident);
	LOG_INFO("Should update registration for %s\n", ident->sip_aor);
	
	if (!timeleft) {
		unsigned char *hmac_key64 = NULL;
		
		while ((buddy = (buddy_t*)ship_list_next(ident->buddy_list, &ptr))) {
			if (buddy->shared_secret) {
				hmac_key64 = ship_hmac_sha1_base64(ident->sip_aor, buddy->shared_secret);	
				if (hmac_key64) {
					olclient_remove((char *)hmac_key64, NULL);
					free(hmac_key64);
				}
			}
		}
		
		/* do this even though we are in paranoid.. ? */
		if (public_put) {
			olclient_remove(ident->sip_aor, NULL);
			public_put = 0;
		}
	} else {
		ASSERT_ZERO(ident_create_new_reg(ident), err);

		while ((buddy = (buddy_t*)ship_list_next(ident->buddy_list, &ptr))) {
			if (buddy->shared_secret && buddy->cert) {
				olclient_put_anonymous_signed_for_someone_with_secret(ident->sip_aor, ident->reg->cached_xml, 
										      ident, buddy, buddy->shared_secret, timeleft, 
										      processor_config_string(processor_get_config(), P2PSHIP_CONF_OL_SECRET));
				LOG_DEBUG("secret reg done for %s to buddy %s\n", ident->sip_aor, buddy->sip_aor);
			}
		}

		if (sipp_ua_mode != PARANOID) {
			public_put = 1;
			olclient_put(ident->sip_aor, ident->reg->cached_xml, timeleft, 
				     processor_config_string(processor_get_config(), P2PSHIP_CONF_OL_SECRET));
			LOG_DEBUG("public reg for %s done\n", ident->sip_aor);
		} else if (public_put) {
			olclient_remove(ident->sip_aor, NULL);
			public_put = 0;
		}
	}
			
	ident_autoreg_save();
	ret = 0;
err:
	ship_obj_unlockref(ident);
	return ret;
	
}

/* this should probably be called async! */
static int
ident_update_registration(ident_t *ident)
{
	processor_tasks_add(ident_update_registration_do,
			    strdup(ident->sip_aor), 
			    ident_update_registration_done);
	return 0;
}


/* this one is called when a new connection to a dht etc has been
   made. this should re-register all identities (put into dht
   again) */
static int 
ident_reregister_all()
{
	void *ptr = 0;
	ident_t *temp_ident = 0;
	
	ship_lock(identities);
	while ((temp_ident = ship_list_next(identities,  &ptr))){
			ship_lock(temp_ident);

			/* update if it seems that we have *any* services that might be
			   outdated or not.. */
			if (ship_list_length(temp_ident->services)) {
				ident_update_registration(temp_ident);
			}
			ship_unlock(temp_ident);
		}
	ship_unlock(identities);
	return 0;
}

#ifdef NEW_CONNS
int
ident_reinit_transport_handlers()
{
	ident_t *ident = 0;
	void *ptr = 0;
	
	ship_lock(identities);
	while ((ident = (ident_t*)ship_list_next(identities, &ptr))) {
		ship_lock(ident);
		conn_init_transports(ident);		
		ship_unlock(ident);
	}
	ship_unlock(identities);
	return 0;
}
#endif

/* this function resets the foreign reg package cache. should be
 * called e.g. when changing networks to update possible peer
 * addresses and not to try connecting to some old non-routable
 * addresss, but rather just report 404
 */
void
ident_reset_foreign_regs()
{
	LOG_INFO("Resetting peer registrations cache..\n");
	ship_list_empty_with(foreign_idents, ident_reg_free);
}

static void 
ident_mark_foreign_regs_for_update()
{
	LOG_DEBUG("Marking peer registration cache for update..\n");
	ship_lock(foreign_idents);
	void *ptr = 0;
	reg_package_t *r;
	while ((r = (reg_package_t *)ship_list_next(foreign_idents, &ptr)))
		r->need_update = 1;
	ship_unlock(foreign_idents);
}

static int
ident_update_buddy_cert(void *aor, processor_task_t **wait, int wait_for_code)
{
	reg_package_t *reg = 0;
	char *name = 0;
	X509 *cert = 0;
	void *ptr = 0;
	ident_t *ident = 0;
	
	ASSERT_TRUE(aor, err);

	/* make a copy of the cert & name & aor of the user. add to
	   all your contacts! */

 	ASSERT_TRUE(reg = ident_find_foreign_reg(aor), err);
	ASSERT_TRUE(name = strdup(reg->name), err);
	ASSERT_TRUE(cert = X509_dup(reg->cert), err);

	ship_unlock(reg);
	reg = 0;

	/* ok.. */
	ship_lock(identities);
	while ((ident = ship_list_next(identities, &ptr))) {
		buddy_t *buddy = 0;
		
		ship_lock(ident);
		if (strcmp(ident->sip_aor, aor) && 
		    (buddy = ident_buddy_find_or_create(ident, aor))) {
			X509 *c2 = 0;

			/* update name & cert! */
			if (!buddy->name || !strlen(buddy->name)) {
				char *tmp = strdup(name);
				if (tmp) {
					freez(buddy->name);
					buddy->name = tmp;
				}
			}
			
			/* always replace the cert.. */
			if ((c2 = X509_dup(cert))) {
				LOG_DEBUG("replacing the certificate for %s's buddy %s\n", ident->sip_aor, aor);
				if (buddy->cert)
					X509_free(buddy->cert);
				buddy->cert = c2;
			}
		}
		ship_unlock(ident);
	}
	ship_unlock(identities);
	ident_save_identities();
 err:
	if (reg) 
		ship_unlock(reg);
	freez(name);
	if (cert) X509_free(cert);
	return 0;
}

static void 
ident_update_buddy_cert_done(void *qt, int code)
{
	freez(qt);
}


int
ident_cert_is_valid(X509 *cert)
{
	int ret = 0;

	if (!ignore_cert_validity) {
		time_t start, end, now;
		now = time(NULL);
		
		/* still/yet valid? (the cert) */
		ASSERT_ZERO(ident_data_x509_get_validity(cert, &start, &end), err);
		ASSERT_TRUE(((start - TIME_APPROX) <= now) && ((end + TIME_APPROX) >= now), err);
	}
	ret = 1;
 err:
	return ret;
}


int
ident_cert_is_trusted(X509 *cert)
{
	ca_t *ca;
	int ret = 0;
	
	/* find suitable CA */
	ca = ident_get_issuer_ca(cert);
	if (ca) {	
		/* check signature */
		int match = ident_data_x509_check_signature(cert, ca->cert);
		ship_unlock(ca);
		if (!match) {
			LOG_WARN("Registration package wasn't signed by CA\n");
			goto err;
		}
	} else {
		ASSERT_TRUE(indent_allow_untrusted, err);
		/* allow an untrusted peer */
	}

	ret = 1;
 err:
	return ret;
}


/* this function imports the given reg package.  it performs all sort
 * of checks according to current policies - whether the package is
 * signed, whether the signature is valid, whether the package itself
 * is valid, whether we already have a never & more recent package for
 * this user, and so on..
 *
 * returns 0 on successful import, -1 on error
 *
 * successful means that the package was valid & newer or as-new as
 * the latest one we know of.
 *
 * Ownership IS taken, the reg package may be invalid after returning.
 */
int
ident_import_foreign_reg(reg_package_t *reg)
{
	int ret = -1;
	void *ptr = NULL;
	void *last = NULL;
	reg_package_t *r;
	int import = 1;
	
	if (!ignore_cert_validity) {
		time_t now;
		now = time(NULL);
		
		/* still valid? (the reg package) */
		ASSERT_TRUE(((reg->created - TIME_APPROX) <= now) && ((reg->valid + TIME_APPROX) >= now), err);
		
		/* still/yet valid? (the cert) */
		ASSERT_TRUE(ident_cert_is_valid(reg->cert), err);
	}
	
	ASSERT_TRUE(ident_cert_is_trusted(reg->cert), err);
	
        /* ok, seemengly valid. check still if we have a newer one */
	ship_lock(foreign_idents);
	while (import && (r = (reg_package_t *)ship_list_next(foreign_idents, &ptr))) {
		if (!strcmp(r->sip_aor, reg->sip_aor)) {
			if (reg->created >= r->created) {
				ship_lock(r);
				ship_list_remove(foreign_idents, r);
				ship_unlock(r);
				ident_reg_free(r);
				ptr = last;
			} else {
				import = 0;
			}
		}
		last = ptr;
	}
                
	if (import) {
		ship_list_add(foreign_idents, reg);
		LOG_DEBUG("new registration package added for %s\n", reg->sip_aor);

		/* update all idents buddies that might have this */
		processor_tasks_add(ident_update_buddy_cert, strdup(reg->sip_aor), ident_update_buddy_cert_done);
		reg = NULL;
		ret = 0;
	} else {
		ret = -2;
	}
	ship_unlock(foreign_idents);

 err:
	ident_reg_free(reg);
        return ret;
}

/* 
 * fetches from the cache a foreign reg-package for the given sip aor
 *
 * @todo This should actually be account-specific (with the privacy things)
 */
reg_package_t *
ident_find_foreign_reg(char *sip_aor)
{
        reg_package_t * ret = NULL;
	time_t start, end, now;
	void *ptr = NULL;
	reg_package_t *r;
	
        ship_lock(foreign_idents);
	while (!ret && (r = (reg_package_t *)ship_list_next(foreign_idents, &ptr))) {
		if (!strcmp(r->sip_aor, sip_aor)) {
			now = time(NULL);				
			if (ignore_cert_validity ||
			    ((!ident_data_x509_get_validity(r->cert, &start, &end)) &&
			     ((start <= (now + TIME_APPROX)) && (end >= (now - TIME_APPROX)))))
				ret = r;
			else
				LOG_WARN("reg info for %s is not valid!! (%d - %d, now %d)\n", sip_aor, start, end, now);
				
		}
	}
		
	if (ret) {
		ship_lock(ret);
		ship_restrict_locks(ret, foreign_idents);
	} else {
		LOG_DEBUG("could not find valid reg for %s\n", sip_aor);
	}
	ship_unlock(foreign_idents);
        return ret;
}



/* callback called after submitting a search for registrations. the
   buf will contain an array of all the entries found for the key. the
   actual data can be whatever (not necessarily a registration entry.

   The status indicates the success of the operation -
   0   is ok, data found, alles gut
   -1  not found (no entries found for key)
   -2  general / other error
   -4  mem fault
   1 ok, but more might still come.
*/
void
ident_cb_lookup_registration(char *key, char *buf, char *signer, void *param, int status)
{
	int imported = 0;
        processor_task_t *val = (processor_task_t *)param;
	
        LOG_INFO("lookup for %s callback with code %d.\n", key, status);
        if (buf) {
                reg_package_t *reg = NULL;
		LOG_VDEBUG("Got data: '%s'\n", buf);
		ident_reg_xml_to_struct(&reg, buf);
                if (reg && !ident_import_foreign_reg(reg)) {
                        status = 0;
                        imported = 1;
                }
        }
        
        /* signal done if we got *any* reg package, even though not
	   the newest */
	if (imported || status != 1) {
		if (!imported && status < 0)
			status = -1;

		/* mark the end time of the lookup! */
		LOG_DEBUG("ended lookup for %s as imported: %d and status: %d\n", key, imported, status);
		STATS_LOG("ended lookup for %s\n", key);
#ifdef CONFIG_SIP_ENABLED
#ifdef DO_STATS
		ac_packetfilter_stats_event(NULL, key, "lookup_end");
#endif		
#endif
		/* might be that val isn't anymore a valid event, but
		   doesn't matter, the processor checks that */
		processor_signal_wait(val, status);
	}
}

#ifdef NEW_CONNS

/* retrieves the connection parameters for a remote peer, only if
 * present.  returns a copy of the string. ownership transferred. */
char *
ident_get_transport_params(ident_t *ident, const char *remote_aor, 
			   const char *transport)
{
	reg_package_t *pkg = 0;
	char *ret = 0;
	ship_lock(ident);
        if ((pkg = ident_find_foreign_reg((char*)remote_aor))) {
		ret = ship_ht_get_string(pkg->transport_addresses, transport);
		if (ret)
			ret = strdup(ret);
		ship_unlock(pkg);
	}
	LOG_HL("transport params for %s are '%s'\n", transport, ret);
	ship_unlock(ident);
	return ret;
}

static void 
ident_update_transport_done(void *rdata, int code)
{
	ident_t *ident;
	void *d = 0;
	char *remote_aor = 0;
	buddy_t *buddy;

	LOG_HL("notifying lookup waiting clients with code %d\n", code);
	ship_unpack_keep(rdata, &ident, &remote_aor, NULL, NULL, NULL);
	ship_obj_lockref(ident);
	
	ASSERT_TRUE(buddy = ident_buddy_find_or_create(ident, remote_aor), err);
	while ((d = ship_list_pop(buddy->lookup_cb))) {
		char *transport;
		ident_transport_param_cb callback;
		void *ptr;
		
		ship_unpack_keep(d, NULL, NULL, &transport, &callback, &ptr);
		callback(ident_get_transport_params(ident, remote_aor, transport), ptr);
		if (rdata != d)
			ship_pack_free(d);
	}
	buddy->lookup_wait = NULL;
 err:
	ship_obj_unlockref(ident);
	ship_pack_free(rdata);
}

static int 
ident_update_transport_do(void *data, processor_task_t **wait, int wait_for_code)
{
	ident_t *ident;
	char *remote_aor = 0;
	reg_package_t *pkg = 0;
	int ret = -1;
	
	if ((*wait)) {
		LOG_HL("lookup done, with code %d\n", wait_for_code);
		return wait_for_code;
	}
	
	ship_unpack_keep(data, &ident, &remote_aor, NULL, NULL, NULL);
	ret = ident_lookup_registration(ident, remote_aor, 
					&pkg, wait);
	ship_unlock(pkg);
	return ret;
}

/* updates async the connection parameters for a remote peer */
int
ident_update_transport_params(ident_t *ident, const char *remote_aor,
			      const char *transport,
			      ident_transport_param_cb callback, void *ptr)
{
	buddy_t *buddy = 0;
	void *ptr2 = 0;
	int ret = -1;
	
	ASSERT_TRUE(ptr2 = ship_pack("psspp", ident, remote_aor, transport, callback, ptr), err);
	
	ship_lock(ident);
	ASSERT_TRUE(buddy = ident_buddy_find_or_create(ident, (char*)remote_aor), err);
	if (!buddy->lookup_wait) {
                ASSERT_TRUE(buddy->lookup_wait = processor_tasks_add(ident_update_transport_do, ptr2,
								     ident_update_transport_done), err);
	}
	ship_list_add(buddy->lookup_cb, ptr2);
	ptr2 = 0;
	ret = 0;
 err:
	ship_unlock(ident);
	ship_pack_free(ptr2);
	//callback("no idea yet..", ptr);
	return ret;
}
#endif

int
ident_lookup_registration(ident_t *ident, char *remote_aor, 
			  reg_package_t **pkg, processor_task_t **wait)
{
        int ret = -1;
        		
        LOG_INFO("should lookup the registration for %s..\n", remote_aor);

	/* this is the only place we care whether the reg package
	   needs updating. If so, keep the old, but initiate an
	   update. */
        (*pkg) = ident_find_foreign_reg(remote_aor);
	/* check whether a transport address is present! */
        if (!(*pkg) || (*pkg)->need_update || !conn_can_connect_to(*pkg)) {
		processor_task_t *val = processor_create_wait();
                
		if (*pkg) {
			ship_unlock(*pkg);
			(*pkg) = 0;
		}

                if (!val) {
                        ret = -4;
		} else {   
			buddy_t *remote_user = NULL;
                     
			(*wait) = val;

			/* mark start of fetch! */
			STATS_LOG("start lookup for %s\n", remote_aor);
#ifdef CONFIG_SIP_ENABLED
#ifdef DO_STATS
			ac_packetfilter_stats_event(NULL, remote_aor, "lookup_start");
#endif
#endif                    
                	  
			/* find the buddy for that user */
			remote_user = ident_buddy_find(ident, remote_aor);
			
			/* here: add some logic for querying the user
			   whether we have a shared secret! */
			if (remote_user) {
				if (!remote_user->cert)
					remote_user = NULL;
				else if (!remote_user->shared_secret) {
					/* .. query? no, just use open mode automatically */
					remote_user = NULL;
				}
			}
				
			if (remote_user &&
			    (sipp_ua_mode == PARANOID || sipp_ua_mode == RELAX)) {
				LOG_DEBUG("finding the peer %s secretly\n", remote_aor);
				if (!olclient_get_anonymous_signed_for_someone_with_secret(remote_aor, remote_user, ident, remote_user->shared_secret,
											   val, ident_cb_lookup_registration))
					ret = 1;
			} else if (sipp_ua_mode != PARANOID) {
				/* we cant search for anything signed here (we don't have the buddy's cert!) */
				LOG_DEBUG("finding the peer %s openly\n", remote_aor);
				if (!olclient_get(remote_aor, val, ident_cb_lookup_registration))
					ret = 1;
			}
			
			if (ret != 1) {
				LOG_DEBUG("Something went wrong when initializing the lookup!\n", remote_aor);
				processor_signal_wait(val, -2);
				ret = -2;
			}
		}
	} else {
                ret = 0;
	}
	
	return ret; 
}

ship_list_t *
ident_get_file_list(char *dir_name, char *extn, ship_list_t* file_list)
{
	/* this structure is used for storing the name of each entry in turn. */
	struct dirent* entry;
	
	/* open the directory for reading. */
	DIR* dir = opendir(dir_name);
	if (!dir) {
		LOG_ERROR("Not able to open directory %s", dir_name);
		goto err;
	}

	/* read the directory's contents and return*/
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") && 
		    strstr(entry->d_name, extn) == (entry->d_name + strlen(entry->d_name) - strlen(extn))){
			char *file_name;
			int length = strlen(dir_name) + strlen(entry->d_name) + 1;
			file_name = (char *)calloc(length, sizeof(char));
			if (!file_name)
				continue;
			strcpy(file_name, dir_name);
			strcat(file_name, entry->d_name);
			ship_list_add(file_list, file_name);
		}
	}
	
	if (closedir(dir) == -1) 
		LOG_ERROR("Not able to close directory %s", dir_name);
	
	return file_list;
 err:
	return NULL;
}

int
ident_remove_ca(char *name)
{
	ca_t *ca;
	int count = 0;
	int i;
	int m = 0;

	ship_lock(cas);
	for (i=0; i < ship_list_length(cas); i++) {
		ca = ship_list_get(cas, i);
		if (strstr(ca->name, name)) {
			m = 1;
			LOG_INFO("Certificate: %s\n", ca->name);
			/*   				ident_data_print_cert("\t", ca->cert); */
			if (ui_query_ca_operation(ca, "remove", "yes", "no")) {
				ca->modified = MODIF_DELETED;
				count++;
				i--;
			}
		}
	}
	ship_unlock(cas);

	if (!m) {
		USER_ERROR("No CA found matching %s\n", name);
	}

	if (count && ident_save_identities()) {
		LOG_ERROR("Error while saving identities\n");
		return -1;
	}
		
	ui_print_import_result("Removed %d CAs.\n", count);
	return 0;
}

int
ident_remove_ident(char *name)
{
	int count = 0;
	int ret = -1;

	ship_lock(identities);
	count = ident_remove_ident_query(name, 1);
	if (count < 0)
		goto err;

	if (count && ident_save_identities()) {
		LOG_ERROR("Error while saving identities\n");
	}
 err:
	ship_unlock(identities);
	return ret;
}

int
ident_remove_ident_query(char *name, int query)
{
	ident_t *ident;
	int count = -1;

	ship_lock(identities);
	ident = ident_find_by_aor(name);
	if (!ident) {
		USER_ERROR("Identity with AOR %s not found\n", name);
		goto err;
	}

 	LOG_INFO("Identity: %s <%s>\n", ident->username, ident->sip_aor);
	count = 0;
	if (!query || ui_query_ident_operation(ident, "remove", "yes", "no")) {
		ident->modified = MODIF_DELETED;
		count++;
	}
	ship_obj_unlockref(ident);
	if (query)
		ui_print_import_result("Removed %d identities.\n", count);
 err:
	ship_unlock(identities);
	return count;
}

/* imports a file which may contain ca's, identities or both */
int
ident_import_file(char *file, int query)
{
	char *buf = 0;
	int ret = -1, len;

	ASSERT_ZERO(ship_load_file(file, &buf, &len), err);
	ret = ident_import_mem(buf, len, query, MODIF_NONE);
 err:
	freez(buf);
	return ret;
}

/* imports a file which may contain ca's, identities or both */
int
ident_import_mem(char *data, int datalen, int query, int modif)
{
	ship_list_t *newi = NULL, *newc = NULL, *newco = NULL;
	int ret = -1;
	ca_t *ca = NULL;	
	contact_t *contact = NULL;	
	int icount = 0, ccount = 0, concount = 0;
	
	ASSERT_TRUE(newi = ship_list_new(), err);
	ASSERT_TRUE(newc = ship_list_new(), err);
	ASSERT_TRUE(newco = ship_list_new(), err);
	
	{
		void *arr[3] = { newi, newc, newco };
		if (ship_load_xml_mem(data, datalen, ident_load_ident_xml, arr)) {
			LOG_ERROR("Error loading from buf\n");
			goto err;
		}
	}
	
	/* here we could have something like:

	ident_create_ops();
	ui_query_all-in-one(ops); // this will mark those we dont want to execute as 'no-ops'
	ident_execute_ops();
	ui_display_import_result();
	*/
	
	ret = 0;
	if (ship_list_first(newi) || ship_list_first(newc)) {
		ret = ident_import_ident_cas(newi, newc, query, modif, &icount, &ccount);
	}
	if (!ret && ship_list_first(newco)) {
		ret = addrbook_import_contacts(newco, &concount, query);
	}

	/* create some sort of result message summarizing the imports */
	if (ccount || icount || concount) {
		if (ident_save_identities()) {
			if (query)
				ui_print_error("Error while saving identities!\n");
		} else {
			char *str = 0, *tmp = 0;
			int i = 0, tot = 0;
			
			tot = (ccount? 1:0) + (icount? 1:0) + (concount? 1:0);
			ASSERT_TRUE(str = mallocz(1024), perr);
			ASSERT_TRUE(tmp = mallocz(128), perr);

			strcpy(str, "Imported ");
			if (icount) {
				sprintf(tmp, (icount == 1? "%d identity":"%d identities"), icount);
				strcat(str, tmp);
				i++;
			}

			if (ccount) {
				sprintf(tmp, (ccount == 1? "%d CA":"%d CAs"), ccount);
				if (i && i == (tot-1)) strcat(str, " and ");
				else if (i) strcat(str, ", ");
				strcat(str, tmp);
				i++;
			}

			if (concount) {
				sprintf(tmp, (concount == 1? "%d contact":"%d contacts"), concount);
				if (i && i == (tot-1)) strcat(str, " and ");
				else if (i) strcat(str, ", ");
				strcat(str, tmp);
				i++;
			}
			strcat(str, ".\n");
			if (query)
				ui_print_import_result(str);

		perr:
			freez(str);
			freez(tmp);
		}
	} else if (query) {
		ui_print_import_result("Nothing imported.\n");
	}


 err:
	ship_obj_list_free(newi);

	if (newc) {
		while ((ca = ship_list_pop(newc)))
			ident_ca_free(ca);
		ship_list_free(newc);
	}

	if (newco) {
		while ((contact = ship_list_pop(newco)))
			ident_contact_free(contact);
		ship_list_free(newco);
	}

	if (ret)
		LOG_ERROR("Error importing buf\n");
	return ret;
}

int
ident_import_ident_cas(ship_list_t *newi, ship_list_t *newc, int query, int modif, int *icount, int *ccount)
{
	int ret = -1;
	ca_t *ca = NULL;	
	char *str = NULL;
	ident_t *ident = NULL;
	char *q;
	*icount = 0; *ccount = 0;

	/* go through certs */
	ship_lock(cas);
	while ((ca = ship_list_pop(newc))) {
		ca_t *oca;
		
		LOG_INFO("Certificate: %s\n", ca->name);
		ASSERT_TRUE(str = ident_data_x509_get_serial(ca->cert), err);
		if ((oca = ident_find_ca_by_serial(str))) {
			ship_unlock(oca);

			USER_ERROR("Certificate already exists\n");
			if (query) {
				/* lets not complain if it is the
				   same. just ignore it. */
				oca = NULL;
				ident_ca_free(ca);
				ca = NULL;
			}
		} else {
			freez(str);
			ASSERT_TRUE(str = ident_data_x509_get_subject_digest(ca->cert), err);
			if ((oca = ident_find_ca_by_serial(str))) {
				LOG_INFO("Certificate for the same issuer already exists:\n");
				ship_unlock(oca);
			}
		}

		if (oca) {
			ident_data_print_cert("\t", oca->cert);
			q = "replace";
		} else {
			q = "import";
		}
			
		if (ca && (!query || ui_query_ca_operation(ca, q, "yes", "no"))) {
			ship_lock(cas);
			ship_list_remove(cas, oca);
			ship_list_add(cas, ca);
			ca->modified = modif;
			ship_unlock(cas);
			ident_ca_free(oca);
			ca = NULL;
			(*ccount)++;
		} else {
			ident_ca_free(ca);
			ca = 0;
		}

		freez(str);
	}
	ship_unlock(cas);

	/* go through idents */
	ship_lock(identities);
	while ((ident = ship_list_pop(newi))) {
		ident_t *oident;
		
		/* find by sip aor */
		LOG_INFO("Identity: %s <%s>\n", ident->username, ident->sip_aor);
		if ((oident = ident_find_by_aor(ident->sip_aor))) {
			LOG_INFO("Identity for SIP AOR already exists:\n");
			ship_unlock(oident); /* we have lock on identities already */
			LOG_INFO("%s <%s>\n", oident->username, oident->sip_aor);
			q = "replace";
		} else {
			q = "import";
		}
		
		ca = ident_get_issuer_ca(ident->cert);
		if (ca) {	
			if (!ident_data_x509_check_signature(ident->cert, ca->cert)) {
				USER_ERROR("Warning: Signature invalid\n");
			}
			ship_unlock(ca);
		} else {
			USER_ERROR("Warning: Identity not issued by a trusted CA\n");
		}
		ca = NULL;

		if (!query || ui_query_ident_operation(ident, q, "yes", "no")) {
			ship_lock(identities);
			ship_obj_list_remove(identities, oident);
			ship_obj_list_add(identities, ident);
			ident->modified = modif;
			ship_unlock(identities);
			
#ifdef CONFIG_MC_ENABLED
			if (query) {
				char *aname = 0, *tmp = 0;
				int enable = 0;
				int update = 1;
				
				/* you already seem to have an account.. ? */
				if (aname = mc_get_account_name(ident->sip_aor)) {
					ASSERT_TRUE(tmp = mallocz(strlen(aname) + 256), mc_err);
					sprintf(tmp, "You seem to already have an account '%s' configured for this identity. Do you want to update it or create a new?", aname);
					switch (ui_query_three("Update account?", tmp, "update", "new", "skip")) {
					case 0: update = 1; break;
					case 1: update = 0; break;
					case 2: update = -1; break;
					}						
					freez(tmp);
				}
				
				if (update > -1) {
					/* enable the account now or later .. */
					if (ui_query_simple("Enable account?",
							    "Do you want to enable the account now?", "yes", "later"))
						enable = 1;
					
					/* just create the contact now. */
					if (mc_create_contact(ident->username, ident->sip_aor, update, enable)) {
						/* some error message */
						LOG_ERROR("Error creating account!\n");
						ui_print_error("An error occured while creating the account");
					}
				}
			mc_err:
				freez(tmp);
				freez(aname);
			}
#endif			
			
			ship_obj_unref(oident);
			ident = NULL;
			(*icount)++;
		} else {
			ship_obj_unref(ident);
			ident = 0;
		}

		freez(str);
	}
	ship_unlock(identities);

	ret = 0;
 err:
	freez(str);
	ident_ca_free(ca);
	ship_obj_unref(ident);
	return ret;
}

/* the ident register */
static struct processor_module_s processor_module = 
{
	.init = ident_module_init,
	.close = ident_module_close,
	.name = "ident",
	.depends = "ident_addr,ui,addrbook",
};

/* register func */
void
ident_register() {
	processor_register(&processor_module);
}
