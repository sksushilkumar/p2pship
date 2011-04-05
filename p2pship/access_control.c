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
#include "access_control.h"
#include "ship_debug.h"
#include <osipparser2/osip_message.h>
#include <osip2/osip.h>
#include <osipparser2/sdp_message.h>
#ifdef CONFIG_OP_ENABLED
#include <opconn.h>
#endif
#include "sipp.h"
#include "trustman.h"
#include "processor.h"
#include "netio_http.h"
#ifdef CONFIG_HIP_ENABLED
#include "hipapi.h"
#endif
#include "conn.h"

//#define AC_HTTP_PF

static void ac_packetfilter_debug(ac_sip_t *asip);
static void ac_packetfilter_simple(ac_sip_t *asip);
#ifdef AC_HTTP_PF
static void ac_packetfilter_http(ac_sip_t *asip);
#endif
static void ac_packetfilter_trust(ac_sip_t *asip);
#ifdef DO_STATS
static void ac_packetfilter_stats(ac_sip_t *asip);
#endif
static void ac_packetfilter_blacklist(ac_sip_t *asip);
static void ac_packetfilter_whitelist(ac_sip_t *asip);
#ifdef CONFIG_OP_ENABLED
static void ac_packetfilter_op(ac_sip_t *asip);
#endif

/* white / blacklists */
static ship_ht_t *white_list = 0;
static ship_ht_t *black_list = 0;
static char *wl_file = 0;
static char *bl_file = 0;

#ifdef AC_HTTP_PF
static char *http_ac = 0;
#endif
static int max_path = 0;

#ifdef CONFIG_OP_ENABLED
static int op_filtering = 1;
#endif

/*
 * the stats- related stuff 
 */
#ifdef DO_STATS

static int pdd_reset_mode = 0;
static int pdd_log = 0;
#define PDD_LOG_FILE "p2pship_pdd_log.csv"

typedef struct pdd_stat_s {
	
	unsigned long start;
	unsigned long end;

	/* some other timestamps */

	/* ol lookup of the ident (only on first time) */
	unsigned long lookup_start;
	unsigned long lookup_done;

	/* connect time (only on first) */
	unsigned long connect_start;
	unsigned long connect_done;

	/* when the sip service packet was actually sent! */
	unsigned long sip_sent;

	/* time for the sip ua processing */
	unsigned long remote_start;
	unsigned long remote_done;

	time_t created;

	char *from;
	char *to;
	char *msg_type;
} pdd_stat_t;

/* the stats */
static ship_ht_t *stats = 0;
static ship_list_t *done_stats = 0;
static ship_ht_t *done_stats_ht = 0;

static int pdd_record_pdd(pdd_stat_t *stat);

/* a new stat */
static void
pdd_free_stat(pdd_stat_t *msg)
{
	if (msg) {
		freez(msg->msg_type);
		freez(msg->to);
		freez(msg->from);
		freez(msg);
	}
}

/* a new stat */
static pdd_stat_t *
pdd_new_stat(osip_message_t *sip, char *from, char *to)
{
	pdd_stat_t *ret = 0;
	ASSERT_TRUE(ret = mallocz(sizeof(pdd_stat_t)), err);
	ASSERT_TRUE(ret->msg_type = strdup(sip->sip_method), err);
	ASSERT_TRUE(ret->from = strdup(from), err);
	ASSERT_TRUE(ret->to = strdup(to), err);
	ret->created = time(0);
	return ret;
 err:
	pdd_free_stat(ret);
	ret = 0;
	return ret;
}

void
ac_packetfilter_stats_remote_event(char *local_aor, char *remote_aor, char *callid, unsigned long time, char *event)
{
	pdd_stat_t *stat;
	LOG_DEBUG("got remote event '%s' for %s => %s at %u\n", event, local_aor, remote_aor, time);
	
	/* find the relevant ones .. */
	ship_lock(stats);
	if ((stat = ship_ht_get_string(stats, callid)) ||
	    (stat = ship_ht_get_string(done_stats_ht, callid))) {
		
		unsigned long *val = 0;
		if (!strcmp(event, "remote_start"))
			val = &stat->remote_start;
		if (!strcmp(event, "remote_end"))
			val = &stat->remote_done;
		
		if (val && !(*val))
			*val = time;
		LOG_DEBUG("stats recorded for call (%s)\n", callid);
	} else {
		LOG_WARN("get stats for unknown call (%s)!\n", callid);
	}
	ship_unlock(stats);
}

void
ac_packetfilter_stats_event(char *local_aor, char *remote_aor, char *event)
{
	unsigned long time = ship_systemtimemillis();
	void *ptr = 0;
	pdd_stat_t *stat;
	LOG_DEBUG("got event '%s' for %s => %s at %u\n", event, local_aor, remote_aor, time);
	
	/* find the relevant ones .. */
	if (!stats || !remote_aor)
		return;

	ship_lock(stats);
	while ((stat = ship_ht_next(stats, &ptr))) {
		if ((!local_aor || !strcmp(stat->from, local_aor)) &&
		    !strcmp(remote_aor, stat->to)) {
			unsigned long *val = 0;
			if (!strcmp(event, "lookup_start"))
				val = &stat->lookup_start;
			if (!strcmp(event, "lookup_end"))
				val = &stat->lookup_done;
			if (!strcmp(event, "conn_start"))
				val = &stat->connect_start;
			if (!strcmp(event, "conn_end"))
				val = &stat->connect_done;
			if (!strcmp(event, "sip_sent"))
				val = &stat->sip_sent;
			
			if (val && !(*val))
				*val = time;
		}
	}
	ship_unlock(stats);
}
#endif

static void
ac_cb_config_update(processor_config_t *config, char *k, char *v)
{
#ifdef DO_STATS
	processor_config_get_bool(config, P2PSHIP_CONF_PDD_RESET_MODE, &pdd_reset_mode);
	processor_config_get_bool(config, P2PSHIP_CONF_PDD_LOG, &pdd_log);
#endif
#ifdef CONFIG_OP_ENABLED
	processor_config_get_enum(config, P2PSHIP_CONF_IDENT_FILTERING, &op_filtering);
#endif
	ASSERT_ZERO(processor_config_get_int(config, P2PSHIP_CONF_AC_MAX_PATH, &max_path), err);
#ifdef AC_HTTP_PF
	freez(http_ac);
	ASSERT_TRUE((http_ac = strdup(processor_config_string(config, P2PSHIP_CONF_AC_HTTP))), err);
#endif
	return;
 err:
	PANIC();
}

static int
ac_stats_handle_message(char *data, int data_len, 
			ident_t *target, char *source, 
			service_type_t service_type)
{
#ifdef DO_STATS
	unsigned int time;
	char *event = 0, *callid = 0;
	char *tmp = 0;

	tmp = mallocz(data_len + 1);
	memcpy(tmp, data, data_len);
	if (tmp && sscanf(tmp, "%u", &time) == 1) {
		if ((event = strchr(tmp, ':'))) {
			event++;
			if ((callid = strchr(event, ':'))) {
				callid[0] = 0;
				callid++;
				ac_packetfilter_stats_remote_event(target->sip_aor, source, callid, time, event);
			}
		}
	}

	if (!callid || !event) {
		LOG_WARN("invalid stats message got: %s\n", data);
	}
	freez(tmp);
#endif
	return 0;
}

static struct service_s ac_stats_service =
{
 	.data_received = ac_stats_handle_message,
	.service_closed = 0,
	.service_handler_id = "ac_stats_service"
};

ship_ht_t *
ac_lists_whitelist()
{
	return white_list;
}

ship_ht_t *
ac_lists_blacklist()
{
	return black_list;
}

static int
_ac_lists_save(ship_ht_t *list, char *filename)
{
	int ret = -1;
	FILE *f = NULL;
	void *ptr = 0;
	char *buf = 0, *tmp = 0;
	int len = 0, size = 0;
	ship_list_t *vals = 0;
	char *name = 0;
	
	ASSERT_TRUE(vals = ship_ht_keys(list), err);
	ASSERT_TRUE((tmp = append_str("# Autogenerated file. Do not edit white proxy is running\n#\n\n", 
				      buf, &size, &len)) && (buf = tmp), err);
	while ((name = ship_list_next(vals, &ptr))) {
		ASSERT_TRUE((tmp = append_str(name, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str("\n", buf, &size, &len)) && (buf = tmp), err);
	}
	ship_list_empty_free(vals);
	ship_list_free(vals);
	
	if (!(f = fopen(filename, "w"))) {
		LOG_ERROR("Could not open file %s\n", filename);
		goto err;
	}
	if (len != fwrite(buf, sizeof(char), len, f))
		goto err;
	
	ret = 0;
 err:
	if (f)
		fclose(f);
	freez(buf);

	/* done always, ignore errors */
	return 0;	
}

/* saves the lists */
void
ac_lists_save()
{
	LOG_DEBUG("Saving white / black lists\n");
	_ac_lists_save(white_list, wl_file);
	_ac_lists_save(black_list, bl_file);
}

static void 
_ac_lists_load_cb(void *data, int lc, char *key, char *value, char *line)
{
	ship_ht_t *list = data;
	trim(line);
	LOG_DEBUG("adding %s to %slist.. \n", line, (list == white_list? "white" : "black"));
	ship_ht_put_string(list, line, (void*)1);	
}

/* loads / saves a white / black list */
static int
ac_lists_load(ship_ht_t *list, char *filename)
{
	int ret = -1;
	ASSERT_ZERO(ship_read_file(filename, list, _ac_lists_load_cb, NULL), err);
	ret = 0;
 err:
	return ret;
}


int
ac_init(processor_config_t *config)
{
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_AC_MAX_PATH, ac_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_AC_HTTP, ac_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_PDD_LOG, ac_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_PDD_RESET_MODE, ac_cb_config_update);

	ac_cb_config_update(config, NULL, NULL);

#ifdef CONFIG_OP_ENABLED
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_IDENT_FILTERING, ac_cb_config_update);
#endif
#ifdef DO_STATS
	ASSERT_TRUE(stats = ship_ht_new(), err);
	ASSERT_TRUE(done_stats = ship_list_new(), err);
	ASSERT_TRUE(done_stats_ht = ship_ht_new(), err);
#endif
	/* whites / blacks */
	ASSERT_TRUE(white_list = ship_ht_new(), err);
	ASSERT_TRUE(black_list = ship_ht_new(), err);

	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_WHITELIST_FILE, &wl_file), err);
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_BLACKLIST_FILE, &bl_file), err);

	ASSERT_ZERO(ac_lists_load(white_list, wl_file), err);
	ASSERT_ZERO(ac_lists_load(black_list, bl_file), err);
	
	ident_register_default_service(SERVICE_TYPE_STATS, &ac_stats_service);
	return 0;
 err:
	return -1;
}

void
ac_close()
{
#ifdef AC_HTTP_PF
	freez(http_ac);
#endif
#ifdef DO_STATS
	if (stats) {
		ship_lock(stats);
		while (ship_list_first(stats)) {
			pdd_free_stat(ship_ht_pop(stats));
		}
		ship_ht_free(stats);
		stats = 0;
	}

	if (done_stats) {
		ship_lock(done_stats);
		while (ship_list_first(done_stats)) {
			pdd_free_stat(ship_list_pop(done_stats));
		}
		ship_list_free(done_stats);
		done_stats = 0;
	}
	ship_ht_free(done_stats_ht);
#endif
	
	if (white_list) {
		ship_ht_free(white_list);
		white_list = 0;
	}

	if (black_list) {
		ship_ht_free(black_list);
		black_list = 0;
	}
}

static void
ac_sip_free(ac_sip_t *asip)
{
	if (asip) {
		freez(asip->local);
		freez(asip->remote);
		freez(asip->to);
		freez(asip->from);
		if (asip->filters) {
			ship_list_free(asip->filters);
		}
		freez(asip);
	}
}

static ac_sip_t*
ac_sip_new(char *local, char *remote, int remotely_got, void *pkg,
	   osip_event_t *evt,
	   void (*func) (char *local_aor, char *remote_aor, void *msg, int verdict))
{	
	ac_sip_t* ret = 0;
	osip_message_t* sip = 0;

	ASSERT_TRUE(ret = mallocz(sizeof(ac_sip_t)), err);
	ret->remotely_got = remotely_got;
	ASSERT_TRUE(ret->evt = evt, err);
	ret->pkg = pkg;
	ASSERT_TRUE(ret->cb_func = func, err);
	ASSERT_TRUE(ret->filters = ship_list_new(), err);
	if (local) {
		ASSERT_TRUE(ret->local = strdup(local), err);
		ASSERT_TRUE(ret->remote = strdup(remote), err);
	}
	
	/* from & to */
	ASSERT_TRUE(sip = evt->sip, err);
	ASSERT_TRUE(sip->to && sip->from, err);
        ASSERT_TRUE(ret->to = sipp_url_to_short_str(sip->to->url), err);
        ASSERT_TRUE(ret->from = sipp_url_to_short_str(sip->from->url), err);
	
        if (MSG_IS_RESPONSE(sip)) {
                char *tmp = ret->to;
                ret->to = ret->from;
                ret->from = tmp;
        }

	ret->verdict = AC_VERDICT_NONE;
	return ret;
 err:
	ac_sip_free(ret);
	return 0;
}

static int
ac_next_packetfilter(ac_sip_t *asip)
{
	void (*func) (ac_sip_t *asip);
	func = ship_list_pop(asip->filters);
	if (func && (asip->verdict == AC_VERDICT_NONE)) {
		func(asip);
		return 0;
	} else {
		/* the 'default' policy */
		if (asip->verdict == AC_VERDICT_NONE)
			asip->verdict = AC_VERDICT_ALLOW;

		asip->cb_func(asip->local, asip->remote, asip->pkg, asip->verdict);
		ac_sip_free(asip);
		return 0;
	}
}

static int 
ac_start_packetfilter_do(void *data, processor_task_t **wait, int wait_for_code)
{
	ac_sip_t *asip = data;
	return ac_next_packetfilter(asip);
}

static void 
ac_start_packetfilter_done(void *data, int code)
{
	ac_sip_t *asip = data;
	if (code) {
		ac_sip_free(asip);
	}
}


static void
ac_start_packetfilter(ac_sip_t *asip, const int filter)
{
	/* create queue of filters */
#ifdef DO_STATS
	ship_list_add(asip->filters, ac_packetfilter_stats);
#endif
	ship_list_add(asip->filters, ac_packetfilter_debug);
	if (filter) {
		ship_list_add(asip->filters, ac_packetfilter_simple);
		ship_list_add(asip->filters, ac_packetfilter_blacklist);
		ship_list_add(asip->filters, ac_packetfilter_whitelist);
		ship_list_add(asip->filters, ac_packetfilter_trust);
#ifdef AC_HTTP_PF
		ship_list_add(asip->filters, ac_packetfilter_http);
#endif
#ifdef CONFIG_OP_ENABLED
		ship_list_add(asip->filters, ac_packetfilter_op);
#endif
	}
	
	/* do this async! */
	processor_tasks_add(ac_start_packetfilter_do, 
			    asip,
			    ac_start_packetfilter_done);	
}

int
ac_packetfilter_remote(char *local_aor, char *remote_aor, osip_event_t *evt, 
		       void (*func) (char *local_aor, char *remote_aor, void *msg, int verdict),
		       const int filter)
{
	ac_sip_t *asip = 0;
	if ((asip = ac_sip_new(local_aor, remote_aor, 1, evt, evt, func))) {
		ac_start_packetfilter(asip, filter);
		return 0;
	} else {
		return -1;
	}
}

int 
ac_packetfilter_local(sipp_request_t *req, 
		      void (*func) (char *local_aor, char *remote_aor, void *msg, int verdict),
		      const int filter)
{
	int ret = -1;
	ac_sip_t *asip = 0;

	if ((asip = ac_sip_new(req->local_aor, req->remote_aor, 0, req, req->evt, func))) {
		ac_start_packetfilter(asip, filter);
		ret = 0;
	}	
	return ret;
}

static void 
ac_packetfilter_debug(ac_sip_t *asip)
{
	if (MSG_IS_RESPONSE(asip->evt->sip)) {
		LOG_INFO("PACKETFILTERING: Got a %d response from %s to %s (channel %s:%s, remotely got: %d)\n", 
			 osip_message_get_status_code(asip->evt->sip),
			 asip->from, asip->to,
			 asip->local, asip->remote, asip->remotely_got);
	} else {
		LOG_INFO("PACKETFILTERING: Got a %s request from %s to %s (channel %s:%s, remotely got: %d)\n", 
			 asip->evt->sip->sip_method,
			 asip->from, asip->to,
			 asip->local, asip->remote, asip->remotely_got);
	}
	ac_next_packetfilter(asip);
}

static void 
ac_packetfilter_trust(ac_sip_t *asip)
{
	osip_message_t* sip = asip->evt->sip;

	LOG_DEBUG("Performing trust ac on %s->%s\n", asip->from, asip->to);

	/* filter only inbound, non-response sessions */
	if (asip->remotely_got && 
	    !MSG_IS_RESPONSE(sip) && 
	    (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip))) {

		/* check max path */
		if (max_path > 0) {
			int pathlen = -1;

			/* the default unless proven otherwise.. */
			asip->verdict = AC_VERDICT_REJECT;
			pathlen = trustman_get_pathlen(asip->from, asip->to);
			
			LOG_DEBUG("Will check params, trust path data: %d, limit: %d\n", pathlen, max_path);
			if ((pathlen > -1) && (pathlen <= max_path)) {
				asip->verdict = AC_VERDICT_NONE;
			} else {
				LOG_DEBUG("No trust parameters got, skipping as we require max %d\n", max_path);
			}
		}
	}
	ac_next_packetfilter(asip);
}

#ifdef CONFIG_OP_ENABLED
static void 
ac_packetfilter_op(ac_sip_t *asip)
{
	osip_message_t* sip = asip->evt->sip;

	LOG_DEBUG("Performing op ac on %s->%s\n", asip->from, asip->to);

	/* filter only inbound, non-response sessions */
	if (asip->remotely_got && 
	    !MSG_IS_RESPONSE(sip) && 
	    (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip))) {
		int is_known = 0;
		char* key = 0;
		reg_package_t *reg = 0;

		/* check identity key */
		if ((reg = ident_find_foreign_reg(asip->from))) {
			key = ident_data_get_pkey_base64(reg->cert);
			if (key) 
				opconn_known(key, &is_known);
			if (is_known)
				LOG_DEBUG("we know the user's key\n");
			freez(key);
			ship_unlock(reg);
		}

		/* check trustman info */
		if (!is_known) {
			key = trustman_op_get_verification_key(asip->from, asip->to);
			if (key)
				opconn_known(key, &is_known);
			if (is_known)
				LOG_DEBUG("we know the verificator of the user's key\n");
			freez(key);
		}
		
		switch (op_filtering) {
		case 0:
			/* block unknown */
			if (!is_known) //is_unknown)
				asip->verdict = AC_VERDICT_REJECT;
			break;
		case 2:
			/* allow known */
			if (is_known)
				asip->verdict = AC_VERDICT_ALLOW;
			break;
		default:
			/* nothing / unknkown */
			break;
		}
	}
	ac_next_packetfilter(asip);
}
#endif

static void 
ac_packetfilter_blacklist(ac_sip_t *asip)
{
	if (asip->remotely_got) {
		/* ..if in blacklist mark as 'reject' */
		if (ship_ht_get_string(black_list, asip->remote))
			asip->verdict = AC_VERDICT_REJECT;
	}
	ac_next_packetfilter(asip);
}

static void 
ac_packetfilter_whitelist(ac_sip_t *asip)
{
	if (asip->remotely_got) {
		/* ..if in whitelist mark as 'allow' */
		if (ship_ht_get_string(white_list, asip->remote))
			asip->verdict = AC_VERDICT_ALLOW;

	}
	ac_next_packetfilter(asip);
}


/* this is a filter that filters messages that have been responded to
   already by a proxy-generated message. Any new requests */

static void 
ac_packetfilter_simple(ac_sip_t *asip)
{
	osip_message_t* sip = asip->evt->sip;
	int code = osip_message_get_status_code(sip);

	LOG_DEBUG("Performing simple ac on %s->%s, remote: %d\n", asip->from, asip->to, asip->remotely_got);
	/* filter only inbound */
	if (asip->remotely_got) {
		
		/* todo: we should check that the sip from == the aor
		   associated with the connection (on remote calls) */

		/* except that that would mess up the gateway things. */

		//ASSERT_ZERO(sipp_get_sip_aors_simple(sip, &local_aor, &remote_aor, 1), end);
		/*
		if ((!MSG_IS_RESPONSE(asip->evt->sip) &&
		     (strcmp(asip->from, asip->remote) || strcmp(asip->to, asip->local))) ||
		    (MSG_IS_RESPONSE(asip->evt->sip) &&
		     (strcmp(asip->to, asip->remote) || strcmp(asip->from, asip->local))))
			asip->verdict = AC_VERDICT_REJECT;
		else 
		*/
		if (MSG_IS_RESPONSE(sip)) {

			/* todo: check if this is for one of this proxy's call
			   ids! */
			TODO("Check if the response is for one of the proxy's messages / invites\n");

			/* reject 482 merges, as server loops aren't of any interest to us */
			if (code == 482) {
				LOG_WARN("Skipping %d response\n", code);
				asip->verdict = AC_VERDICT_REJECT;
			}
		} else if (MSG_IS_ACK(sip) || MSG_IS_BYE(sip) || MSG_IS_CANCEL(sip) || MSG_IS_UPDATE(sip)) {
			
			/* this we should let through pretty much undisturbed */
		
		} else if (MSG_IS_SUBSCRIBE(sip) || MSG_IS_PUBLISH(sip)) {

			/* if this is remotely got, just reject */
			asip->verdict = AC_VERDICT_REJECT;

		} else if (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip)) {
			/* hm, nothing.. */
			// } else if (MSG_IS_NOTIFY(sip)) {
			
		} else {
			/* todo: what about OPTIONS? */
			LOG_WARN("Got unsupported request\n");
			asip->verdict = AC_VERDICT_UNSUPP;
		}
	} else {
		/* allow *all* outgoing! */
		asip->verdict = AC_VERDICT_ALLOW;
	}
	ac_next_packetfilter(asip);
}


#ifdef AC_HTTP_PF
static void 
ac_packetfilter_http_cb(char *url, int respcode, char *data, 
			int datalen, void *pkg)
{
	ac_sip_t *asip = pkg;
	LOG_DEBUG("Got HTTP AC code %d\n", respcode);
	
	/* check the response message */
	if (((respcode/100) == 2) && data && datalen) {
		if (!strncmp(data, "allow", datalen)) {
			asip->verdict = AC_VERDICT_ALLOW;
		} else if (!strncmp(data, "reject", datalen)) {
			asip->verdict = AC_VERDICT_REJECT;
		} else if (!strncmp(data, "drop", datalen)) {
			asip->verdict = AC_VERDICT_DROP;
		} else if (!strncmp(data, "ignore", datalen)) {
			asip->verdict = AC_VERDICT_IGNORE;
		} else if (!strncmp(data, "unsupp", datalen)) {
			asip->verdict = AC_VERDICT_UNSUPP;
		} else if (!strncmp(data, "none", datalen)) {
			/* we do nothing.. */
		}
	}

	ac_next_packetfilter(asip);
}

/* currently not used, unstatified to supress compiler warning .. */
static void 
ac_packetfilter_http(ac_sip_t *asip)
{
	char *data = 0, *tmp = 0;
	int pathlen = -1;
	int len = 0, size = 0;
	char buf[32];

	if (!http_ac || !strlen(http_ac))
		goto err;
	
	LOG_DEBUG("Performing http ac on %s->%s\n", asip->from, asip->to);
	pathlen = trustman_get_pathlen(asip->from, asip->to);
	sprintf(buf, "%d", pathlen);

	/* create a nice post param packet from this */
	ASSERT_TRUE((tmp = ship_addparam_urlencode("p2pship_ver", "1", data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("from", asip->from, data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("to", asip->to, data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("type", (asip->evt->sip->sip_method?asip->evt->sip->sip_method:""), 
						   data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("response", (MSG_IS_RESPONSE(asip->evt->sip)? "yes":"no"), 
						   data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("local", (asip->local?asip->local:""), data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("remote", (asip->remote?asip->remote:""), data, &size, &len)) && (data = tmp), err);
	ASSERT_TRUE((tmp = ship_addparam_urlencode("pathlen", buf, data, &size, &len)) && (data = tmp), err);
	
	if (!netio_http_post_host(http_ac,
				  "/validate", "",
				  "application/x-www-form-urlencoded", 
				  data, len, ac_packetfilter_http_cb, asip)) {
		asip = 0;
	}
 err:
	freez(data);
	if (asip)
		ac_next_packetfilter(asip);
}
#endif


/* measures some stats related to the call setup times etc */
#ifdef DO_STATS
static void 
ac_packetfilter_stats(ac_sip_t *asip)
{
	osip_message_t* sip = asip->evt->sip;
	char *callid = 0;
	unsigned long now = ship_systemtimemillis();

	if (asip->remotely_got) {
		/* .. meaning remotely got */
		if (MSG_IS_RESPONSE(sip)) {
			pdd_stat_t *stat = 0;
			int code = osip_message_get_status_code(sip);
			
			/* check for ACK with code != 100 */
			callid = sipp_get_call_id(sip);
			ship_lock(stats) ;
			if (code != 100 && 
			    (stat = ship_ht_get_string(stats, callid)) &&
			    !stat->end) {
				
				stat->end = ship_systemtimemillis();
				LOG_INFO("Got PDD for %s %s -> %s (status %d) in %u.%03u seconds..\n",
					 stat->msg_type, stat->from, stat->to, code, 
					 (stat->end - stat->start) / 1000, 	
					 ((stat->end - stat->start) % 1000));

				/* ... if we are recording special, then do that! */
				if (pdd_log) {
					pdd_record_pdd(stat);
				}

				/* remove.. ? */
				ship_ht_remove_string(stats, callid);

				ship_lock(done_stats);
				while (ship_list_length(done_stats) > 20) {
					pdd_stat_t *s2 = ship_list_pop(done_stats);
					ship_ht_remove(done_stats_ht, s2);
					pdd_free_stat(s2);
				}
				ship_list_add(done_stats, stat);
				ship_ht_put_string(done_stats_ht, callid, stat);
				ship_unlock(done_stats);
			}
			ship_unlock(stats);
		} else if (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip)) {
			/* record the pdd for the other fellow .. */
			callid = sipp_get_call_id(sip);
			
			/* send 'stats' packet back, event remote_req */
			ac_send_stats(asip->remote, asip->local,
				      now, callid, "remote_start");
		}
	} else {
		/* if we get an invite or something like that, record the time .. and so on */
		if (MSG_IS_INVITE(sip) || MSG_IS_MESSAGE(sip)) {

			/* if not seen already & pdd mode, do some
			   funky stuff.. */
			if (pdd_reset_mode) {
				LOG_INFO("pdd measurement mode: clearing SAs and peer DB!\n");
#ifdef CONFIG_HIP_ENABLED
				hipapi_clear_sas();
#endif
				ident_reset_foreign_regs();
				conn_close_all();
			}

			callid = sipp_get_call_id(sip);
			ship_lock(stats);
			if (!ship_ht_get_string(stats, callid)) {
				pdd_stat_t *stat = pdd_new_stat(sip, asip->from, asip->to);
				if (stat) {
					stat->start = ship_systemtimemillis();
					ship_ht_put_string(stats, callid, stat);
				}
			}
			ship_unlock(stats);
		} else if (MSG_IS_RESPONSE(sip)) {
			int code = osip_message_get_status_code(sip);
			if (code != 100) {
				callid = sipp_get_call_id(sip);

				/* send 'stats' packet back, event remote_resp */
				ac_send_stats(asip->remote, asip->local,
					      now, callid, "remote_end");
			}
		}
	}
	
	freez(callid);
	ac_next_packetfilter(asip);
}

int 
ac_send_stats(char *remote, char *local,
	      unsigned long time, char *callid, char *event)
{
	char *buf = mallocz(strlen(callid) + strlen(event) + 64);
	if (buf) {
		LOG_DEBUG("sending remote stat %s\n", event);
		sprintf(buf, "%u:%s:%s", (unsigned int)time, event, callid);
		conn_send_simple(remote, local,
				 SERVICE_TYPE_STATS,
				 buf, strlen(buf));
		freez(buf);
	}
	return 0;
}

static int 
pdd_record_pdd(pdd_stat_t *stat)
{
	char *tmp = 0, *filename = 0;
	int ret = -1;
	FILE *f = NULL;
	
	int total = stat->end - stat->start, 
		lookup = stat->lookup_done - stat->lookup_start, 
		connect = stat->connect_done - stat->connect_start,
		auth = (stat->connect_done? stat->sip_sent - stat->connect_done : 0),
		remote = stat->remote_done - stat->remote_start;
	
	/* create the file name .. */
	ASSERT_ZERO(ship_get_homedir_file(PDD_LOG_FILE, &filename), err);
	ASSERT_ZERO(ship_ensure_file(filename, 
				     "From, To, Message type, Dot, Total, Lookup, Connect, Auth, Remote, Misc\n"),
		    err);

	ASSERT_TRUE(tmp = mallocz(strlen(stat->from) + strlen(stat->to) + strlen(stat->msg_type) + 128), err);
	sprintf(tmp, "%s, %s, %s, %d, %u, %u, %u, %u, %u, %u\n",
		stat->from, stat->to, stat->msg_type, (int)stat->created, 
		total, lookup, connect, auth, remote,
		(int)(total - lookup - connect - auth - remote));
	
	if ((f = fopen(filename, "a"))) {
		fwrite(tmp, sizeof(char), strlen(tmp), f);
		fclose(f);
	}
	
	LOG_INFO("recorded PDD into csv file %s..\n", filename);
	ret = 0;
 err:
	if (ret) {
		LOG_ERROR("could not record PDD: %d\n", ret);
	}

	freez(tmp);
	freez(filename);
	return ret;
}

/* dumps the current stats to json format .. */
void
stats_dump_json(char **str)
{
	void *ptr = 0;
	char *buf = 0;
	int buflen = 0, datalen = 0;
	char *tmp = 0;
	pdd_stat_t *stat = 0;
	
	ship_lock(done_stats);
	ASSERT_TRUE(buf = append_str("var p2pship_pdds = [\n", buf, &buflen, &datalen), err);
	while ((stat = ship_list_next(done_stats, &ptr))) {
		int len = strlen(stat->from) + strlen(stat->to) + strlen(stat->msg_type) + 128;
		
		ASSERT_TRUE(tmp = mallocz(len), err);
		sprintf(tmp, " [ \"%s\", \"%s\", \"%s\", \"%d\", \"%u\", \"%u\", \"%u\", \"%u\", \"%u\" ],\n",
			stat->from, stat->to, stat->msg_type, (int)stat->created, 
			(unsigned int)(stat->end - stat->start), (unsigned int)(stat->lookup_done - stat->lookup_start), 
			(unsigned int)(stat->connect_done - stat->connect_start),
			(unsigned int)(stat->connect_done? stat->sip_sent - stat->connect_done : 0),
			(unsigned int)(stat->remote_done - stat->remote_start));
		ASSERT_TRUE(buf = append_str(tmp, buf, &buflen, &datalen), err);
		freez(tmp);
	}
	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("];\n", buf, &buflen, &datalen), err);
	*str = buf;
	buf = 0;
 err:
	ship_unlock(done_stats);
	freez(buf);
	freez(tmp);
}
#endif
