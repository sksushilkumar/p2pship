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
#include "ship_utils.h"
#include "processor_config.h"
#include "ship_debug.h"
#include "ident.h"

static void 
sipp_buddy_pf_cb(char *url, int respcode, char *data, int data_len, void *pkg)
{
	LOG_DEBUG("Got buddylist submit callback code %d\n", respcode);
}

/* called to re-update the buddy list to the pathfinder */
static int
sipp_buddy_perform_buddylist_update(ident_t *from)
{
	char *postdata = 0, *tmp = 0;
	int len = 0, size = 0;
	int ret = -1;
	char buf[128];
	time_t exp, now;
	char *xml = 0;
	buddy_t* buddy = 0;
	void *ptr = 0;
	char *x = 0, *x2 = 0;
	
	/* construct the xml package of all still-valid subscribes */
	time(&now);
	exp = now;

	while (buddy = ship_list_next(from->buddy_list, &ptr)) {
		int valid = buddy->created + buddy->expire;
		if (valid > now) {
			ASSERT_TRUE((x = append_str("<buddy><hash>", xml, &size, &len)) &&
				    (xml = x), berr);
			ASSERT_TRUE(x2 = ship_hash_sha1_base64(buddy->sip_aor, strlen(buddy->sip_aor)), berr);
			ASSERT_TRUE((x = append_str(x2, xml, &size, &len)) &&
				    (xml = x), berr);
			freez(x2);
			ASSERT_TRUE((x = append_str("</hash></buddy>", xml, &size, &len)) &&
				    (xml = x), berr);
			if (valid < exp || exp == now)
				exp = valid;
		}
	}
 berr:
	freez(x2);
	if (!x)
		freez(xml);
	
	if (!xml) {
		ASSERT_TRUE(xml = strdup(""), err);
	}
	
	/* construct complete xml - timestamps */
	len = 0; size = 0;
	ASSERT_TRUE((tmp = append_str("<buddylistdoc><payload><![CDATA[<load><timestamp>", postdata, &size, &len)) &&
		    (postdata = tmp), err);
	ship_format_time(now, buf, sizeof(buf));
	ASSERT_TRUE((tmp = append_str(buf, postdata, &size, &len)) &&
		    (postdata = tmp), err);
	ASSERT_TRUE((tmp = append_str("</timestamp><expires>", postdata, &size, &len)) &&
		    (postdata = tmp), err);
	ship_format_time(exp, buf, sizeof(buf));
	ASSERT_TRUE((tmp = append_str(buf, postdata, &size, &len)) &&
		    (postdata = tmp), err);

	/* self hash */
	ASSERT_TRUE((tmp = append_str("</expires><self><hash>", postdata, &size, &len)) &&
		    (postdata = tmp), err);
	
	ASSERT_TRUE(x2 = ship_hash_sha1_base64(from->sip_aor, strlen(from->sip_aor)), err);
	ASSERT_TRUE((tmp = append_str(x2, postdata, &size, &len)) &&
		    (postdata = tmp), err);
	freez(x2);

	/* buddies */
	ASSERT_TRUE((tmp = append_str("</hash><cert></cert></self><buddies>", postdata, &size, &len)) &&
		    (postdata = tmp), err);
	ASSERT_TRUE((tmp = append_str(xml, postdata, &size, &len)) &&
		    (postdata = tmp), err);
	ASSERT_TRUE((tmp = append_str("</buddies></load>]]></payload><signature /></buddylistdoc>", postdata, &size, &len)) &&
		    (postdata = tmp), err);
	freez(xml);
	xml = postdata;

	/* url-encode & post */
	len = 0; size = 0;
	postdata = 0;
	x2 = ship_urlencode(xml);
	ASSERT_TRUE((tmp = append_str("submission.xml=", postdata, &size, &len)) && (postdata = tmp), err);
	ASSERT_TRUE((tmp = append_str(x2, postdata, &size, &len)) && (postdata = tmp), err);
	
	ret = netio_http_post_host(trustman_get_pathfinder(),
				   "/postbuddylist",
				   "",
				   "application/x-www-form-urlencoded",
				   postdata, strlen(postdata),
				   sipp_buddy_pf_cb, NULL);
 err:
	freez(x2);
	freez(xml);
	freez(postdata);
	return ret;
}

/* called when a new subscribe has been issued by a local AOR */
static int
__sipp_buddy_handle_subscribe(ident_t *from, char *to, int expire, char *callid)
{
	buddy_t* buddy = 0;
	void *ptr = 0;
	time_t now;
	
	LOG_DEBUG("Got subscribe for %s from %s, exp %d, callid %s\n",
		  to, from->sip_aor, expire, callid);
	
	ASSERT_TRUE(buddy = ident_buddy_find_or_create(from, to), err);
	time(&now);
	buddy->created = now;
	buddy->expire = expire;	
	return 0;
 err:
	return -1;
}

/* called when a new subscribe has been issued by a local AOR */
int
sipp_buddy_handle_subscribe(ident_t *from, char *to, int expire, char *callid)
{
	int ret = __sipp_buddy_handle_subscribe(from, to, expire, callid);
	processor_run_async(ident_save_identities);
	if (!ret)
		return sipp_buddy_perform_buddylist_update(from);
	return ret;
}

/* called when we have a complete list of buddies we want to subscribe
   to. Clears all old ones. */
int
sipp_buddy_handle_subscribes(ident_t *from, char **to, int expire, char *callid)
{
	int i = 0, ret = 0;
	buddy_t* buddy = 0;
	void *ptr = 0, *last = 0;
	
	/* clear all old regs */
	while (buddy = ship_list_next(from->buddy_list, &ptr)) {
		buddy->expire = -1;
	}
		
	/* do new ones */
	while (!ret && to[i]) {
		ret = __sipp_buddy_handle_subscribe(from, to[i++], expire, callid);
	}
	
	processor_run_async(ident_save_identities);

	if (!ret)
		return sipp_buddy_perform_buddylist_update(from);
	return ret;
}


