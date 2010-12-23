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
#include <stdlib.h>
#include <stdio.h>

#include <glib.h>
#include <libosso.h>
#include <mcd-manager.h>
#include <libmissioncontrol/mc-profile.h>

#include "ship_utils.h"
#undef LOG_DEBUG
#undef LOG_INFO
#include "ship_debug.h"

char *
mc_get_account_name(char *aor)
{
	GList *alist = 0, *l;
	gchar* acc_name = 0;
	char *ret = 0;
	
	alist = mc_accounts_list();
	for (l=alist; !ret && l; l = g_list_next(l)) {
		McAccount *acc = l->data;
		
		mc_account_get_param_string(acc, "account", &acc_name);
		if (!acc_name)
			continue;
		if (!strcmp(acc_name, aor))
			ret = strdup(mc_account_get_display_name(acc));
		g_free(acc_name);
	}

	if (alist)
		mc_accounts_list_free(alist);
	return ret;
}

int
mc_create_contact(char *display, char *aor, int update, int enable)
{
	GList *alist = 0, *plist = 0, *l;
	McAccount *acc = 0, *uacc = 0;
	McProfile *prof = 0;
	int ret = -1;
	
	/* first - try to find a profile that matches this one
	   (account name) */
	alist = mc_accounts_list();
	for (l=alist; update && !acc && l; l = g_list_next(l)) {
		gchar* acc_name = 0;
		acc = l->data;
		
		mc_account_get_param_string(acc, "account", &acc_name);
		if (!acc_name || strcmp(acc_name, aor))
			acc = 0;
		if (acc_name)
			g_free(acc_name);
	}

	/* find the profile for us - p2psip or sip? */
	if (!acc) {
		plist = mc_profiles_list();
		for (l=plist; l; l = g_list_next(l)) {
			McProfile *tp = l->data;
			if (!prof && !strcmp(mc_profile_get_unique_name(tp), "sip"))
				prof = tp;
			else if (!strcmp(mc_profile_get_unique_name(tp), "p2psip"))
				prof = tp;
		}
		
		ASSERT_TRUE(prof, err);
		ASSERT_TRUE(uacc = mc_account_create(prof), err);
		acc = uacc;
		mc_account_set_display_name(acc, display);
	}

	ASSERT_TRUE(mc_account_set_param_string(acc, "discover-binding", "true"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "transport", "udp"), err);
	ASSERT_TRUE(mc_account_set_param_int(acc, "keepalive-interval", 0), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "stun-port", "3478"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "discover-stun", "true"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "proxy-host", "localhost"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "account", aor), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "keepalive-mechanism", "off"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "password", "none"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "port", "1234"), err);
	ASSERT_TRUE(mc_account_set_param_string(acc, "avoid-difficult", "false"), err);

	mc_account_set_enabled(acc, enable);
	ret = 0;
 err:
	if (alist)
		mc_accounts_list_free(alist);
	if (plist)
		mc_profiles_free_list(plist);
	if (uacc)
		g_object_unref(uacc);
	return ret;
}

