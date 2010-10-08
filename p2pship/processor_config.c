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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "processor_config.h"
#include "ship_utils.h"
#include "ship_debug.h"
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>

/* the default values for all the configs */
static char* DEFAULT_CONFIGURATION[] =
 	{
 		P2PSHIP_CONF_DAEMON, "no", "Daemon mode", "static_bool", 0,
		P2PSHIP_CONF_WORKER_THREADS, "3", "Number of worker threads", "static_int", 0,
		P2PSHIP_CONF_SHIP_PORT, "5566", "The initial SHIP protocol port to try", "int", 0,
		P2PSHIP_CONF_SHIP_PORT_RANGE, "20", "The range (forward) or ship ports to try if first fails", "int", 0,
		P2PSHIP_CONF_IFACES, "ext", "Public SHIP interface to advertise", "string", 0,

		P2PSHIP_CONF_OL_SECRET, "", "Overlay key secret", "string", 0,

		P2PSHIP_CONF_IDENT_ALLOW_UNKNOWN_REGISTRATIONS, "no", "Allow unknown registrations", "bool", 0,
		P2PSHIP_CONF_IDENT_ALLOW_UNTRUSTED, "no", "Allow untrusted peers", "bool", 0,
		P2PSHIP_CONF_IDENT_REQUIRE_AUTHENTICATION, "no", "Require SIP UA authentication", "bool", 0,
		P2PSHIP_CONF_IDENT_IGNORE_CERT_VALIDITY, "yes", "Ignore the validity of peer certificates", "bool", 0,
		P2PSHIP_CONF_IDENT_RENEGOTIATE_SECRET, "no", "Re-negotiate shared secret on each contact", "bool", 0,

#ifdef CONFIG_PYTHON_ENABLED
		P2PSHIP_CONF_START_SHELL, "no", "Start Python shell on stdin", "bool", 0,
		P2PSHIP_CONF_RUN_SCRIPT, "", "Run a script at startup", "string", 0,
#endif

#ifdef CONFIG_SIP_ENABLED
		P2PSHIP_CONF_SIPP_PROXY_IFACES, "lo", "SIP proxy interface", "string", 0,
		P2PSHIP_CONF_SIPP_PROXY_PORT, "1234", "SIP proxy port", "int", 0,
		P2PSHIP_CONF_SIPP_MEDIA_PROXY, "yes", "Enable media proxy", "bool", 0,
		P2PSHIP_CONF_SIPP_MEDIA_PROXY_MOBILITY_SUPPORT, "yes", "Enable media proxy mobility hack", "bool", 0,
		P2PSHIP_CONF_SIPP_FORCE_PROXY, "yes", "Force use of media proxy", "bool", 0,
		P2PSHIP_CONF_SIPP_TUNNEL_PROXY, "no", "Tunnel media proxy traffic", "bool", 0,

		P2PSHIP_CONF_CALL_LOG_SHOW_PATHINFO, "yes", "Show trustpath for accepted calls", "bool", 0,
		P2PSHIP_CONF_CALL_LOG_SHOW_DROPPED, "yes", "Show dropped calls", "bool", 0,

		P2PSHIP_CONF_PDD_RESET_MODE, "no", "Reset peer connections before each call", "bool", 0,
		P2PSHIP_CONF_PDD_LOG, "no", "Log PDD data to separate file", "bool", 0,
#endif
		
		P2PSHIP_CONF_IDENT_UA_MODE, "open", "UA mode", "enum:open,relax,paranoid", 0,
		P2PSHIP_CONF_CONN_KEEPALIVE, "30", "Keepalive interval in seconds", "int", 0,

#ifdef CONFIG_BROADCAST_ENABLED
		P2PSHIP_CONF_BC_ADDR, "239.254.254.200:1902", "Broadcast address", "string", 0,
		P2PSHIP_CONF_BC_IFACES, "ext", "Broadcast interfaces", "string", 0,
#endif

#ifdef CONFIG_OPENDHT_ENABLED
		P2PSHIP_CONF_OPENDHT_PROXY, "192.38.109.143:5851", "OpenDHT proxy to use", "string", 0,
#endif

#ifdef CONFIG_P2PEXT_ENABLED
		P2PSHIP_CONF_P2PEXT_PROXY, "p2pext.appspot.com", "P2PSHIP EXT proxy to use", "string", 0,
#endif

#ifdef CONFIG_HIP_ENABLED
		P2PSHIP_CONF_PROVIDE_RVS, "no", "Provide RVS for others", "bool", 0,
		P2PSHIP_CONF_NAT_TRAVERSAL, "plain", "NAT traversal", "enum:none,plain,ice", 0,
		//P2PSHIP_CONF_RVS, "crossroads.infrahip.net", "RVS to use", "string", 0,
		P2PSHIP_CONF_RVS, "", "RVS to use", "string", 0,

		P2PSHIP_CONF_HIP_SHUTDOWN, "/bin/sh /etc/init.d/hipd-initd restart", "hipd shutdown command", "string", 0,

		P2PSHIP_CONF_ALLOW_NONHIP, "yes", "Allow non-hip control & data connections", "bool", 0,
#endif

#ifdef CONFIG_WEBCONF_ENABLED
		P2PSHIP_CONF_WEBCONF_SS, "127.0.0.1:9080", "The webconf interface address", "string", 0,
#endif

#ifdef CONFIG_EXTAPI_ENABLED
		P2PSHIP_CONF_EXTAPI_SS, "127.0.0.1:9081", "The ext interface address", "string", 0,

#ifdef CONFIG_HTTPPROXY_ENABLED
		P2PSHIP_CONF_HTTPPROXY_ADDR, "127.0.0.1:9090", "The HTTP client proxy address", "string", 0,
		P2PSHIP_CONF_HTTPPROXY_REVEAL_ORIGINAL, "yes", "Reveal original HTTP url when making proxy requests", "bool", 0,
#endif
#endif

#ifdef CONFIG_WEBCACHE_ENABLED
		P2PSHIP_CONF_WEBCACHE_FILELIMIT, "2097152", "Webcache file size limit", "int", 0,
		P2PSHIP_CONF_WEBCACHE_LIMIT, "20971520", "Webcache disk usage limit", "int", 0,
		P2PSHIP_CONF_WEBCACHE_STRICTNESS, "all", "Webcache strictness", "enum:all,relaxed,strict", 0,
		P2PSHIP_CONF_WEBCACHE_USE_P2P_LOOKUP, "yes", "Use P2P webcache lookups", "bool", 0,
#endif
		
		P2PSHIP_CONF_USE_PATHFINDER, "no", "Use the pathfinder", "bool", 0,
		P2PSHIP_CONF_PATHFINDER, "193.167.187.22:7372", "The pathfinder", "string", 0,
		P2PSHIP_CONF_AC_HTTP, "localhost:9292", "The HTTP access control module", "string", 0,
		P2PSHIP_CONF_AC_MAX_PATH, "0", "Max path length allowed for incoming requests", "int", 0,
#ifdef REMOTE_DEBUG
		P2PSHIP_CONF_REMOTE_DEBUG, "193.167.187.92:9876", "The remote debug monitor", "string", 0,
#endif
		0, 0, 0, 0, 0
 	};

#if 0
static char* DEFAULT_FILES[] =
 	{
		
		0, 0, 0, 0, 0
	};
#endif

/* these should be autogenerated in config.h */
#define DEFAULT_CONF_FILE ".p2pship/settings.conf"
#define DEFAULT_IDENT_FILE ".p2pship/identities.xml"
#define DEFAULT_AUTOREG_FILE ".p2pship/autoreg"
#define DEFAULT_WEB_DIR ".p2pship/web"
#define DEFAULT_LOG_FILE ".p2pship/log"
#define DEFAULT_WEBCACHE_INDEX ".p2pship/webcache/index.txt"
#ifdef CONFIG_SIP_ENABLED
#define DEFAULT_SIPP_ROUTING_FILE ".p2pship/sip-routing.xml"
#endif
#define DEFAULT_DATA_DIR ".p2pship/data"

#define DEFAULT_CONTACTS_FILE ".p2pship/contacts.log"

/* the white / blacklists */
#define DEFAULT_BLACKLIST_FILE ".p2pship/blacklist"
#define DEFAULT_WHITELIST_FILE ".p2pship/whitelist"

#ifdef CONFIG_PYTHON_ENABLED
#define DEFAULT_PYTHON_LIB_DIR ".p2pship/apps/lib"
#define DEFAULT_PYTHON_SCRIPTS_DIR ".p2pship/apps/scripts"
#define DEFAULT_PYTHON_INSTANCES_DIR ".p2pship/apps/instances"
#define DEFAULT_PYTHON_PACKAGES_DIR ".p2pship/apps/packages"

/*
/apps/lib
/apps/scripts

/apps/instances
/apps/instances/0xd0304340/data
/apps/instances/0xd0304340/app.db
/apps/instances/0xd0304340/instance.nfo
/apps/instances/0xd0304340/src

/apps/packages/0xf434343/data
/apps/packages/0xf434343/app.nfo
/apps/packages/0xf434343/src
*/
#endif

/* the dynamic config .. ? */
static ship_ht_t *processor_config_dynamic = NULL;

/* inits the dynamic config */
int
processor_config_init()
{
	int ret = -1;
	ASSERT_TRUE(processor_config_dynamic = ship_ht_new(), err);
	ret = 0;
 err:
	return ret;
}

void
processor_config_close()
{
	char **ptr = 0;
	if (processor_config_dynamic) {
		while ((ptr = (char**)ship_ht_pop(processor_config_dynamic))) {
			freez_arr(ptr, 4);
		}
		ship_ht_free(processor_config_dynamic);
		processor_config_dynamic = NULL;
	}
}


/* adds a configuration type to the stack */
int
processor_config_create_key(processor_config_t *config, const char *key, const char *description,
			    const char *type, const char *value)
{
	int ret = -1;
	char **arr = NULL;

	ASSERT_TRUE(processor_config_dynamic && config, err);
	ASSERT_TRUE(arr = mallocz(sizeof(char*) * 5), err);
	ASSERT_TRUE(arr[0] = strdup(key), err);
	ASSERT_TRUE(arr[1] = strdup(value), err);
	ASSERT_TRUE(arr[2] = strdup(description), err);
	ASSERT_TRUE(arr[3] = strdup(type), err);
	ship_ht_put_string(processor_config_dynamic, key, arr);
	if (!processor_config_string(config, key)) {
		ASSERT_ZERO(processor_config_set_string(config, key, value), err);
	}
	ret = 0;
	arr = 0;
 err:
	freez_arr(arr, 4);
	return ret;
}

/* returns all the config keys. ownership kept! */
int
processor_config_get_keys(ship_list_t *list)
{
	char **arr = DEFAULT_CONFIGURATION;
	while (*arr) {
		ship_list_add(list, *arr);
		arr += 5;
	}
	if (processor_config_dynamic)
		ship_ht_keys_add(processor_config_dynamic, list);
	return 0;
}

/* checks that the given string is a valid config key */
static inline char **
processor_config_get_default(const char *key)
{
	char **arr = DEFAULT_CONFIGURATION;
	while (*arr) {
		if (!strcmp(*arr, key))
			return arr;
		arr += 5;
	}
	if (processor_config_dynamic)
		return ship_ht_get_string(processor_config_dynamic, key);
	return 0;
}

/* checks that the given string is a valid config key */
int
processor_config_is_valid_key(char *key)
{
	if (processor_config_get_default(key))
		return 1;
	else
		return 0;
}

/* gets the default value for some key */
/*
static char *
processor_config_get_default_val(processor_config_t *config, 
				 char *key)
{
	char **arr = processor_config_get_default(key);
	if (!arr)
		return NULL;
	return arr[1];
}
*/

/* marks a config value as dynamic (even though no callback) */
void
processor_config_set_dynamic(processor_config_t *config, const char *key)
{
	char **arr = processor_config_get_default(key);
	if (arr)
		arr[4] = (void*)-1;
}

/* sets a callback for dynamic config updates */
int
processor_config_set_dynamic_update(processor_config_t *config, 
				    const char *key, void (*func) (processor_config_t *c, char *k, char *v))
{
	/* hm.. these should be config-specific, but.. */
	char **arr = processor_config_get_default(key);
	if (!arr)
		return -1;
	arr[4] = (char*)func;
	return 0;
}

/* update dynamically some var */
int
processor_config_dynamic_update(processor_config_t *config, 
				char *key, char *value)
{
	char **arr;
	char *val;
	
	arr = processor_config_get_default(key);
	if (!arr) {
		LOG_WARN("Dynamic update for an unknown key: %s. Ignoring!\n", key);
		return -1;
	}

	val = processor_config_string(config, key);
	if (!val || strcmp(val, value)) {
		LOG_INFO("Dynamic update %s from %s to %s\n", key, val, value);
		processor_config_set_string(config, key, value);
		if (arr[4]) {
			if (arr[4] != (void*)-1) {
				void *tmp = arr[4];
				void (*cbfunc) (processor_config_t *c, char *k, char *v) = tmp;
				cbfunc(config, key, value);
			}
		} else {
			LOG_WARN("Dynamic update might not have been activated!\n");
		}
	}
	return 0;
}

/*
void 
processor_config_dump(processor_config_t *config, char *msg)
{
	processor_config_item_t *item;
	void *ptr = 0;
	USER_PRINT("\ndumping config %s\n", msg);
	while (item = ship_list_next(config, &ptr)) {
		USER_PRINT("\tdump %s -> %s..\n", item->key, item->value);
	}	
}
*/

void 
processor_config_dump_json(processor_config_t *config, char **msg)
{
	char *buf = 0, *key;
	int buflen = 0, datalen = 0;
	ship_list_t *list = 0;
	
	ASSERT_TRUE(list = ship_list_new(), err);
	ASSERT_ZERO(processor_config_get_keys(list), err);
	
	ASSERT_TRUE(buf = append_str("var p2pship_config = {\n", buf, &buflen, &datalen), err);
	while ((key = ship_list_pop(list))) {
		char **def = processor_config_get_default(key);
		char *value = 0;
		if (!def) continue;
		
		value = processor_config_string(config, key);
		ASSERT_TRUE(buf = append_str("     \"", buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str(key, buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str("\" : [ \"", buf, &buflen, &datalen), err);
		if (value) {
			ASSERT_TRUE(buf = append_str(value, buf, &buflen, &datalen), err);
		}
		ASSERT_TRUE(buf = append_str("\", \"", buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str(def[2], buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str("\", \"", buf, &buflen, &datalen), err);
		ASSERT_TRUE(buf = append_str(def[3], buf, &buflen, &datalen), err);
		if (def[4]) {
			ASSERT_TRUE(buf = append_str("\", \"static\" ],\n", buf, &buflen, &datalen), err);
		} else {
			ASSERT_TRUE(buf = append_str("\", \"dynamic\" ],\n", buf, &buflen, &datalen), err);
		}
	}
	ASSERT_TRUE(replace_end(buf, &buflen, &datalen, ",\n", "\n"), err);
	ASSERT_TRUE(buf = append_str("};\n", buf, &buflen, &datalen), err);
	*msg = buf;
	buf = 0;
 err:
	ship_list_free(list);
	freez(buf);
}

int
processor_config_transfer(processor_config_t *target, processor_config_t *source)
{
	processor_config_item_t *item;
	void *ptr = 0;
	while ((item = ship_list_next(source, &ptr))) {
		if (processor_config_set_string(target, item->key, item->value))
			return -1;
	}	
	return 0;
}

/* small func to check & ensure that a file exists */
static int
processor_config_check_ensure_homedir_file(char *filename, char *conf_name, 
					   char *default_content, processor_config_t *config)
{
	char *tmpstr = 0;
	int ret = -1;
	
	ASSERT_ZERO(ship_get_homedir_file(filename, &tmpstr), err);
	ASSERT_ZERO(processor_config_set_string(config, conf_name, tmpstr), err);
	if (default_content)
		ship_ensure_file(tmpstr, default_content);
	else
		ship_ensure_dir(tmpstr);
	ret = 0;
 err:
	freez(tmpstr);
	return ret;
}


int
processor_config_load_defaults(processor_config_t *config)
{
	char *tmpstr = 0;
	int ret = -1;
	char **arr = 0;

	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_IDENT_FILE, P2PSHIP_CONF_IDENTS_FILE, 
							       "<p2pship-ident>\n  <identities />\n  <trusted-ca />\n</p2pship-ident>\n", config), err);
	
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_CONF_FILE, P2PSHIP_CONF_CONF_FILE, 
							       "# settings file for p2pship\n#\n\n", config), err);

	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_AUTOREG_FILE, P2PSHIP_CONF_AUTOREG_FILE, 
							       "", config), err);
	
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_LOG_FILE, P2PSHIP_CONF_LOG_FILE, 
							       "", config), err);
	
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_CONTACTS_FILE, P2PSHIP_CONF_CONTACTS_FILE, 
							       "", config), err);

	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_WHITELIST_FILE, P2PSHIP_CONF_WHITELIST_FILE, 
							       "# The whitelist for P2PSHIP\n# Please don't edit white the proxy is running!\n#\n\n", config), err);
	
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_BLACKLIST_FILE, P2PSHIP_CONF_BLACKLIST_FILE, 
							       "# The blacklist for P2PSHIP\n# Please don't edit white the proxy is running!\n#\n\n", config), err);
	
#ifdef CONFIG_SIP_ENABLED
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_SIPP_ROUTING_FILE, P2PSHIP_CONF_SIPP_ROUTING_FILE, 
							       "<sip-routing />\n", config), err);
#endif
	ASSERT_ZERO(ship_get_homedir_file(DEFAULT_WEB_DIR, &tmpstr), err);
	ASSERT_ZERO(processor_config_set_string(config, P2PSHIP_CONF_WEB_DIR, tmpstr), err);

	/* the default listings file */
#ifdef CONFIG_WEBCACHE_ENABLED
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_WEBCACHE_INDEX, P2PSHIP_CONF_WEBCACHE_INDEX, 
							       "# The web cache index file\n#\n\n", config), err);
#endif

	/* create the dynamic config here.... ? */
	
	arr = DEFAULT_CONFIGURATION;
	while (*arr) {
		char *key = *(arr++);
		char *value = *(arr++);
		ASSERT_ZERO(processor_config_set_string(config, key, value), err);
		arr += 3;
	}

	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_DATA_DIR, P2PSHIP_CONF_DATA_DIR,
							       NULL, config), err);

#ifdef CONFIG_PYTHON_ENABLED
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_PYTHON_LIB_DIR, P2PSHIP_CONF_PYTHON_LIB_DIR,
							       NULL, config), err);
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_PYTHON_SCRIPTS_DIR, P2PSHIP_CONF_PYTHON_SCRIPTS_DIR,
							       NULL, config), err);
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_PYTHON_INSTANCES_DIR, P2PSHIP_CONF_PYTHON_INSTANCES_DIR,
							       NULL, config), err);
	ASSERT_ZERO(processor_config_check_ensure_homedir_file(DEFAULT_PYTHON_PACKAGES_DIR, P2PSHIP_CONF_PYTHON_PACKAGES_DIR,
							       NULL, config), err);
#endif
	ret = 0;
 err:
	freez(tmpstr);
	return ret;
}

/* callbacks for the normal load */
static void
__processor_config_load_content_cb(void *data, int lc, char *key, char *value, char *line)
{
	processor_config_t *config = (processor_config_t *)data;
	if (!processor_config_is_valid_key(key)) {
		LOG_WARN("Invalid configuration on line %d: %s\n", lc, key);
	}
		
	/* should we perhaps check the validity of the config
	   key - enums especially? */

	if (processor_config_set_string(config, key, value)) {
		LOG_ERROR("Error adding configuration on line %d: %s\n", lc, key);
	} else {
		LOG_DEBUG("Loaded config on line %d: %s => %s\n", lc, key, value);
	}
}

static void
__processor_config_load_ignore_cb(void *data, int lc, char *key, char *line)
{
	LOG_VDEBUG("Skipping line %d: %s\n", lc, key);
}

/* loads the config from the give file */
int 
processor_config_load(processor_config_t *config, char *filename)
{
	int ret = -1;
	struct stat sdata;
	
	if (!filename)
		filename = processor_config_string(config, P2PSHIP_CONF_CONF_FILE);
	
	/* if it doesn't exist AND is not the default, do nothing */
	if (!filename || stat(filename, &sdata)) {
		LOG_WARN("Config file %s does not exist\n", filename);
		goto err;
	}
	
	ret = ship_read_file(filename, config, 
			     __processor_config_load_content_cb, 
			     __processor_config_load_ignore_cb);
 err:
	return ret;
}

/* callbacks for the save */
static void
__processor_config_save_content_cb(void *data, int lc, char *key, char *value, char *line)
{
	void **blob = data;
	char **buf = blob[0];
	int *len = blob[1], *size = blob[2];
	processor_config_t *config = blob[3];
	
	/* modify only those that differ & part of the default set */
	char *newvalue = processor_config_string(config, key);
	if (processor_config_get_default(key) && 
	    ((!newvalue && strlen(value)) || 
	     (newvalue && strcmp(newvalue, value)))) {
		ASSERT_TRUE((*buf) = append_str(key, *buf, size, len), err);
		ASSERT_TRUE((*buf) = append_str(" = ", *buf, size, len), err);
		if (newvalue)
			ASSERT_TRUE((*buf) = append_str(newvalue, *buf, size, len), err);
		ASSERT_TRUE((*buf) = append_str("\n", *buf, size, len), err);
	} else {
		/* keep old line as-is */
		ASSERT_TRUE((*buf) = append_str(line, *buf, size, len), err);
	}
 err:
	/* remove the config */
	processor_config_remove(config, key);
}

static void
__processor_config_save_ignore_cb(void *data, int lc, char *key, char *line)
{
	void **blob = data;
	char **buf = blob[0];
	int *len = blob[1], *size = blob[2];

	(*buf) = append_str(line, *buf, size, len);
}

/* saves the config to the specific file. This saves by modifying
   (preserving) the existing file, and doesn't save configurations
   that aren't part of the 'standard array'. That is, it doesn't save
   file path modifications (web path, ident file etc. that doesn't
   show up in the web-conf interface).
*/
int 
processor_config_save(processor_config_t *config, char *filename)
{
	int ret = -1;
	processor_config_t *dup = 0;
	char *data = 0;
	int len = 0, size = 0;
	void *blob[4];
	void *ptr = 0;
	processor_config_item_t *item;
	int added = 0;
	FILE *f = NULL;
	
	LOG_INFO("Saving configuration to %s..\n", filename);
	ASSERT_TRUE(filename && config, err);
	ASSERT_TRUE(dup = processor_config_new(), err);

	/* create dup of the configs */
	ASSERT_ZERO(processor_config_transfer(dup, config), err);
	
	/* go through the file, modify the configs, remove from the
	   dup when encountered */
	blob[0] = &data;
	blob[1] = &len;
	blob[2] = &size;
	blob[3] = dup;
	ship_read_file(filename, &blob, 
		       __processor_config_save_content_cb, 
		       __processor_config_save_ignore_cb);
	
	/* go through the remaining entries, append those */
	while ((item = ship_list_next(dup, &ptr))) {
		/* should we save additional stuff.. ? */
		if (!added) {
			ASSERT_TRUE(data = append_str("\n#\n# Added by the web configuration interface:\n\n", 
						      data, &size, &len), err);
			added = 1;
		}
		ASSERT_TRUE(data = append_str(item->key, data, &size, &len), err);
		ASSERT_TRUE(data = append_str(" = ", data, &size, &len), err);
		if (item->value)
			ASSERT_TRUE(data = append_str(item->value, data, &size, &len), err);
		ASSERT_TRUE(data = append_str("\n", data, &size, &len), err);
	}

	if (!(f = fopen(filename, "w"))) {
		LOG_ERROR("Could not open configuration file %s\n", filename);
		goto err;
	}
	if (len != fwrite(data, sizeof(char), len, f))
		goto err;
	
	ret = 0;
 err:
	if (f)
		fclose(f);
	freez(data);
	processor_config_free(dup);
	return ret;
}

void 
processor_config_clear(processor_config_t *config)
{
	processor_config_item_t *item;
	while (config && (item = ship_list_pop(config))) {
		freez(item->value);
		freez(item->key);
		freez(item);
	}	
}

void 
processor_config_free(processor_config_t *config)
{
	processor_config_clear(config);
	ship_list_free(config);
}

processor_config_t *
processor_config_new()
{
	return ship_list_new();
}

/* getters / setters */
int 
processor_config_set_int(processor_config_t *config, const char *key, const int value)
{
	char buf[24];
	sprintf(buf, "%d", value);
	return processor_config_set_string(config, key, buf);
}

int 
processor_config_set_string(processor_config_t *config, const char *key, const char *value)
{
	processor_config_item_t *item = 0;
	int i = -2;
	char *tmp = 0;
	void *ptr = 0;

	/* set only if len > 0 */
	if (value && value[0]) {
		ASSERT_TRUE(tmp = strdup(value), err);
	}

	tmp = trim(tmp);

	/* try to replace first */
	while ((item = ship_list_next(config, &ptr))) {
		if (!strcmp(item->key, key)) {
			/* reverse order as maemo compiler seems to
			   screw this up */
			char *t2 = item->value;
			item->value = tmp;
			freez(t2);
			tmp = 0;
		}
	}

	if (tmp) {
		ASSERT_TRUE(item = mallocz(sizeof(processor_config_item_t)), err);
		ASSERT_TRUE(item->key = strdup(key), err);
		item->value = tmp;
		ship_list_add(config, item);
		item = NULL;
		tmp = NULL;
	}

	i = 0;
 err:
	freez(tmp);
	if (item) {
		freez(item->value);
		freez(item->key);
		freez(item);
	}
	return i;
}

void
processor_config_remove(processor_config_t *config, const char *key)
{
	processor_config_item_t *item;
	void *ptr = 0, *last = 0;
	while ((item = ship_list_next(config, &ptr))) {
		if (!strcmp(item->key, key)) {
			ship_list_remove(config, item);
			freez(item->value);
			freez(item->key);
			freez(item);
			ptr = last;
		} else
			last = ptr;
	}
}

/* ownership NOT given */
int 
processor_config_get_int(processor_config_t *config, const char *key, int *value)
{
	char *tmp;
	if (!processor_config_get_string(config, key, &tmp)) {
		*value = atoi(tmp);
		return 0;
	} else {
		return -1;
	}
}

int 
processor_config_is_true(processor_config_t *config, const char *key)
{
	int tmp;
	if (processor_config_get_bool(config, key, &tmp) || !tmp)
		return 0;
	else
		return 1;
}

int 
processor_config_is_false(processor_config_t *config, const char *key)
{
	int tmp;
	if (processor_config_get_bool(config, key, &tmp) || tmp)
		return 0;
	else
		return 1;
}

int 
processor_config_get_bool(processor_config_t *config, const char *key, int *value)
{
	char *tmp;
	if (!processor_config_get_string(config, key, &tmp)) {
		
		if (ship_is_true(tmp))
			*value = 1;
		else
			*value = 0;
		return 0;
	} else {
		return -1;
	}
}

int 
processor_config_get_string(processor_config_t *config, const char *key, char **value)
{
	processor_config_item_t *item;
	void *ptr = NULL;

	while ((item = ship_list_next(config, &ptr))) {
		if (!strcmp(key, item->key) && item->value) {
			*value = item->value;
			return 0;
		}
	}
	return -1;
}

int
processor_config_get_enum(processor_config_t *config, const char *key, int *value)
{
	int ret = -1;
	char *tmp;
	if (!processor_config_get_string(config, key, &tmp)) {
		char **def;
		int pos = 0;
		
		ASSERT_TRUE(def = processor_config_get_default(key), err);
		ASSERT_TRUE(def[3], err);
		
		/* 'parse' the enums, find which one this is .. */
		ASSERT_TRUE(str_startswith(def[3], "enum:"), err);
		pos = ship_find_token(strchr(def[3], ':')+1, tmp, ',');
		if (pos > -1) {
			*value = pos;
			ret = 0;
		} else {
			USER_ERROR("invalid enum value for key %s: %s\n", key, tmp);
		}
	}
 err:
	return ret;
}

char *
processor_config_string(processor_config_t *config, const char *key)
{
	char *ret = 0;
	if (config && !processor_config_get_string(config, key, &ret))
		return ret;
	return 0;
}

int
processor_config_int(processor_config_t *config, const char *key)
{
	int ret = 0;
	if (config && !processor_config_get_int(config, key, &ret))
		return ret;
	return 0;
}

int
processor_config_bool(processor_config_t *config, const char *key)
{
	int ret = 0;
	if (config && !processor_config_get_bool(config, key, &ret))
		return ret;
	return 0;
}
