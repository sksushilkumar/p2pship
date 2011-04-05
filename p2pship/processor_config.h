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
#ifndef __PROCESSOR_CONFIG_H__
#define __PROCESSOR_CONFIG_H__

#include "ship_utils.h"

/* list of config keys */
#define P2PSHIP_CONF_DAEMON "ship_daemon"
#define P2PSHIP_CONF_WORKER_THREADS "ship_worker_threads"
#define P2PSHIP_CONF_SHIP_PORT "ship_port"
#define P2PSHIP_CONF_SHIP_PORT_RANGE "ship_port_range"
#define P2PSHIP_CONF_IFACES "ship_ifaces"

#define P2PSHIP_CONF_OL_SECRET "ol_secret"

#define P2PSHIP_CONF_IDENT_TRUST_FRIENDS "ident_trust_friends"
#define P2PSHIP_CONF_IDENT_IGNORE_CERT_VALIDITY "ident_ignore_cert_validity"
#define P2PSHIP_CONF_IDENT_ALLOW_UNKNOWN_REGISTRATIONS "ident_allow_unknown_registrations"
#define P2PSHIP_CONF_IDENT_ALLOW_UNTRUSTED "ident_allow_untrusted"
#define P2PSHIP_CONF_IDENT_REQUIRE_AUTHENTICATION "ident_require_authentication"
#define P2PSHIP_CONF_IDENT_UA_MODE "ident_ua_mode"
#define P2PSHIP_CONF_IDENT_RENEGOTIATE_SECRET "ident_renegotiate_secret"

#define P2PSHIP_CONF_IDENTS_FILE "idents_file"
#define P2PSHIP_CONF_CONF_FILE "conf_file"
#define P2PSHIP_CONF_AUTOREG_FILE "autoreg_file"
#define P2PSHIP_CONF_LOG_FILE "log_file"
#define P2PSHIP_CONF_WEB_DIR "web_dir"
#define P2PSHIP_CONF_DATA_DIR "data_dir"

#define P2PSHIP_CONF_CONTACTS_FILE "contacts_log"
#define P2PSHIP_CONF_WHITELIST_FILE "whitelist_file"
#define P2PSHIP_CONF_BLACKLIST_FILE "blacklist_file"

#define P2PSHIP_CONF_PATHFINDER "ac_pathfinder"
#define P2PSHIP_CONF_USE_PATHFINDER "ac_use_pathfinder"
#define P2PSHIP_CONF_AC_HTTP "ac_http"
#define P2PSHIP_CONF_AC_MAX_PATH "ac_maxpath"

#define P2PSHIP_CONF_CONN_KEEPALIVE "conn_keepalive"

#ifdef CONFIG_PYTHON_ENABLED
#define P2PSHIP_CONF_START_SHELL "py_start_shell"
#define P2PSHIP_CONF_RUN_SCRIPT "py_run_script"
#define P2PSHIP_CONF_STARTUP_SCRIPTS "py_startup_scripts"

#define P2PSHIP_CONF_PYTHON_LIB_DIR "py_lib"
#define P2PSHIP_CONF_PYTHON_SCRIPTS_DIR "py_scripts"
#define P2PSHIP_CONF_PYTHON_INSTANCES_DIR "py_instances"
#define P2PSHIP_CONF_PYTHON_PACKAGES_DIR "py_packages"
#endif

/* hm, should these be in ? */
#ifdef CONFIG_SIP_ENABLED
#define P2PSHIP_CONF_SIPP_PROXY_IFACES "sip_proxy_ifaces"
#define P2PSHIP_CONF_SIPP_PROXY_PORT "sip_proxy_port"
#define P2PSHIP_CONF_SIPP_MEDIA_PROXY "sip_media_proxy"
#define P2PSHIP_CONF_SIPP_MEDIA_PROXY_MOBILITY_SUPPORT "sip_media_proxy_mobility"
#define P2PSHIP_CONF_SIPP_MEDIA_PROXY_FORCE4 "sip_media_proxy_force4"
#define P2PSHIP_CONF_SIPP_FORCE_PROXY "sip_force_proxy"
#define P2PSHIP_CONF_SIPP_TUNNEL_PROXY "sip_tunnel_proxy"
#define P2PSHIP_CONF_CALL_LOG_SHOW_PATHINFO "call_log_show_path"
#define P2PSHIP_CONF_CALL_LOG_SHOW_DROPPED "call_log_show_dropped"
#define P2PSHIP_CONF_SIPP_ROUTING_FILE "sip_routing_file"

/* the post-dial delay measurement-related things */
#define P2PSHIP_CONF_PDD_RESET_MODE "pdd_reset_mode"
#define P2PSHIP_CONF_PDD_LOG "pdd_log"
#endif


#ifdef CONFIG_BROADCAST_ENABLED
#define P2PSHIP_CONF_BC_ADDR "bc_addr"
#define P2PSHIP_CONF_BC_IFACES "bc_ifaces"
#endif

#ifdef CONFIG_P2PEXT_ENABLED
#define P2PSHIP_CONF_P2PEXT_PROXY "p2pext_proxy"
#endif

#ifdef CONFIG_OPENDHT_ENABLED
#define P2PSHIP_CONF_OPENDHT_PROXY "opendht_proxy"
#endif

#ifdef CONFIG_HIP_ENABLED
#define P2PSHIP_CONF_PROVIDE_RVS "hip_provide_rvs"
#define P2PSHIP_CONF_NAT_TRAVERSAL "hip_nat_traversal"
#define P2PSHIP_CONF_RVS "hip_rvs"
#define P2PSHIP_CONF_HIP_SHUTDOWN "hip_shutdown"
#define P2PSHIP_CONF_ALLOW_NONHIP "hip_allow_nonhip"
#endif

#ifdef CONFIG_WEBCONF_ENABLED
#define P2PSHIP_CONF_WEBCONF_SS "webconf"
#endif

#ifdef CONFIG_EXTAPI_ENABLED
#define P2PSHIP_CONF_EXTAPI_SS "extapi"

#ifdef CONFIG_HTTPPROXY_ENABLED
#define P2PSHIP_CONF_HTTPPROXY_ADDR "httpproxy"
#define P2PSHIP_CONF_HTTPPROXY_REVEAL_ORIGINAL "httpproxy_reveal_original"
#endif
#endif

#ifdef CONFIG_WEBCACHE_ENABLED
#define P2PSHIP_CONF_WEBCACHE_STRICTNESS "webcache_strictness"
#define P2PSHIP_CONF_WEBCACHE_FILELIMIT "webcache_filelimit"
#define P2PSHIP_CONF_WEBCACHE_LIMIT "webcache_limit"
#define P2PSHIP_CONF_WEBCACHE_INDEX "webcache_index"
#define P2PSHIP_CONF_WEBCACHE_USE_P2P_LOOKUP "webcache_use_p2p_lookup"
#endif

#ifdef REMOTE_DEBUG
#define P2PSHIP_CONF_REMOTE_DEBUG "remote_debug"
#endif

#ifdef CONFIG_OP_ENABLED
#define P2PSHIP_CONF_IDENT_USE_OP_FOR_UNKNOWN "use_op_for_unknown"
#define P2PSHIP_CONF_IDENT_FILTERING "op_filtering"
#endif


typedef ship_list_t processor_config_t;
typedef struct processor_config_item_s {
	char *value;
	char *key;
} processor_config_item_t;

/* loads the config from the give file */
int processor_config_load(processor_config_t *config, char *filename);
int processor_config_save(processor_config_t *config, char *filename);
int processor_config_load_defaults(processor_config_t *config);
int processor_config_ensure_configs(processor_config_t *config);

void processor_config_dump_json(processor_config_t *config, char **msg);

/* overwrites the values from one to another one */
int processor_config_transfer(processor_config_t *target, processor_config_t *source);

/* construction */
void processor_config_free(processor_config_t *config);
void processor_config_clear(processor_config_t *config);
processor_config_t *processor_config_new();

int processor_config_init();
void processor_config_close();

/* getters / setters */
int processor_config_set_int(processor_config_t *config, const char *key, const int value);
int processor_config_set_string(processor_config_t *config, const char *key, const char *value);
#define processor_config_set_true(config, key) processor_config_set_string(config, key, "yes")
#define processor_config_set_false(config, key) processor_config_set_string(config, key, "no")

/* ownership NOT given */
int processor_config_get_int(processor_config_t *config, const char *key, int *value);
int processor_config_get_bool(processor_config_t *config, const char *key, int *value);
int processor_config_is_true(processor_config_t *config, const char *key);
int processor_config_is_false(processor_config_t *config, const char *key);
int processor_config_get_string(processor_config_t *config, const char *key, char **value);
int processor_config_get_enum(processor_config_t *config, const char *key, int *value);

char * processor_config_string(processor_config_t *config, const char *key);
int processor_config_int(processor_config_t *config, const char *key);
int processor_config_bool(processor_config_t *config, const char *key);

void processor_config_remove(processor_config_t *config, const char *key);

int processor_config_is_valid_key(char *key);

/* check if we have a key .. */
int processor_config_has_key(processor_config_t *config, const char *key);

int processor_config_set_dynamic_update(processor_config_t *config, 
					const char *key, void (*func) (processor_config_t *c, char *k, char *v));
int processor_config_dynamic_update(processor_config_t *config, 
				    char *key, char *value);

void processor_config_set_dynamic(processor_config_t *config, const char *key);
int processor_config_create_key(processor_config_t *config, const char *key, const char *description,
				const char *type, const char *value);

#endif
