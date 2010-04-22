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
#include "processor_config.h"
#include "netio.h"
#include "ship_debug.h"
#include "ship_utils.h"
#include "webconf.h"
#include <sys/stat.h>
#include "processor.h"
#include "ident.h"
#include "netio_http.h"
#ifdef CONFIG_SIP_ENABLED
#include "sipp.h"
#include "access_control.h"
#endif

/* the listening socket */
static int webconf_ss = -1;
static processor_config_t *p_config;
extern time_t p2pship_start;

/* list of sockets that want un events */
static ship_list_t *un_events = 0;


char*
webconf_get_json(const char *url)
{
	char *json = 0, *tmp = 0;
	int size = 0, len = 0;
	char *all = strstr(url, "/all");
		
	if (strstr(url, "/config") || all) {
		LOG_DEBUG("Got config json request\n");
		processor_config_dump_json(p_config, &tmp);
		json = append_str(tmp, json, &size, &len);
		freez(tmp);
	}
	if (strstr(url, "/idents") || all) {
		LOG_DEBUG("Got idents json request\n");
		ident_data_dump_identities_json(ident_get_identities(), &tmp);
		json = append_str(tmp, json, &size, &len);
		freez(tmp);
	}
	if (strstr(url, "/cas") || all) {
		LOG_DEBUG("Got cas json request\n");
		ident_data_dump_cas_json(ident_get_cas(), &tmp);
		json = append_str(tmp, json, &size, &len);
		freez(tmp);
	}
#ifdef CONFIG_SIP_ENABLED
	if (strstr(url, "/mps") || all) {
		LOG_DEBUG("Got mps json request\n");
		sipp_mp_dump_json(&tmp);
		json = append_str(tmp, json, &size, &len);
		freez(tmp);
	} 
#endif
	if (strstr(url, "/info") || all) {
		LOG_DEBUG("Got info json request\n");
		ship_debug_dump_json(&tmp);
		json = append_str(tmp, json, &size, &len);
		freez(tmp);
	}

#ifdef CONFIG_SIP_ENABLED
#ifdef DO_STATS
	if (strstr(url, "/stats") || all) {
		LOG_DEBUG("Got stats json request\n");
		stats_dump_json(&tmp);
		json = append_str(tmp, json, &size, &len);
		freez(tmp);
	}
#endif
#endif
	return json;
}

static int
webconf_process_req(netio_http_conn_t *conn, void *pkg)
{
	LOG_DEBUG("got req for %s\n", conn->url);
	if (str_startswith(conn->url, "/json/")) {
		char *json = webconf_get_json(conn->url);
		if (json) {
			netio_http_respond_str(conn, 200, "OK", json);
			freez(json);
		} else {
			netio_http_respond_str(conn, 500, "Error", "Internal server error");
		}	
	} else if (str_startswith(conn->url, "/post/")) {
		char *redir = 0;
		netio_http_param_t *param = 0;
		void *ptr = 0;
		
		/* the redir */
		redir = netio_http_conn_get_param(conn, "return_url");
		LOG_VDEBUG("Got redir addr %s\n", redir);

		if (strstr(conn->url, "/config")) {
			int save = 0;
			ship_list_t *vals = ship_ht_values(conn->params);
			
			LOG_DEBUG("Got config POST\n");
			while (vals && (param = ship_list_next(vals, &ptr))) {
				LOG_VDEBUG("Got param set '%s' => '%s'\n", param->name, param->data);
				if (!strcmp("return_url", param->name))
					redir = param->data;
				else if (!strcmp("save", param->name))
					save = 1;
				else 
					processor_config_dynamic_update(p_config, param->name, param->data);
			}
			
			ship_list_free(vals);

			/* should we save to disk? */
			if (save) {
				processor_config_save(p_config, processor_config_string(p_config, P2PSHIP_CONF_CONF_FILE));
			}
			
		} else if (strstr(conn->url, "/remove_ident")) {
			char *aor = netio_http_conn_get_param(conn, "sip_aor");
			LOG_DEBUG("Got ident remove POST for %s\n", aor);
			ident_remove_ident_query(aor, 0);
		} else if (strstr(conn->url, "/ident_import")) {
			char *buf = netio_http_conn_get_param(conn, "file");
			LOG_DEBUG("Got identity import\n");
			
			if (buf) {
				ident_import_mem(buf, strlen(buf), 0, MODIF_NEW);
			}
		} else if (strstr(conn->url, "/save_idents")) {
			if (ident_save_identities()) {
				LOG_ERROR("Error while saving identities\n");
				redir = 0;
			}
		} else if (strstr(conn->url, "/reload_idents")) {
			if (ident_load_identities()) {
				LOG_ERROR("Error while loading identities\n");
				redir = 0;
			}
		} else if (strstr(conn->url, "/set_status")) {
			char *aor = netio_http_conn_get_param(conn, "sip_aor");
			char *status = netio_http_conn_get_param(conn, "status");
			
			if (aor && status)
				ident_set_status(aor, status);
		}
		
		if (redir) {
			netio_http_redirect(conn, redir);
			/* webconf_respond_str(conn, 202, "Accepted", "POST accepted"); */
		} else {
			netio_http_respond_str(conn, 400, "Error", "Invalid request");
		}

	} else if (str_startswith(conn->url, "/shutdown")) {
		char *redir = 0, *resp = 0;
		void *ptr = 0;

		redir = netio_http_conn_get_param(conn, "return_url");
		if (redir && (resp = mallocz(strlen(redir) + 256))) {
			sprintf(resp, "Shutting down. Reload from <a href='%s'>here</a>", redir);
			netio_http_respond(conn, 
					   200, "OK",
					   "text/html",
					   resp, strlen(resp));
			freez(resp);
		} else {
			netio_http_respond_str(conn, 200, "OK", "Shutting down.");
		}
		processor_shutdown();
		/* real elegant ;) */
		processor_shutdown();

#ifdef CONFIG_HIP_ENABLED
 	} else if (str_startswith(conn->url, "/restarthipd")) {
		int ret = -1;
		char *resp = 0;
		char *cmd = processor_config_string(p_config, P2PSHIP_CONF_HIP_SHUTDOWN);
		char **tokens = 0;
		int toklen = 0;
		
		if (cmd && !ship_tokenize_trim(cmd, strlen(cmd), &tokens, &toklen, ' ')) {
			if (!(ret = fork())) {
				execvp(*tokens, tokens);
			}
			
			if (resp = mallocz(strlen(cmd) + 128)) {
				sprintf(resp, "'%s' was executed as process %d", cmd, ret);
				netio_http_respond_str(conn, 200, "OK", resp);
			} else {
				netio_http_respond_str(conn, 200, "OK", "Executed");
			}
			ship_tokens_free(tokens, toklen);
		} else {
			netio_http_respond_str(conn, 500, "Error", "Internal server error");
		}
		freez(resp);
#endif
	} else if (str_startswith(conn->url, "/web/")) {
		char *filename = 0, *buf = 0;
		char *filepath = conn->url + 4; /* skip '/web' */
		struct stat sdata;
		int found = 0;
		char *web_dir = processor_config_string(p_config, P2PSHIP_CONF_WEB_DIR);
		
		/* skip multiple /'s */
		if (web_dir && strlen(web_dir) && web_dir[strlen(web_dir)-1] == '/')
			filepath++;
		
		/* load the file from the web-dir */
		if (web_dir && (filename = mallocz(strlen(filepath) + strlen(web_dir) + 1))) {
			strcpy(filename, web_dir);
			strcat(filename, filepath);
			
			/* cut off */
			if (filepath = strchr(filename, '?'))
				filepath[0] = 0;
			
			if (stat(filename, &sdata)) {
				LOG_WARN("Requested non-existing file %s\n", filename);
			} else {
				/* load file .. */
				char *buf = 0;
				FILE *f = fopen(filename, "r");
				if (f && (buf = malloc(sdata.st_size))) {
					size_t r = fread(buf, 1, sdata.st_size, f);
					if (r == sdata.st_size) {
						netio_http_respond(conn, 200, "OK", "text/html",
								buf, r);
						found = 1;
					}
				}
				freez(buf);
				if (f)
					fclose(f);
			}
		}

		freez(filename);
		if (!found)
			netio_http_respond_str(conn, 404, "Not found", "The page you were looking for could not be found");
			
	} else {
		LOG_WARN("Got unknown HTTP request on webconf interface for %s\n", conn->url);

		/* go to the default start page */
		if (!strcmp(conn->url, "/"))
			netio_http_redirect(conn, "/web/start.html");
		else
			netio_http_respond_str(conn, 404, "Not found", "The page you were looking for could not be found");
	}
	
	return 0;
}

/* this gets called when an config has been updated */
static int
webconf_cb_config_update(processor_config_t *config, char *k, char *v)
{
	int ret = -1;

	/* webdir & shutdown command are used dynamically anyway.. */
	if (!strcmp(k, P2PSHIP_CONF_WEBCONF_SS)) {
		char *ss_addr;
		ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_WEBCONF_SS, &ss_addr), err);

		if (webconf_ss == -1) {
			ASSERT_TRUE((webconf_ss = netio_http_server_create(ss_addr, 
									   webconf_process_req, NULL)) != -1, err);
		} else {
			ASSERT_ZERO((ret = netio_http_server_modif(webconf_ss, ss_addr)) != -1, err);
			webconf_ss = ret;
		}
	}
	ret = 0;
 err:
	return ret;
}

#ifdef CONFIG_SIP_ENABLED

/* callback for receiving sip_log events */
static void 
webconf_un_receive_sip_log(char *event, void *data, void *eventdata)
{
	struct sockaddr *addr = 0;
	socklen_t addrlen = 0;
	void *ptr = 0, *last = 0;
	
	int len = 0, size = 0, *s = 0;
	char *str = 0, *tmp = 0, *name = 0;

	call_log_entry_t *e = eventdata;
	reg_package_t *r = 0;
	ident_t *ident = 0;
	char buf[32];
	
	ship_lock(un_events);

	/* create the event string */
	if (str_startswith(e->id, "invite")) {
		ASSERT_TRUE((tmp = append_str("call;", str, &size, &len)) && (str = tmp), err);
	} else if (str_startswith(e->id, "message")) {
		ASSERT_TRUE((tmp = append_str("conversation;", str, &size, &len)) && (str = tmp), err);
	} else {
		ASSERT_TRUE((tmp = append_str("unknown;", str, &size, &len)) && (str = tmp), err);
	}

	ASSERT_TRUE((tmp = append_str((e->remotely_initiated? "remote;" : "local;"), str, &size, &len)) && (str = tmp), err);

	ASSERT_TRUE((tmp = append_str(e->local_aor, str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(";", str, &size, &len)) && (str = tmp), err);
	if (ident = ident_find_by_aor(e->local_aor))
		name = ident->username;
	ASSERT_TRUE((tmp = append_str((name? name:""), str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(";", str, &size, &len)) && (str = tmp), err);
    
	ASSERT_TRUE((tmp = append_str(e->remote_aor, str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(";", str, &size, &len)) && (str = tmp), err);
	if (r = ident_find_foreign_reg(e->remote_aor))
		name = r->name;
	ASSERT_TRUE((tmp = append_str((name? name:""), str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(";", str, &size, &len)) && (str = tmp), err);
	ship_unlock(r);
	r = 0;
	
	if (e->verdict == AC_VERDICT_ALLOW) {
		ASSERT_TRUE((tmp = append_str("allow;", str, &size, &len)) && (str = tmp), err);
	} else {
		ASSERT_TRUE((tmp = append_str("block;", str, &size, &len)) && (str = tmp), err);
	}
	
	sprintf(buf, "pathlen=%d", e->pathlen);
	ASSERT_TRUE((tmp = append_str(buf, str, &size, &len)) && (str = tmp), err);
	ASSERT_TRUE((tmp = append_str(";\n", str, &size, &len)) && (str = tmp), err);
	
	/* loop through and send */
	while (s = ship_list_next(un_events, &ptr)) {
		if (getpeername(*s, addr, &addrlen)) {
			netio_close_socket(*s);
			ship_list_remove(un_events, s);
			ptr = last;
			free(s);
		} else {
			netio_send(*s, str, strlen(str));
		}
		last = ptr;
	}
	
 err:
	ship_obj_unlockref(ident);
	ship_unlock(r);
	freez(str);
	ship_unlock(un_events);
}

#endif

/* socket conf interface. this might not be the best place for this,
   but seems sort-of related to the webconf */
static void
webconf_un_read_cb(int s, char *data, ssize_t datalen)
{
	if (datalen > 0) {
		char *ret = 0;
		int val = -1;
		char *conf, *conf_val;
		
		LOG_VDEBUG("got '%s' over unix socket\n", data);
		conf = strchr(data, ':')+1;
		if (str_startswith(data, "get_conf:")) {
			if (processor_config_is_valid_key(conf)) {
				if (!(conf_val = processor_config_string(p_config, conf)))
					conf_val = "";
				if (ret = mallocz(strlen(conf) + strlen(conf_val) + 10))
					sprintf(ret, "%s:%s", conf, conf_val);
				
				LOG_VDEBUG("sending config value for %s:%s\n", conf, conf_val);
			} else {
				LOG_DEBUG("got request for non-existing conf key '%s'\n", conf);
				ret = strdup("invalid key");
			}
		} else if (str_startswith(data, "set_conf:")) {
			if (conf_val = strchr(conf, '=')) {
				conf_val[0] = 0;
				conf_val++;

				LOG_DEBUG("setting config value for %s to %s\n", conf, conf_val);
				if (processor_config_dynamic_update(p_config, conf, conf_val))
					ret = strdup("error");
				else {
					ret = strdup("ok");
					processor_config_save(p_config, processor_config_string(p_config, P2PSHIP_CONF_CONF_FILE));
				}
			} else {
				LOG_DEBUG("got invalid key-value pair for set conf request '%s'\n", conf);
				ret = strdup("invalid request");
			}
		} else if (str_startswith(data, "set_status:")) {
			char *aor = strchr(data, ':') + 1;
			char *status = strchr(aor, ':');
			
			if (status) {
				status[0] = 0;
				status++;
			}
			
			if (!strlen(aor) || !strcmp(aor, "all")) {
				ident_set_status(NULL, status);
			} else {
				ident_set_status(aor, status);
			}
			ret = strdup("ok");
		} else if (str_startswith(data, "get_status:")) {
			char *aor = strchr(data, ':') + 1;
			char *status = 0;
			
			status = ident_get_status((strlen(aor)? aor : NULL));

			if (status)
				ret = status;
			else
				ret = strdup("");
			
		} else if (str_startswith(data, "events:")) {
			int *s2 = 0;
#ifdef CONFIG_SIP_ENABLED
			if (!strcmp(conf, "sip_log")) {
				if (s2 = mallocz(sizeof(int))) {
					*s2 = s;
					ship_lock(un_events);
					ship_list_push(un_events, s2);
					ship_unlock(un_events);
					ret = strdup("ok\n");
					netio_send(s, ret, strlen(ret)+1);
					s = -1;
				}
			}
#endif

#ifdef CONFIG_SIP_ENABLED
		} else if (str_startswith(data, "ac:")) {
			char *listname = 0;
			char *name = 0;
			ship_ht_t *list = 0;

			if (listname = strchr(conf, ':')) {
				listname++;
				if (name = strchr(listname, ':'))
					name++;
				if (str_startswith(listname, "whitelist"))
					list = ac_lists_whitelist();
				else if (str_startswith(listname, "blacklist"))
					list = ac_lists_blacklist();
			}

			if (list && str_startswith(conf, "show:")) {
				int len = 0, size = 0;
				char *tmp;
				ship_list_t *names = 0;
				
				if (tmp = append_str("", ret, &size, &len))
					ret = tmp;

				if (names = ship_ht_keys(list)) {
					while(name = ship_list_pop(names)) {
						if (tmp = append_str(name, ret, &size, &len))
							ret = tmp;
						/* todo: add the name & other metainfo */
						if (tmp = append_str(",User name", ret, &size, &len))
							ret = tmp;
						if (tmp = append_str("\n", ret, &size, &len))
							ret = tmp;						
						free(name);
					}
					ship_list_free(names);
				}
				
			}  else if (list && name && str_startswith(conf, "add:")) {
				ship_ht_put_string(list, name, (void*)1);
				ac_lists_save();
				ret = strdup("ok\n");
			}  else if (list && name && str_startswith(conf, "remove:")) {
				ship_ht_remove_string(list, name);
				ac_lists_save();
				ret = strdup("ok\n");
			}

#endif
		} else {
			LOG_DEBUG("got invalid invalid request '%s'\n", data);
		}
		
		if (!ret)
			ret = strdup("error");
		
		if (ret && s != -1)
			netio_send(s, ret, strlen(ret)+1);
		freez(ret);
	}
	
	if (s != -1)
		netio_close_socket(s);
}

/* socket callback */
static void 
webconf_un_conn_cb(int s, struct sockaddr *sa, socklen_t size, int ss)
{
	LOG_VDEBUG("got unix socket\n");
	if (netio_read(s, webconf_un_read_cb)) {
		netio_close_socket(s);
	}
}


/* starts up the webconf interface */
int
webconf_init(processor_config_t *config)
{
	int ret = -1;
	
	p_config = config;

	webconf_cb_config_update(config, P2PSHIP_CONF_WEBCONF_SS, processor_config_string(config, P2PSHIP_CONF_WEBCONF_SS));
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_WEB_DIR, webconf_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_WEBCONF_SS, webconf_cb_config_update);
#ifdef CONFIG_HIP_ENABLED
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_HIP_SHUTDOWN, webconf_cb_config_update);
#endif	

	/* start the socket listener */
	ASSERT_TRUE(un_events = ship_list_new(), err);
	ASSERT_TRUE(netio_new_unix_socket("/tmp/p2pship.socket", 0666,
					  webconf_un_conn_cb) != -1, err);
#ifdef CONFIG_SIP_ENABLED
	ASSERT_ZERO(processor_event_receive("sip_log", NULL, webconf_un_receive_sip_log), err);
#endif
	ret = 0;
 err:
	return ret;
}

/* closes up the module */
void
webconf_close()
{
	netio_http_server_close(webconf_ss);
	if (un_events) {
		ship_list_empty_free(un_events);
		ship_list_free(un_events);
	}
}

/* the webconf register */
static struct processor_module_s processor_module = 
{
	.init = webconf_init,
	.close = webconf_close,
	.name = "webconf",
#ifdef CONFIG_SIP_ENABLED
	.depends = "netio_ff,netio_http,sipp",
#else
	.depends = "netio_ff,netio_http",
#endif
};

/* register func */
void
webconf_register() {
	processor_register(&processor_module);
}

