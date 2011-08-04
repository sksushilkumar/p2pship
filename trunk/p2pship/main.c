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
/* p2pship
 *
 * The main point-of-entry for the p2pship stack
 */
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include "processor_config.h"
#include "processor.h"
#include "ship_utils.h"
#include "ship_debug.h"
#include "p2pship_version.h"
#include "netio.h"
#include "ui.h"
#include "conn.h"
#include "netio_events.h"
#include "netio_http.h"
#include "addrbook.h"
#include "osso_dbus.h"
#include "resourceman.h"

#ifdef CONFIG_START_GTK
#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#endif

#ifdef CONFIG_BROADCAST_ENABLED
#include "ol_broadcast.h"
#endif
#ifdef CONFIG_PYTHON_ENABLED
#include "pymod.h"
#endif
#ifdef CONFIG_HIP_ENABLED
#include "hipapi.h"
#endif
#ifdef CONFIG_SIP_ENABLED
#include "sipp.h"
#endif
#ifdef CONFIG_WEBCONF_ENABLED
#include "webconf.h"
#endif
#ifdef CONFIG_EXTAPI_ENABLED
#include "ext_api.h"
#endif
#ifdef CONFIG_WEBCACHE_ENABLED
#include "webcache.h"
#endif
#ifdef CONFIG_MEDIA_ENABLED
#include "media.h"
#endif

/* default log level */
extern int p2pship_log_level;
extern char* p2pship_log_file;
extern time_t p2pship_start;

/* prints usage, exits */
static void 
print_usage()
{
	processor_config_t *config = 0;
	p2pship_log_level = -1;
	if ((config = processor_config_new())) {
		if (processor_config_load_defaults(config)) {
			USER_ERROR("Warning: Current configuration completely loaded\n");
		}
		processor_config_load(config, NULL);
	}
	
        USER_ERROR("Usage: p2pship [OPTION]\n\n");
        USER_ERROR("  -v, --verbose              verbosely report info\n");
        USER_ERROR("  -i, --iface [IFACE,..]     list of interfaces to publicly advertise (%s)\n", 
		   processor_config_string(config, P2PSHIP_CONF_IFACES));
#ifdef CONFIG_SIP_ENABLED
        USER_ERROR("  -p [PORT]                  use PORT for the legacy sip proxy (%d)\n", 
		   processor_config_int(config, P2PSHIP_CONF_SIPP_PROXY_PORT));
#endif
        USER_ERROR("  -s [PORT]                  use PORT for SHIP daemon communication (%d)\n", 
		   processor_config_int(config, P2PSHIP_CONF_SHIP_PORT));
        USER_ERROR("  -D                         start as daemon (%s)\n", 
		   (processor_config_is_true(config, P2PSHIP_CONF_DAEMON)? "yes":"no"));
        USER_ERROR("  -c [FILE]                  read configuration from [FILE]\n");
	USER_ERROR("                             (%s)\n", 
		   processor_config_string(config, P2PSHIP_CONF_CONF_FILE));
        USER_ERROR("  -R                         autoregister previous UAs\n");
        USER_ERROR("  -r [FILE]                  use [FILE] as the autoregister cache\n");
	USER_ERROR("                             (%s)\n", 
		   processor_config_string(config, P2PSHIP_CONF_AUTOREG_FILE));
        USER_ERROR("  -L                         log to file (auto in daemon mode)\n");
        USER_ERROR("      --log [FILE]           use [FILE] as output for file logging\n");
	USER_ERROR("                             (%s)\n", 
		   processor_config_string(config, P2PSHIP_CONF_LOG_FILE));
        USER_ERROR("      --threads=THREADS      set the number of worker threads (%d)\n", 
		   processor_config_int(config, P2PSHIP_CONF_WORKER_THREADS));
	USER_ERROR("      --help                 print help\n");
#ifdef CONFIG_SIP_ENABLED
	USER_ERROR("      --no-mp                disables the mediaproxy functionality (%s)\n", 
		   (processor_config_is_false(config,  P2PSHIP_CONF_SIPP_MEDIA_PROXY)? "on":"off"));
	USER_ERROR("      --tunnel-mp            forces tunnelled proxy mode (%s)\n", 
		   (processor_config_is_true(config, P2PSHIP_CONF_SIPP_TUNNEL_PROXY)? "on":"off"));
	USER_ERROR("      --force-mp             forces media proxy for ipv4 (%s)\n", 
		   (processor_config_is_true(config, P2PSHIP_CONF_SIPP_FORCE_PROXY)? "on":"off"));
        USER_ERROR("      --allow-unknown        allow unknown identities to register (%s)\n", 
		   (processor_config_is_true(config, P2PSHIP_CONF_IDENT_ALLOW_UNKNOWN_REGISTRATIONS)? "yes":"no"));
        USER_ERROR("      --proxy-iface          a list of interfaces to listen to for the proxy (%s)\n",
		   processor_config_string(config, P2PSHIP_CONF_SIPP_PROXY_IFACES));
        USER_ERROR("\n");
        USER_ERROR("      --allow-untrusted      allow untrusted peers to connect (%s)\n", 
		   (processor_config_is_true(config, P2PSHIP_CONF_IDENT_ALLOW_UNTRUSTED)? "yes":"no"));
#endif
	USER_ERROR("      --list-ca              list all trusted CA's\n");
        USER_ERROR("      --import-ca [file]     import a new ca\n");
        USER_ERROR("      --remove-ca [ca name]  remove the given trusted CA\n");
        USER_ERROR("      --list                 list all my identities\n");
        USER_ERROR("      --import [file]        import a new identity\n");
        USER_ERROR("      --remove [sip aor]     remove the identity\n");
        USER_ERROR("      --idents [file]        use [file] for identities\n");
	USER_ERROR("                             (%s)\n",
		   processor_config_string(config, P2PSHIP_CONF_IDENTS_FILE));
        USER_ERROR("\n");
#ifdef CONFIG_OPENDHT_ENABLED
        USER_ERROR("      --opendht [host:port]  use [host:port] as the opendht proxy\n");
	USER_ERROR("                             (%s)\n", 
		   processor_config_string(config, P2PSHIP_CONF_OPENDHT_PROXY));
        USER_ERROR("\n");
#endif
#ifdef CONFIG_BROADCAST_ENABLED
        USER_ERROR("      --bc-addr [addr:port]  use [host:port] as the broadcast. Either \n");
	USER_ERROR("                             host or port can be omitted in case\n");
 	USER_ERROR("                             address %s will be used.\n",
 		   processor_config_string(config, P2PSHIP_CONF_BC_ADDR));
        USER_ERROR("\n");
#endif
#ifdef CONFIG_WEBCONF_ENABLED
        USER_ERROR("      --webconf [addr:port]  use [host:port] as the webconf interface\n");
        USER_ERROR("                             (%s)\n",
		   processor_config_string(config, P2PSHIP_CONF_WEBCONF_SS));
#endif
#ifdef CONFIG_HIP_ENABLED
        USER_ERROR("      --list-hits            display the available hits & exit\n");
	USER_ERROR("      --rvs hit,ip;hit2,ip2  register to the specified RVS's\n");
	if (processor_config_string(config, P2PSHIP_CONF_RVS)) {
		USER_ERROR("                             (%s)\n", 
			   processor_config_string(config, P2PSHIP_CONF_RVS));
	}
        USER_ERROR("\n");
#endif
#ifdef CONFIG_PYTHON_ENABLED
	USER_ERROR("      --shell                Starts a new Python shell on stdin\n");
	USER_ERROR("      --console              Usees only console-UI\n");
	USER_ERROR("      --run [file]           Runs the given script in a Python environment\n");
#endif
        USER_ERROR("Bug reports to %s\n", PACKAGE_BUGREPORT);

	processor_config_free(config);
}

static inline void 
print_version()
{
        USER_ERROR("%s version %s (%s)\n", PACKAGE_NAME, VERSION, P2PSHIP_BUILD_VERSION);
}


/* the actions that can be performed */
enum {
	ACTION_NONE = 0,
	ACTION_LIST_CA = 1,
	ACTION_REMOVE_CA = 2,
	ACTION_IMPORT_CA = 3,
	ACTION_LIST = 4,
	ACTION_REMOVE = 5,
	ACTION_IMPORT = 6,

	ACTION_LIST_HITS = 7,
	ACTION_END
};

#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

/*
static
void xml_error_func(void * ctx, const char * msg, ...)
{
	LOG_WARN("Error occured while parsing XML document\n");
	LOG_WARN("Error message: '%s'\n", msg);
}
*/

/* point-of-entry */
int 
main(int argc, char **argv)
{
	int ret = -1, c, index, action = ACTION_NONE, tmp;
	char *action_param = NULL;
        processor_config_t *config = 0, *config2 = 0;
	char *conf_file = 0;
	int load_autoreg = 0;
	int flag_quiet = 0;
	int log_to_file = 0;
	int console_only = 0;

	xmlInitParser();
	xmlInitThreads();
	//initGenericErrorDefaultFunc((xmlGenericErrorFunc *)xml_error_func);

        /* the getopt values */
        static struct option long_options[] =
                {                        
                        {"verbose", no_argument, 0, 0},
                        {"iface", required_argument, 0, 0},
                        {"threads", required_argument, 0, 0},
                        {"help", no_argument, 0, 0},
                        {"version", no_argument, 0, 0},
                        {"console", no_argument, 0, 0},
#ifdef CONFIG_PYTHON_ENABLED
                        {"shell", no_argument, 0, 0},
                        {"run", required_argument, 0, 0},
                        {"no-scripts", no_argument, 0, 0},
#endif
#ifdef CONFIG_SIP_ENABLED
                        {"proxy-iface", required_argument, 0, 0},
                        {"no-mp", no_argument, 0, 0},
                        {"tunnel-mp", no_argument, 0, 0},
                        {"force-mp", no_argument, 0, 0},
                        {"allow-unknown", no_argument, 0, 0},
                        {"allow-untrusted", no_argument, 0, 0},
#endif
                        {"list-ca", no_argument, 0, 0},
                        {"import-ca", required_argument, 0, 0},
                        {"remove-ca", required_argument, 0, 0},
                        {"list", no_argument, 0, 0},
                        {"import", required_argument, 0, 0},
                        {"remove", required_argument, 0, 0},
                        {"idents", required_argument, 0, 0},
                        {"log", required_argument, 0, 0},
#ifdef CONFIG_BROADCAST_ENABLED
                        {"bc-addr", required_argument, 0, 0},
#endif
#ifdef CONFIG_WEBCONF_ENABLED
                        {"webconf", required_argument, 0, 0},
#endif
#ifdef CONFIG_OPENDHT_ENABLED
                        {"opendht", required_argument, 0, 0},
#endif
#ifdef CONFIG_HIP_ENABLED
                        {"list-hits", no_argument, 0, 0},
                        {"rvs", required_argument, 0, 0},
                        {"provide-rvs", no_argument, 0, 0},
#endif
                        {0, 0, 0, 0}
                };        

#ifdef LOCK_DEBUG
	debug2_init();
#endif
#ifdef REF_DEBUG2
	ship_debug_initref();
#endif


	if (!(config = processor_config_new()) || !(config2 = processor_config_new())) {
                USER_ERROR("Error loading application\n");
		goto err;
	}

	if (processor_config_load_defaults(config2)) {
                USER_ERROR("Error loading default configurations\n");
                goto err;
	}
	processor_config_get_string(config2, P2PSHIP_CONF_CONF_FILE, &conf_file);

        opterr = 0;
        while ((c = getopt_long(argc, argv, "LqvhDVs:c:p:i:Rr:", long_options, &index)) != -1) {
                
                if (!c) {
                        if (!strcmp(long_options[index].name, "threads")) {
				processor_config_set_int(config, P2PSHIP_CONF_WORKER_THREADS, atoi(optarg));
                        } else if (!strcmp(long_options[index].name, "help")) {
                                c = '?';
                        } else if (!strcmp(long_options[index].name, "version")) {
                                c = 'V';
                        } else if (!strcmp(long_options[index].name, "verbose")) {
                                c = 'v';
                        } else if (!strcmp(long_options[index].name, "iface")) {
                                c = 'i';
                        } else if (!strcmp(long_options[index].name, "console")) {
				console_only = 1;
#ifdef CONFIG_PYTHON_ENABLED
                        } else if (!strcmp(long_options[index].name, "shell")) {
				processor_config_set_true(config, P2PSHIP_CONF_START_SHELL);
                        } else if (!strcmp(long_options[index].name, "run")) {
				processor_config_set_string(config, P2PSHIP_CONF_RUN_SCRIPT, optarg);
                        } else if (!strcmp(long_options[index].name, "no-scripts")) {
				processor_config_set_false(config, P2PSHIP_CONF_STARTUP_SCRIPTS);
#endif
#ifdef CONFIG_SIP_ENABLED
                        } else if (!strcmp(long_options[index].name, "proxy-iface")) {
				processor_config_set_string(config, P2PSHIP_CONF_SIPP_PROXY_IFACES, optarg);
                        } else if (!strcmp(long_options[index].name, "no-mp")) {
				processor_config_set_string(config, P2PSHIP_CONF_SIPP_MEDIA_PROXY, "no");
                        } else if (!strcmp(long_options[index].name, "tunnel-mp")) {
				processor_config_set_string(config, P2PSHIP_CONF_SIPP_TUNNEL_PROXY, "yes");
                        } else if (!strcmp(long_options[index].name, "force-mp")) {
				processor_config_set_string(config, P2PSHIP_CONF_SIPP_FORCE_PROXY, "yes");
                        } else if (!strcmp(long_options[index].name, "allow-unknown")) {
				processor_config_set_string(config, P2PSHIP_CONF_IDENT_ALLOW_UNKNOWN_REGISTRATIONS, "yes");
                        } else if (!strcmp(long_options[index].name, "allow-untrusted")) {
				processor_config_set_string(config, P2PSHIP_CONF_IDENT_ALLOW_UNTRUSTED, "yes");
#endif
                        } else if (!action && !strcmp(long_options[index].name, "list-ca")) {
				action = ACTION_LIST_CA;
                        } else if (!action && !strcmp(long_options[index].name, "remove-ca")) {
				action = ACTION_REMOVE_CA;
				if (!action_param) action_param = strdup(optarg);
                        } else if (!action && !strcmp(long_options[index].name, "import-ca")) {
				action = ACTION_IMPORT_CA;
				if (!action_param) action_param = strdup(optarg);
			} else if (!action && !strcmp(long_options[index].name, "list")) {
				action = ACTION_LIST;
                        } else if (!action && !strcmp(long_options[index].name, "remove")) {
				action = ACTION_REMOVE;
				if (!action_param) action_param = strdup(optarg);
                        } else if (!action && !strcmp(long_options[index].name, "import")) {
				action = ACTION_IMPORT;
				if (!action_param) action_param = strdup(optarg);
                        } else if (!strcmp(long_options[index].name, "idents")) {
				processor_config_set_string(config, P2PSHIP_CONF_IDENTS_FILE, optarg);
                        } else if (!strcmp(long_options[index].name, "log")) {
				processor_config_set_string(config, P2PSHIP_CONF_LOG_FILE, optarg);
#ifdef CONFIG_BROADCAST_ENABLED
                        } else if (!strcmp(long_options[index].name, "bc-addr")) {
				processor_config_set_string(config, P2PSHIP_CONF_BC_ADDR, optarg);
#endif
#ifdef CONFIG_OPENDHT_ENABLED
                        } else if (!strcmp(long_options[index].name, "opendht")) {
				processor_config_set_string(config, P2PSHIP_CONF_OPENDHT_PROXY, optarg);
#endif
#ifdef CONFIG_HIP_ENABLED
                        } else if (!strcmp(long_options[index].name, "list-hits")) {
				action = ACTION_LIST_HITS;
                        } else if (!strcmp(long_options[index].name, "rvs")) {
				processor_config_set_string(config, P2PSHIP_CONF_RVS, optarg);
                        } else if (!strcmp(long_options[index].name, "provide-rvs")) {
				processor_config_set_string(config, P2PSHIP_CONF_PROVIDE_RVS, "yes");
#endif
#ifdef CONFIG_WEBCONF_ENABLED
                        } else if (!strcmp(long_options[index].name, "webconf")) {
				processor_config_set_string(config, P2PSHIP_CONF_WEBCONF_SS, optarg);
#endif
			} else {
				c  = '?';
			}
		}

                switch (c) {    
                case 0:
                        /* already processed */
                        break;
                case 'v':
                        if (p2pship_log_level > -1)
                                p2pship_log_level++;
                        break;
                case 'q':
                        flag_quiet = 1;
                        p2pship_log_level = -1;
                        break;
                case 'D':
			log_to_file = 1;
			processor_config_set_string(config, P2PSHIP_CONF_DAEMON, "yes");
                        break;
                case 'c':
                        conf_file = optarg;
			processor_config_set_string(config, P2PSHIP_CONF_CONF_FILE, conf_file);
                        break;
                case 'i':
			processor_config_set_string(config, P2PSHIP_CONF_IFACES, optarg);
                        break;
#ifdef CONFIG_SIP_ENABLED
                case 'p':
                        if (sscanf(optarg, "%u", &tmp) != 1) {
                                USER_ERROR("Invalid port %s\n", optarg);
                                return 1;
                        } else {
				processor_config_set_int(config, P2PSHIP_CONF_SIPP_PROXY_PORT, tmp);
			}
                        break;
#endif
                case 's':
                        if (sscanf(optarg, "%u", &tmp) != 1) {
                                USER_ERROR("Invalid port %s\n", optarg);
                                return 1;
                        } else {
				processor_config_set_int(config, P2PSHIP_CONF_SHIP_PORT, tmp);
			}
                        break;
                case 'V':
                        print_version();
                        return 0;
		case 'R':
			load_autoreg = 1;
			break;
		case 'r':
			processor_config_set_string(config, P2PSHIP_CONF_AUTOREG_FILE, optarg);
			break;
		case 'L':
			log_to_file = 1;
			break;
                case 'h':
                case '?':
                default:
                        print_version();
                        print_usage();
                        return 1;
                }
        }
        
        if (!flag_quiet)
                print_version();
     
        /* 1. load the defaults (done already), 2. load the conf file, 3. put on the manual overrides */
	/* ensure that we have a config file! */
	if (ship_ensure_file(conf_file, "# Autocreated\n\n") || 
	    processor_config_load(config2, conf_file)) {
		USER_ERROR("Error processing config file %s\n", conf_file);
		goto err;
	}
        
        if (processor_config_transfer(config2, config)) {
                USER_ERROR("Error processing configs\n");
                goto err;
        }

	/* transfer */
	processor_config_free(config);
	config = config2;
	config2 = NULL;

	/* ok, ready to rock! */
	processor_config_ensure_configs(config);
	if (log_to_file) {
		p2pship_log_file = processor_config_string(config, P2PSHIP_CONF_LOG_FILE);
	}

#ifdef CONFIG_START_GTK
	if (!g_thread_supported())
		g_thread_init(NULL);
	gdk_threads_init();
	gdk_threads_enter();
	gtk_init(&argc, &argv);
#endif

#ifdef CALL_DEBUG
	calldebug_init();
#endif
	/* mark starttime for uptime calcs */
	time(&p2pship_start);

	/* register each modules */
	ASSERT_ZERO(processor_init(config), err);
#ifdef CONFIG_HIP_ENABLED
	hipapi_register();
#endif
#ifdef CONFIG_SIP_ENABLED
	sipp_register();
#endif
	ident_addr_register();
	ident_register();
#ifdef CONFIG_WEBCONF_ENABLED
	webconf_register();
#endif
#ifdef CONFIG_EXTAPI_ENABLED
	extapi_register();
#endif
#ifdef CONFIG_WEBCACHE_ENABLED
	webcache_register();
#endif
	resourceman_register();
	olclient_register();
	conn_register();
	netio_register();
	netio_events_register();
	netio_ff_register();
	netio_man_register();
	netio_http_register();
	ui_register();
	ui_stdin_register();
	processor_init_module("ui_stdin", config);
	
#ifdef CONFIG_DBUS_ENABLED
	dbus_register();
#endif

	if (!console_only) {
#ifdef CONFIG_GTKUI_ENABLED
		ui_gtk_register();
		processor_init_module("ui_gtk", config);
#endif
	}
	addrbook_register();
#ifdef CONFIG_PYTHON_ENABLED
	pymod_register();	
#endif

#ifdef CONFIG_MEDIA_ENABLED
	media_register();
#endif
	/* check what we actually should do */
	switch (action) {
	case ACTION_LIST_CA: { /* list ca */
		if (processor_init_module("ident", config)) {
			USER_ERROR("Error initializing system\n");
		} else {
			ident_data_print_cas(ident_get_cas());
		}
		break;
	}

	case ACTION_REMOVE_CA: { /* remove ca */
		if (processor_init_module("ident", config)) {
			USER_ERROR("Error initializing system\n");
		} else {
			ident_remove_ca(action_param);
		}
		break;
	}

	case ACTION_LIST: { /* list */
		if (processor_init_module("ident", config)) {
			USER_ERROR("Error initializing system\n");
		} else {
			ident_data_print_idents(ident_get_identities());
		}
		break;
	}

	case ACTION_REMOVE: { /* remove */
		if (processor_init_module("ident", config)) {
			USER_ERROR("Error initializing system\n");
		} else {
			ident_remove_ident(action_param);
		}
		break;
	}

	case ACTION_IMPORT:  /* import */
	case ACTION_IMPORT_CA: { /* import ca */
		if (processor_init_module("ident", config)) {
			USER_ERROR("Error initializing system\n");
		} else {
			if (ident_import_file(action_param, 1)) {
				USER_ERROR("Error loading processing file %s\n", action_param);
			}
		}
		break;
	}
		
#ifdef CONFIG_HIP_ENABLED
	case ACTION_LIST_HITS: {
		if (processor_init_module("hipapi", config)) {
			USER_ERROR("Error initializing system\n");
		} else {
			hipapi_list_hits();
		}
		break;
	}
#endif
	case ACTION_NONE:
	default: {
		struct rlimit rl;
		int result;
		
#ifdef CONFIG_PYTHON_ENABLED
		if (processor_config_is_true(config, P2PSHIP_CONF_START_SHELL))
			processor_config_set_false(config, P2PSHIP_CONF_DAEMON);
#endif
		/* go daemon (..whee!) */
		if (processor_config_is_true(config, P2PSHIP_CONF_DAEMON)) {
			if (fork())
				goto err;			
		}
		
		/* check the stack size */
		if (!(result = getrlimit(RLIMIT_STACK, &rl))) {
			const rlim_t stacksize = 32L * 1024L * 1024L;
			if (rl.rlim_cur < stacksize) {
				LOG_INFO("increasing stack size to %d\n", stacksize);
				rl.rlim_cur = stacksize;
				if (setrlimit(RLIMIT_STACK, &rl)) {
					LOG_ERROR("could not set new stack size!\n");
				}
			}
		} else {
			LOG_ERROR("error checking stack size\n");
		}

		if (processor_init_modules(config) ||
		    (load_autoreg && ident_autoreg_load())) {
			USER_ERROR("Error initializing system\n");
		} else {
#ifdef REMOTE_DEBUG
			ship_remote_debug_init(config);
#endif
			/* start the main loop, blocks */
#ifdef REF_DEBUG2
			//			processor_tasks_add_periodic(ship_debug_reportref, 10000);
#endif
			processor_run();
		}
	}
	}
        
	ret = 0;
 err:
#ifdef REF_DEBUG2
	ship_debug_reportref();
#endif
	processor_close();
	freez(action_param);
	processor_config_free(config);
	processor_config_free(config2);

#ifdef LOCK_DEBUG
	debug2_close();
#endif
#ifdef REF_DEBUG2
	ship_debug_closeref();
#endif

	xmlCleanupThreads();
        if (!ret && !flag_quiet)
                USER_ERROR("ending ok\n");
        return ret;
}
