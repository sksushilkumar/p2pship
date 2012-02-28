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
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include "ship_debug.h"
#include "processor.h"
#include "ident.h"
#include "conn.h"

#ifdef CONFIG_HIP_ENABLED
#include "hipapi.h"

/* the RVS's we are registered to */
static ship_list_t *rvs_arr = NULL;

/* how often the rvs registration should be updated, in seconds */
#define RVS_UPDATE_PERIOD 60

static int hipapi_update_rvs_registration();
static int hipapi_update_hip_config();

static int hipconf(const char *template, ...);

static int 
hipapi_update_hip_state(void *data)
{
	hipapi_update_rvs_registration();
	hipapi_update_hip_config();
	return 0;
}

static void
hipapi_cb_config_update(processor_config_t *config, char *k, char *v)
{
	hipapi_update_hip_state(NULL);
}

/* checks whether the hipd is running, and if not, tries to start
   it. */
void
hipapi_check_hipd()
{
	static addr_t ownhit;
	
	if (processor_config_bool(processor_get_config(), P2PSHIP_CONF_AUTOSTART)
	    && hipapi_gethit(&ownhit)) {
		int r = 0;
		char *paths[] = { "/sbin", "/bin", "/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin", 0 };
		char hipd_path[50] = "";
		
		// locate hipd
		for (r = 0; paths[r]; r++) {
			struct stat sdata;
			strcpy(hipd_path, paths[r]);
			strcat(hipd_path, "/hipd");
			
			
			if (stat(hipd_path, &sdata))
				continue;
			break;
		}

		if (strlen(hipd_path)) {
			char *args[] = { "hipd", "-kb", NULL };
			
			LOG_INFO("trying to start HIP from %s..\n", hipd_path);

			/*
			strcat(hipd_path, " -kb");
			r = system(hipd_path);
			if (r) {
				LOG_ERROR("could not start hip, code %d (%d): %s\n", r, errno, strerror(errno));
			} else {
				LOG_INFO("started hipd\n");
			}
			*/
			
			if ((r = vfork()) < 0) {
				LOG_ERROR("could not fork!\n");
			} else if (r) {
				LOG_INFO("started hipd as pid %d\n", r);
				waitpid(r, NULL, 0);
				LOG_INFO("hipd subprocess done\n", r);
			} else {
				r = execv(hipd_path, args);
				if (r) {
					LOG_ERROR("could not start hip(%d): %s\n", errno, strerror(errno));
				}
				LOG_INFO("hipd exiting\n");
				_exit(0);
			}
			hipapi_update_hip_config();

		} else {
			LOG_WARN("could not find hipd!\n");
		}
	}
}

static void
hipapi_cb_events(char *event, void *data, ship_pack_t *eventdata)
{
	if (str_startswith(event, "net_")) {
		hipapi_update_hip_state(NULL);
	}
}

/* inits the hipapi */
int 
hipapi_init(processor_config_t *config)
{
	static addr_t ownhit;
        int ret = -1;
	LOG_INFO("Initing the hipapi module..\n");
	
	if (hipapi_gethit(&ownhit) && !processor_config_bool(config, P2PSHIP_CONF_ALLOW_NONHIP)
	    && !processor_config_bool(config, P2PSHIP_CONF_AUTOSTART)) {
		USER_ERROR("Error retrieving HITs. Please check that hipd is running.\n");
		// goto err; // kill (do not!)
	}

	ASSERT_TRUE(rvs_arr = ship_list_new(), err);

	/* hipd config */
	hipapi_update_hip_config();

	/* rvs & nat? */
	if (hipapi_update_rvs_registration()) {
		LOG_WARN("Error initializing RVS registration\n");
	}

	ASSERT_ZERO(processor_tasks_add_periodic(hipapi_update_hip_state, NULL, RVS_UPDATE_PERIOD*1000), err);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_NAT_TRAVERSAL, hipapi_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_RVS, hipapi_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_AUTOSTART, hipapi_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_PROVIDE_RVS, hipapi_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_HIP_SHOTGUN, hipapi_cb_config_update);

 	ASSERT_ZERO(processor_event_receive("net_*", 0, hipapi_cb_events), err);
	
	ret = 0;
err:
        return ret;
}

/* closes */
void 
hipapi_close()
{
        LOG_INFO("closing the hipapi module\n");
	if (rvs_arr) {
		ship_list_empty_free(rvs_arr);
		ship_list_free(rvs_arr);
		rvs_arr = NULL;
	}

}

static int
hipapi_update_hip_config()
{
	char **tokens = NULL; 
	int len = 0;
	ship_list_t *ips = NULL;
	char *str = NULL;

	if (processor_config_is_true(processor_get_config(), P2PSHIP_CONF_PROVIDE_RVS))
		if (hipapi_init_rvs(1)) {
			LOG_WARN("Error initializing RVS provisioning\n");
		} else {
			char *inifs = NULL;
			addr_t *addr = NULL;
			addr_t hit;

			hipapi_gethit(&hit);
			
			ASSERT_ZERO(processor_config_get_string(processor_get_config(), P2PSHIP_CONF_RVS_IFACES, &inifs), err);
			ASSERT_ZERO(ship_tokenize_trim(inifs, strlen(inifs), &tokens, &len, ','), err);
			ASSERT_ZERO(conn_validate_ifaces(tokens, len), err);

			ASSERT_TRUE(ips = ship_list_new(), err);
			conn_getips(ips, tokens, len, 0);
			while ((addr = ship_list_pop(ips))) {
				if (str) {
					ASSERT_ZERO(append_str2(&str, ";"), err);
				}
				ASSERT_ZERO(append_str2(&str, hit.addr), err);
				ASSERT_ZERO(append_str2(&str, ","), err);
				ASSERT_ZERO(append_str2(&str, addr->addr), err);
			}

			ident_set_global_service_param(SERVICE_TYPE_RELAY, "public_rvs", str);
		}
	else
		ident_remove_global_service_param(SERVICE_TYPE_RELAY, "public_rvs");
 err:
	ship_list_empty_free(ips);
	ship_list_free(ips);
	freez(str);
	
	hipapi_init_shotgun((processor_config_is_true(processor_get_config(), P2PSHIP_CONF_HIP_SHOTGUN)? 1 : 0));
	ship_tokens_free(tokens, len);
	return 0;
}


/* adds new rvs registrations from a line of rvs-hits in the format of

   line := <rvs-hit>[;<rvs-hit>]*
   rvs-hit := <ip> | <hit>,<ip>
*/
static int
hipapi_add_single_rvs_line(const char *line, int *total)
{
	char **tokens = 0;
	int toklen = 0;
	addr_t *rvs = 0;
	int c = 0;
	
	ASSERT_ZERO(ship_tokenize(line, strlen(line), &tokens, &toklen, ';'), err);
	for (c = 0; c < toklen; c++) {
		char *loc = strchr(tokens[c], ','), *hit = tokens[c];
		
		/* if ',' is missing, then assume only an address, no HIT */
		if (!loc) {
			loc = hit;
			hit = 0;
		} else {
			*loc = 0;
			loc++;
		}
		
		/* create rvs arr */
		ASSERT_TRUE(rvs = (addr_t*)mallocz(2*sizeof(addr_t)), err);
		ASSERT_ZERO((hit && ident_addr_str_to_addr(hit, &(rvs[0]))) ||
			    ident_addr_str_to_addr(loc, &(rvs[1])), err);
		
		if (strlen(rvs[1].addr)) {
			if (hipapi_register_to_rvs(&(rvs[0]), &(rvs[1]), 1)) {
				LOG_WARN("Error registering to RVS! You might not have the privileges. Continuing as if it succeeded\n");
			}
			(*total)++;
			ship_list_add(rvs_arr, rvs);
			rvs = 0;
		} else
			freez(rvs);
	}
	return 0;
 err:
	return -1;
}

static int 
hipapi_update_rvs_registration()
{
	char *str = 0;
	int ret = -1;
	char **tokens = 0;
	int toklen = 0;
	addr_t *rvs = 0;
	int natmode;
	ship_list_t *old_rvs = NULL;
	ship_list_t *peer_rvs = NULL;
	int total = 0;
	
	ASSERT_ZERO(processor_config_get_enum(processor_get_config(), P2PSHIP_CONF_NAT_TRAVERSAL, &natmode), err);
	if (hipapi_set_udp_encap(natmode)) {
		LOG_WARN("Error activating UDP encapsulation\n");
	}

	ASSERT_TRUE(old_rvs = ship_list_new(), err);
	ASSERT_TRUE(peer_rvs = ship_list_new(), err);
	ship_lock(rvs_arr);

	/* store the old ones so we know from which ones we should unregister */
	while ((rvs = ship_list_pop(rvs_arr))) {
		ship_list_add(old_rvs, rvs);
	}
	
	/* register to the RVS's we have specified */
	if ((str = processor_config_string(processor_get_config(), P2PSHIP_CONF_RVS)))
		hipapi_add_single_rvs_line(str, &total);

	/* get RVS information from known registration packets.. */
	ident_find_foreign_reg_service_params(SERVICE_TYPE_RELAY, "public_rvs", peer_rvs);
	while ((str = ship_list_pop(peer_rvs))) {
		hipapi_add_single_rvs_line(str, &total);
		freez(str);
	}

	/* check which ones are still present .. */
	while ((rvs = ship_list_pop(old_rvs))) {
		void *ptr = NULL;
		addr_t *newrvs = 0;
		int found = 0;
		
		while (!found && (newrvs = ship_list_next(rvs_arr, &ptr))) {
			if (!ident_addr_cmp(&(rvs[0]), &(newrvs[0])) &&
			    !ident_addr_cmp(&(rvs[1]), &(newrvs[1]))) {
				LOG_DEBUG("RVS at %s still exists, skipping..\n", rvs[1].addr);
				found = 1;
			}
		}
			
		if (!found) {
			LOG_DEBUG("RVS at %s is old, unregistering\n", rvs[1].addr);
			hipapi_register_to_rvs(&(rvs[0]), &(rvs[1]), 0);
			freez(rvs);
		}
	}

	LOG_DEBUG("Registered to %d RVSs\n", total);
	ret = 0;
 err:
	freez(rvs);
	ship_tokens_free(tokens, toklen);
	ship_unlock(rvs_arr);
	ship_list_empty_free(old_rvs);
	ship_list_free(old_rvs);
	ship_list_empty_free(peer_rvs);
	ship_list_free(peer_rvs);
	return ret;
}


#define HIPCONF_TRACKING

static int
hipconf(const char *template, ...)
{
	int p = 0, ret = -1, arrlen = 0;
	char **arr = 0;	
	va_list ap;

#ifdef HIPCONF_TRACKING
	char *buf = NULL;
#endif
	
	arrlen = strlen(template)+2;
	ASSERT_TRUE(arr = mallocz(arrlen * sizeof(char*)), err);
	ASSERT_TRUE(arr[0] = strdup("hipconf"), err);
	ASSERT_TRUE(arr[1] = strdup("daemon"), err);
	va_start(ap, template);
	
	while (p < strlen(template)) {
		char *str = 0;
		
		switch (template[p]) {
		case 's':
			ASSERT_TRUE(str = strdup(va_arg(ap, char*)), err);
			break;
		case 'i':
			ASSERT_TRUE(str = mallocz(15), err);
			sprintf(str, "%d", va_arg(ap, int));
			break;
		default:
			ASSERT_TRUES(0, err, "Invalid arg: %c", template[p]);
			break;
		}

		arr[p+2] = str;
		p++;
	}
	va_end(ap);

#ifdef HIPCONF_TRACKING
	for (p = 0; p < arrlen; p++) {
		append_str2(&buf, arr[p]);
		append_str2(&buf, " ");
	}
	LOG_INFO(">> sending to hipconf: %s\n", buf);
#endif
	ret = hip_do_hipconf(arrlen, arr, 1);
 err:
	freez_arr(arr, arrlen);
#ifdef HIPCONF_TRACKING
	LOG_DEBUG("<< -- hipconf sent with %d\n", ret);
	freez(buf);
#endif
	return ret;
}


/* registers to the given RVS */
int
hipapi_register_to_rvs(addr_t *rvshit, addr_t *rvsloc, int add)
{
	int ret = -1;

	if (strlen(rvshit->addr)) {
		if (add)
			ret = hipconf("sssssi", "add", "server", "rvs", rvshit->addr, rvsloc->addr, RVS_UPDATE_PERIOD*2);
		else
			ret = hipconf("sssss", "del", "server", "rvs", rvshit->addr, rvsloc->addr);
	} else {
		if (add)
			ret = hipconf("ssssi", "add", "server", "rvs", rvsloc->addr, RVS_UPDATE_PERIOD*2);
		else
			ret = hipconf("ssss", "del", "server", "rvs", rvsloc->addr);
	}
	
	if (ret) {
		LOG_WARN("could not %s registration to RVS %s at %s\n", (add? "add": "del"), rvshit->addr, rvsloc->addr);
	} else {
		LOG_DEBUG("Update registration '%s' to rvs hit '%s', addr '%s'\n",
			  (add? "add":"del"), rvshit->addr, rvsloc->addr);
	}
	return ret;
}

/* offer RVS services for others */
int
hipapi_init_rvs(int on)
{
	return hipconf("sss", (on? "add":"del"), "service", "rvs");
}

/* turn shotgun mode on */
int
hipapi_init_shotgun(int on)
{
	return hipconf("ss", "shotgun", (on? "on":"off"));
}

/* turns on udp encapsulation for hip */
int
hipapi_set_udp_encap(int mode)
{
	char *types[3] = { "none", "plain-udp", "ice-udp" };
	ASSERT_TRUE(mode > -1 && mode < 3, err);
	return hipconf("ss", "nat", types[mode]);
 err:
	return -1;
}

/* Checks whether we have a working link to the given HIT. */
int
hipapi_has_linkto(addr_t *remote_hit)
{
	static const char *tcp6_file = "/proc/net/tcp6";
	int ret = 0;
	unsigned long rxq, txq, time_len, retr, inode;
	int local_port, rem_port, d, state, uid, timer_run, timeout;
	char rem_addr[128], local_addr[128], more[512];

	/* todo: a better way to do this! Currently we just red the
	   tcp6 table, trying to find an active connection to the
	   HIT */

	/* load file .. */
	FILE *f = fopen(tcp6_file, "r");
	if (f) {
		char *buf = NULL;
		size_t len = 0;
		ssize_t got = 0;
		while (!ret && (got = getline(&buf, &len, f)) > -1) {
			addr_t addr;
			struct in6_addr in6;
			int num;

			num = sscanf(buf,
				     "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %512s\n",
				     &d, local_addr, &local_port, rem_addr, &rem_port, &state,
				     &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode, more);
			if (num > 10) {
				
				/* Demangle what the kernel gives us */
				sscanf(rem_addr, "%08X%08X%08X%08X",
				       &in6.s6_addr32[0], &in6.s6_addr32[1],
				       &in6.s6_addr32[2], &in6.s6_addr32[3]);
				inet_ntop(AF_INET6, &in6, addr.addr, sizeof(addr.addr));
				
				if (!strcmp(addr.addr, remote_hit->addr))
					ret = 1;
			}
		}
		freez(buf);
		fclose(f);
	}
	return ret;
}


static int
hipapi_map_hit_ip(addr_t *hit, addr_t *loc)
{
	addr_t l2;
	ASSERT_ZERO(ident_addr_str_to_addr_lookup(loc->addr, &l2), err);
	LOG_INFO("Mapping HIT %s to IP address %s (was: %s)\n", 
		 hit->addr, l2.addr, loc->addr);
	return hipconf("ssss", "add", "map", hit->addr, l2.addr);
 err:
	return -1;
}	

/* establishes, or tries, a connection to the given hit on the give
   ips / rvss. currently just maps the hip to the ip */
int
hipapi_establish(addr_t *hit, ship_list_t *ips, ship_list_t *rvs)
{
	addr_t *loc = NULL;
	void *ptr = NULL;

	/* we should check here also if we have an SA for this HIT. If
	   so, we should check whether that SA is active (we have
	   active conn or mp using it, or if possible some
	   kernel-level info on how much is going through it). If the
	   SA seems inactive, we should reset it - just delete
	   it. This will force a new bex, fixing stale SA-problems. */

	/* for now, we just map the first ip to the hit and let the
	   bex go passively. in the future we should actually try the
	   different combinations and so on.. */
	
	if (processor_config_is_true(processor_get_config(), P2PSHIP_CONF_HIP_SHOTGUN)) {
		hipapi_init_shotgun(1);

		/* map first raw ips.. */
		while ((loc = ship_list_next(ips, &ptr))) {
			if (loc->port)
				continue;
			ASSERT_ZERO(hipapi_map_hit_ip(hit, loc), err);
		}
		
		ptr = 0;
		while ((loc = ship_list_next(rvs, &ptr))) {
			ASSERT_ZERO(hipapi_map_hit_ip(hit, loc), err);
		}
	} else {
		/* use the rvs if available, else first non-transport ip */
		if (!rvs || !(loc = ship_list_first(rvs))) {
			while (ips && !loc && (loc = ship_list_next(ips, &ptr))) {
				if (loc->port)
					loc = NULL;
			}
		}
		ASSERT_TRUES(loc, err, "No IP address to map HIT to!\n");
		ASSERT_ZERO(hipapi_map_hit_ip(hit, loc), err);
	}
	sleep(1); // hmm..
	return 0;
 err:
	return -1;
}

static void 
parse_if_inet6_entry(void *data, int lc, char *key, char *value, char *line)
{
	addr_t *addr = data;
	
	/* 32 chars long, should start with 2001001! */
	if (!strlen(addr->addr) && strstr(line, "2001001") == line &&
	    strlen(line) > 32 && line[32] == ' ') {
		strncpy(addr->addr, line, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+4, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+8, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+12, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+16, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+20, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+24, 4);
		strcat(addr->addr, ":");
		strncat(addr->addr, line+28, 4);
	}
}

static void 
parse_if_inet6(void *data, int lc, char *key, char *value, char *line)
{
	ship_list_t *list = data;
	addr_t addr;
	
	bzero(&addr, sizeof(addr));
	parse_if_inet6_entry(&addr, lc, key, value, line);
	if (strlen(addr.addr)) {
		addr_t *addr2 = mallocz(sizeof(addr_t));
		if (addr2) {
			addr2->family = AF_INET6;
			addr2->port = 0;
			addr2->type = IPPROTO_NONE;
			strcpy(addr2->addr, addr.addr);
			ship_list_add(list, addr2);
		}
	}
}

/* Returns true/false whether a HIP daemon is running */
int 
hipapi_hip_running()
{
	addr_t a;
	return !hipapi_gethit(&a);
}

/* retrieves my own HITs that I use */
int 
hipapi_gethit(addr_t *addr)
{
	/* read /proc/net/if_inet6. Use the first HIT found! */
	bzero(addr, sizeof(*addr));
	if (!ship_read_file("/proc/net/if_inet6", addr,
			    parse_if_inet6_entry, NULL) &&
	    strlen(addr->addr)) {

		addr->family = AF_INET6;
		addr->port = 0;
		addr->type = IPPROTO_NONE;
		return 0;
	}
	return -1;
}

/* checks whether the given address is a hit or something else */
int 
hipapi_addr_is_hit(addr_t *addr)
{
	if (!addr)
		return 0;
	
	LOG_DEBUG("is %s a HIT?\n", addr->addr);
	if (((addr->family == AF_INET6) && !strncmp("2001:001", addr->addr, 8)) ||
	    ((addr->family == AF_INET) && !strncmp("1.", addr->addr, 2)))
		return 1;
	else
		return 0;
}


/* retrieves all available hits as addr_t's */
int
hipapi_getallhits(ship_list_t *list)
{
	/* read /proc/net/if_inet6 */
	return ship_read_file("/proc/net/if_inet6", list,
			      parse_if_inet6, NULL);
}

/* retrieves all rvs we are registered to as addr_t's */
int
hipapi_getrvs(ship_list_t *list)
{
	int i;
	ship_lock(rvs_arr);
	for (i=0; rvs_arr && i < ship_list_length(rvs_arr); i++) {
		addr_t *r, *copy;
		r = ship_list_get(rvs_arr, i);
		if ((copy = mallocz(sizeof(addr_t)))) {
			memcpy(copy, &r[1], sizeof(addr_t));
			ship_list_add(list, copy);
		}
	}
	ship_unlock(rvs_arr);
	return 0;
}

int
hipapi_list_hits()
{
	ship_list_t *hits = NULL;
	int i, ret = -1, us;
	addr_t defhit;
	
	ASSERT_TRUE(hits = ship_list_new(), err);
		
	ASSERT_ZERO(hipapi_gethit(&defhit), err);
	ASSERT_ZERO(hipapi_getallhits(hits), err);
	
	USER_PRINT("HITS (total %d):\n", ship_list_length(hits));
	us = 0;
	for (i=0; i < ship_list_length(hits); i++) {
		addr_t *hit = ship_list_get(hits, i);		
		if (!ident_addr_cmp(hit, &defhit)) {
			USER_PRINT("\t* %s\n", hit->addr);
			us = 1;
		} else
			USER_PRINT("\t  %s\n", hit->addr);
	}

	if (!us) {
		USER_PRINT("\t* %s\n", defhit.addr);
	}
	
	ret = 0;
 err:
	if (ret) {
		USER_ERROR("Error retrieving HITs. Please check that hipd is running.\n");
	}
	
	if (hits) {
		ship_list_empty_free(hits);
		ship_list_free(hits);
	}
       
	return ret;
}

/* the hipapi register */
static struct processor_module_s processor_module = 
{
	.init = hipapi_init,
	.close = hipapi_close,
	.name = "hipapi",
	.depends = "ident,netio,netio_ff",
};

/* register func */
void
hipapi_register() {
	processor_register(&processor_module);
}

int 
hipapi_clear_sas()
{
	return hipconf("ss", "rst", "all");
}

/* this function creates a mapping from a HIT to a locator so that the
   HIT can be used as-is when sending packets. The HIT must be tied to
   a specific peer (the aor given) meaning that the locators will be
   looked up only from that peer's registration package.

   If the HIT doesn't belong to the peer, locator missing or something
   else goes wrong, it returns an errorcode
*/
int
hipapi_create_peer_hit_locator_mapping(char *sip_aor, addr_t *hit) 
{
	int ret = -1;
	/* dtn: get the hip transport addresses where the locators are */
	reg_package_t *reg = 0;
	void *ptr = 0;
	addr_t *tmp = 0;

	if (hipapi_has_linkto(hit))
		return 0;
	

	/* we should do this async actually (fetching the reg package)! */
	LOG_INFO("Should map %s's HIT %s to a locator\n", sip_aor, hit->addr);
	ASSERT_TRUE(reg = ident_find_foreign_reg(sip_aor), err);
	
	/* Assure that the HIT really belongs to this person */
	while (!tmp && (tmp = (addr_t*)ship_list_next(reg->hit_addr_list, &ptr))) {
		if (strcmp(tmp->addr, hit->addr))
			tmp = NULL;
	}
	ASSERT_TRUE(tmp, err);
	
	/* establish .. */
	ASSERT_ZERO(hipapi_establish(hit, reg->ip_addr_list, reg->rvs_addr_list), err);
	ret = 0;
 err:
	if (reg) 
		ship_unlock(reg);
	return ret;
}

#endif
