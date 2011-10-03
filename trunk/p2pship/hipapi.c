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

#ifdef CONFIG_HIP_ENABLED
#include "hipapi.h"

/* the RVS's we are registered to */
static ship_list_t *rvs_arr = NULL;

/* how often the rvs registration should be updated */
#define RVS_UPDATE_PERIOD 600

static int hipapi_update_rvs_registration();


static void
hipapi_cb_config_update(processor_config_t *config, char *k, char *v)
{
	hipapi_update_rvs_registration();
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
		} else {
			LOG_INFO("could not find hipd..\n");
		}
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

	/* rvs & nat? */

	if (processor_config_is_true(config, P2PSHIP_CONF_PROVIDE_RVS))
		if (hipapi_init_rvs(1)) {
			LOG_WARN("Error initializing RVS provisioning\n");
		}

	ASSERT_TRUE(rvs_arr = ship_list_new(), err);
	if (hipapi_update_rvs_registration()) {
		LOG_WARN("Error initializing RVS registration\n");
	}
	ASSERT_ZERO(processor_tasks_add_periodic(hipapi_update_rvs_registration, NULL, RVS_UPDATE_PERIOD*1000), err);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_NAT_TRAVERSAL, hipapi_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_RVS, hipapi_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_AUTOSTART, hipapi_cb_config_update);
	
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
hipapi_update_rvs_registration(void *data)
{
	char *str = 0;
	int ret = -1;
	char **tokens = 0;
	int toklen = 0;
	addr_t *rvs = 0;
	int c = 0;
	int natmode;
	
	ASSERT_ZERO(processor_config_get_enum(processor_get_config(), P2PSHIP_CONF_NAT_TRAVERSAL, &natmode), err);
	if (hipapi_set_udp_encap(natmode)) {
		USER_ERROR("Error activating UDP encapsulation\n");
		goto err;
	}

	ship_lock(rvs_arr);
	/* clear the rvs registrations */
	while ((rvs = ship_list_pop(rvs_arr))) {
		hipapi_register_to_rvs(&(rvs[0]), &(rvs[1]), 0);
		freez(rvs);
	}
	
	/* register to the RVS's we have specified */
	if ((str = processor_config_string(processor_get_config(), P2PSHIP_CONF_RVS)))
		ASSERT_ZERO(ship_tokenize(str, strlen(str), &tokens, &toklen, ';'), err);
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
			ship_list_add(rvs_arr, rvs);
			rvs = 0;
		} else
			freez(rvs);
	}
	ret = 0;
 err:
	freez(rvs);
	ship_tokens_free(tokens, toklen);
	ship_unlock(rvs_arr);
	return ret;
}

//#define HIPCONF_TRACKING
#ifdef HIPCONF_TRACKING
static int
hipconf(int len, char **arr, int sendonly)
{
	int ret = -1;
	
	LOG_DEBUG(">> sending hipconf: %s %s %s..\n", 
		  arr[0], (len > 0? arr[1]:""), (len > 1? arr[2]:""));
	ret = hip_do_hipconf(len, arr, sendonly);
	LOG_DEBUG("<< -- hipconf sent with %d\n", ret);
	return ret;
}
#else
#define hipconf(a, b, c) hip_do_hipconf(a, b, c)
#endif

/* registers to the given RVS */
int
hipapi_register_to_rvs(addr_t *rvshit, addr_t *rvsloc, int add)
{
	int ret = -1;
	char *arr[7] = { "hipconf", "add", "server", "rvs", "HIT", "IP", "3600" };
	int len = 7;
	
	char num[32];
	sprintf(num, "%d", RVS_UPDATE_PERIOD);
	
	if (!strlen(rvshit->addr)) {
		len--;
		arr[4] = rvsloc->addr;
	} else {
		arr[4] = rvshit->addr;
		arr[5] = rvsloc->addr;
	}
	
	if (!add) {
		arr[1] = "del";
		len--;
	} else
		arr[len-1] = num;
	
	ret = hipconf(len, arr, 1);
	if (ret) {
		LOG_WARN("could not %s register to RVS %s at %s\n", arr[1], rvshit->addr, rvsloc->addr);
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
	char *arr[4] = { "hipconf", "add", "service", "rvs"};
	if (!on)
		arr[1] = "del";	
	return hipconf(4, arr, 1);
}

/* turns on udp encapsulation for hip */
int
hipapi_set_udp_encap(int mode)
{
	char *arr[3] = { "hipconf", "nat", "plain-udp" };
	char *types[3] = { "none", "plain-udp", "ice-udp" };
	
	if (mode > -1 && mode < 3)
		arr[2] = types[mode];
	
	return hipconf(3, arr, 1);
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


/* establishes, or tries, a connection to the given hit on the give
   ips / rvss. currently just maps the hip to the ip */
int
hipapi_establish(addr_t *remote_hit, ship_list_t *ips, ship_list_t *rvs)
{
	int ret = -1;
	addr_t *loc = NULL;
	addr_t l2;

	/* we should check here also if we have an SA for this HIT. If
	   so, we should check whether that SA is active (we have
	   active conn or mp using it, or if possible some
	   kernel-level info on how much is going through it). If the
	   SA seems inactive, we should reset it - just delete
	   it. This will force a new bex, fixing stale SA-problems. */

	/* for now, we just map the first ip to the hit and let the
	   bex go passively. in the future we should actually try the
	   different combinations and so on.. */
	
	/* use the rvs if available */
	if (!rvs || !(loc = ship_list_first(rvs))) {
		ASSERT_TRUE(ips && (loc = ship_list_first(ips)), err);
	}

	ASSERT_ZERO(ident_addr_str_to_addr_lookup(loc->addr, &l2), err);
	LOG_INFO("Mapping HIT %s to IP address %s (was: %s)\n", 
		 remote_hit->addr, l2.addr, loc->addr);

	char *arr[5] = { "hipconf", "add", "map", remote_hit->addr, l2.addr };
	ret = hipconf(5, arr, 1);
 err:
	return ret;
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
	.depends = "netio,netio_ff",
};

/* register func */
void
hipapi_register() {
	processor_register(&processor_module);
}

int 
hipapi_clear_sas()
{
	char *arr[3] = { "hipconf", "rst", "all"};
	return hipconf(3, arr, 1);
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
