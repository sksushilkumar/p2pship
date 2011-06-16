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
#include "netio_events.h"
#include "processor.h"
#include "ship_utils.h"
#include "ship_debug.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "ident.h"
#include "netio.h"
#include "conn.h"

static int i4_route = -1;
static ship_list_t *oldips = 0;

int 
netio_events_open(unsigned proto, unsigned group)
{
        int s = -1;
        struct sockaddr_nl addr;
	
	ASSERT_TRUE(((s = socket(AF_NETLINK, SOCK_RAW, proto)) != -1), err);
        memset((void *)&addr, 0, sizeof(addr));
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = getpid();
        addr.nl_groups = group;
        if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                close(s);
		s = -1;
	}
 err:
        return s;
}

static int
netio_events_ip_changed()
{
	ship_list_t *ips = 0;
	char *ptr[1];
	int ret = 1;
	void *ptr1 = 0, *ptr2 = 0;
	addr_t *a1, *a2;

	ptr[0] = "all";
	ASSERT_TRUE(ips = ship_list_new(), err);
	conn_getips(ips, ptr, 1, 0);
	
	if (ship_list_length(oldips) != ship_list_length(ips))
		goto end;

	/* these shuold be in the same order .. */
	ret = 0;
	while (!ret && 
	       (a1 = ship_list_next(oldips, &ptr1)) &&
	       (a2 = ship_list_next(ips, &ptr2))) {

		if (ident_addr_cmp(a1, a2))
			ret = 1;
	}
 end:
	ship_list_empty_free(oldips);
	ship_list_free(oldips);
	oldips = ips;
	ips = 0;
 err:
	ship_list_empty_free(ips);
	ship_list_free(ips);
	return ret;
		
}

static void 
netio_events_read(int s, char *data, ssize_t datalen)
{
	/* check whether any addresses have actually changed! */
	if (netio_events_ip_changed())
		processor_event_generate_pack("net_ip_changed", NULL);
	else
		LOG_DEBUG("skipping net event as no ip has changed!\n");
}



int 
netio_events_init(processor_config_t *config)
{
	int ret = -1;
	LOG_INFO("Initing the netio_events module\n");
	ASSERT_TRUE((i4_route = netio_events_open(NETLINK_ROUTE, 
						  RTMGRP_LINK | RTMGRP_IPV6_IFADDR | 
						  IPPROTO_IPV6 | RTMGRP_IPV4_IFADDR | 
						  IPPROTO_IP)) != -1, err);
	ASSERT_ZERO(netio_read(i4_route, netio_events_read), err);
	ASSERT_TRUE(oldips = ship_list_new(), err);
	netio_events_ip_changed();

	ret = 0;
 err:
	return ret;
}

void 
netio_events_close()
{
	netio_close_socket(i4_route);
	ship_list_empty_free(oldips);
	ship_list_free(oldips);
}

/* the netio_events register */
static struct processor_module_s processor_module = 
{
	.init = netio_events_init,
	.close = netio_events_close,
	.name = "netio_events",
	.depends = "netio",
};

/* register func */
void
netio_events_register() {
	processor_register(&processor_module);
}
