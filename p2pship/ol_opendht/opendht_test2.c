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
/* Teststub for the openDHT interface  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include "libhipopendht.h"
//#include "debug.h"
#include "ship_utils.h"
#include "ship_debug.h"

LOCK_DECL(lock);
COND_DECL(cond);

char *last_data = NULL;

/* default log level */
int p2pship_log_level = LOG_DEBUG;

void data_cb(char *key, char *data, int status)
{
        printf("got callback on key %s code %d.\ndata: %s\n", key, status, data);
        if (data)
                last_data = strdup(data);
        COND_WAKEUP(cond, lock);
}


int main(int argc, char *argv[])
{
/*     int s, ret, error; */
/*     /\* */
/*     struct in6_addr val_hit_addr; */
/*     struct in6_addr val_ip_addr; */
/*     char opendht[] = "opendht.nyuld.net"; */
/*     *\/ */
/*     char opendht[] = "planetlab1.diku.dk"; */
/*     char dht_response[1024]; */
/*     char dht_response2[1024]; */

/*     /\* Test values *\/   */
/*     char val_bogus[] = "BogusKey"; */
/*     char val_host[] = "testhostname"; */
/*     char val_hit[] = "2001:0071:7c97:a5b4:6c73:1b1b:081e:126d"; */
/*     char val_ip[] = "128.196.1.100"; */
/*     //    char host_addr[] = "planetlab1.diku.dk"; //"127.0.0.1"; /\* TODO change this to something smarter :) *\/ */
/*     char host_addr[] = "127.0.0.1"; /\* TODO change this to something smarter :) *\/ */

/*     LOCK_INIT(lock); */
/*     COND_INIT(cond); */


/*     printf("Starting to test the openDHT interface.\n"); */
/*     printf("Using test mapping\n'%s (FQDN) -> %s (HIT) -> %s (IP)'.\n", */
/*            val_host, val_hit, val_ip); */

/*     /\*!!!! put fqdn->hit !!!!*\/ */
/*     s = opendht_init(opendht, 5851, NULL); */
/*     if (s < 0) exit(0); */
/*     ret = 0; */
    
/*     printf("Put packet (fqdn->hit)  ...\n"); */
/*     SYNCHRONIZE(lock, { */
/*             ret = opendht_put((unsigned char *)val_host, */
/*                               (unsigned char *)val_hit, 120, data_cb);    */
/*             if (!ret) { */
/*                     COND_WAIT(cond, lock); */
/*             } */
/*     }); */
    
/*     /\*!!!! put hit->ip !!!!*\/  */
/*     printf("Put packet (hit->ip) and ...\n"); */
/*     ret = 0; */
/*     SYNCHRONIZE(lock, { */
/*             freez(last_data); */
/*             ret = opendht_put((unsigned char *)val_hit, */
/*                               (unsigned char *)val_ip,120,data_cb); */
/*             if (!ret) { */
/*                     COND_WAIT(cond, lock); */
/*             } */
/*     }); */

/*     /\*!!!! get fqdn !!!!*\/ */
/*     ret = 0; */
/*     printf("Get packet (fqdn) and ...\n"); */
/*     SYNCHRONIZE(lock, { */
/*             freez(last_data); */
/*             ret = opendht_get((unsigned char *)val_host,data_cb); */
/*             if (!ret) { */
/*                     COND_WAIT(cond, lock); */
/*             } */
/*     }); */

/*     if (last_data)  */
/*     { */
/*         printf("Value received from DHT: %s\n", last_data); */
/*         if (!strcmp(last_data, val_hit))  */
/*             printf("Did match the sent value.\n"); */
/*         else */
/*             printf("Did NOT match the sent value!\n"); */
/*     } */

/*     /\*!!!! get hit !!!!*\/ */
/*     ret = 0; */
/*     printf("Get packet (hit) and ...\n"); */
/*     SYNCHRONIZE(lock, { */
/*             freez(last_data); */
/*             ret = opendht_get((unsigned char *)val_hit,data_cb);  */
/*             if (!ret) { */
/*                     COND_WAIT(cond, lock); */
/*             } */
/*     }); */

/*     if (last_data) */
/*     { */
/*         printf("Value received from DHT: %s\n", last_data); */
/*         if (!strcmp(last_data, val_ip)) */
/*             printf("Did match the sent value.\n"); */
/*         else */
/*             printf("Did NOT match the sent value!\n"); */
/*     } */

/*     /\* Finally let's try to get a key that doesn't exist *\/ */
/*     ret = 0; */
/*     printf("Get packet (bogus, will not be found (hopefully)) and ...\n"); */
/*     SYNCHRONIZE(lock, { */
/*             freez(last_data); */
/*             ret = opendht_get((unsigned char *)val_bogus,data_cb);  */
/*             if (!ret) { */
/*                     COND_WAIT(cond, lock); */
/*             } */
/*     }); */
/*     freez(last_data); */
    
/*     printf("end!\n"); */
/*     opendht_close(); */

/*     LOCK_FREE(lock); */
/*     COND_FREE(cond); */

    exit(EXIT_SUCCESS);
}
