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

/* resourceman.c
   
   Resource fetching and pushing. Separated from the webcache module
   as it is used in a lot of other things as well. Or could be, at
   least.
*/

#include "resourceman.h"
#include "ident.h"
#include "conn.h"

static int resourcefetch_handle_message(char *data, int data_len, 
					ident_t *target, char *source, 
					service_type_t service_type);

static struct service_s resourcefetch_service =
{
 	.data_received = resourcefetch_handle_message,
	.service_closed = 0,
	.service_handler_id = "resourcefetch_service"
};

/* the list of pending calls */
static ship_list_t *pending_rfs = 0;


/* the resource fetches */
typedef struct pending_rf_s {
	
	void (*func)(void *param, char *host, char *rid, char *data, int datalen);
	void *data;
	
	time_t start;
	char *host;
	char *rid;
	
} pending_rf_t;

/* the list of stored resources */
static ship_ht_t *resources = 0;

/* The entries for the data stored */
typedef struct resourceman_entry_s {
	
	char *id;
	char *filename;
	char *recipient;
	
	int expire;
	int created;
	
	/* the access counter - how many times this has been loaded */
	int access_counter;

} resourceman_entry_t;


static void
resourceman_entry_free(resourceman_entry_t* ret)
{
	if (ret) {
		freez(ret->id);
		freez(ret->filename);
		freez(ret->recipient);
		freez(ret);
	}
}


static resourceman_entry_t*
resourceman_entry_new(const char *id,
		      const char *filename, const int expire, 
		      const char *recipient)
{
	resourceman_entry_t *ret = NULL;
	char *rand = NULL;
	
	ASSERT_TRUE(ret = mallocz(sizeof(*ret)), err);
	
	if (id) {
		ASSERT_TRUE(ret->id = strdup(id), err);
	} else {
		ASSERT_TRUE(rand = ship_get_random_base64(8), err);
		ASSERT_TRUE(ret->id = (char*)ship_hmac_sha1_base64(filename, rand), err);
	}

	ASSERT_TRUE(ret->filename = strdupz(filename), err);
	if (recipient) {
		ASSERT_TRUE(ret->recipient = strdup(recipient), err);
	}
	ret->created = time(0);
	ret->expire = expire;
	goto end;
 err:
	resourceman_entry_free(ret);
	ret = NULL;
 end:
	freez(rand);
	return ret;
}

/*** the resource fetch things ****/

static void
resourcefetch_free(pending_rf_t *rf)
{
	if (rf) {
		freez(rf->host);
		freez(rf->rid);
		free(rf);
	}
}

static pending_rf_t *
resourcefetch_new(char *host, char *rid, 
		  void (*func) (void *param, char *host, char *rid, char *data, int datalen),
		  void *data)
{
	pending_rf_t *rf = 0;
	ASSERT_TRUE(rf = mallocz(sizeof(*rf)), err);
	ASSERT_TRUE(rf->host = strdup(host), err);
	ASSERT_TRUE(rf->rid = strdup(rid), err);
	rf->start = time(0);
	rf->func = func;
	rf->data = data;
	return rf;
 err:	
	resourcefetch_free(rf);
	return NULL;
}

#define RESOURCEMAN_SEP ","
#define RESOURCEMAN_SEP_CHAR ','


static void 
_resourceman_load_cb(void *data, int lc, char *key, char *value, char *line)
{
	char **tokens = 0;
	int toklen = 0;

	trim(line);
	if (!ship_tokenize(line, strlen(line), &tokens, &toklen, RESOURCEMAN_SEP_CHAR)) {
		if (toklen != 6) {
			LOG_WARN("Invalid resourceman state line (%d): %s\n", lc, line);
		} else {
			resourceman_entry_t *entry = NULL;
			ASSERT_TRUE(entry = resourceman_entry_new(tokens[0], tokens[1], atoi(tokens[3]), 
								  (strlen(tokens[2]) > 0? tokens[2] : NULL)), err);
			entry->created = atoi(tokens[4]);
			entry->access_counter = atoi(tokens[5]);
			ship_ht_put_string(resources, entry->id, entry);
			
			LOG_DEBUG("loaded resource %s: %s for %s, %d, %d, %d\n", entry->id, entry->filename,
				  entry->recipient, entry->expire, entry->created, entry->access_counter);
		}
	err:
		ship_tokens_free(tokens, toklen);
	}
}


/* loading and saving of the state */
static int
resourceman_load()
{
	int ret = -1;
	ASSERT_ZERO(ship_read_file(processor_config_string(processor_get_config(), P2PSHIP_CONF_RESOURCEMAN_STATE_FILE), NULL,
				   _resourceman_load_cb, NULL), err);
	ret = 0;
 err:
	return ret;
}

static int
resourceman_save()
{
	resourceman_entry_t *entry = NULL;
	time_t now;
	FILE *f = NULL;
	void *ptr = 0, *last = 0;
	char *buf = 0, *tmp = 0;
	int len = 0, size = 0;
	int ret = -1;
	char *filename = NULL;

	LOG_DEBUG("Saving resourcemanager's state\n");

	ship_lock(resources);
	now = time(0);

	while ((entry = ship_ht_next(resources, &ptr))) {
		
		if (entry->expire > 0 && (entry->expire + entry->created < now)) {
			ship_ht_remove(resources, entry);
			resourceman_entry_free(entry);
			ptr = last;
		} else {
			/* save id, filename, for whom, created, expire, access counter .. */
			ASSERT_TRUE((tmp = append_str(entry->id, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(RESOURCEMAN_SEP, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(entry->filename, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(RESOURCEMAN_SEP, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(entry->recipient, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(RESOURCEMAN_SEP, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_int(entry->expire, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(RESOURCEMAN_SEP, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_int(entry->created, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str(RESOURCEMAN_SEP, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_int(entry->access_counter, buf, &size, &len)) && (buf = tmp), err);
			ASSERT_TRUE((tmp = append_str("\n", buf, &size, &len)) && (buf = tmp), err);
			
			last = ptr;
		}
	}
	ship_unlock(resources);

	filename = processor_config_string(processor_get_config(), P2PSHIP_CONF_RESOURCEMAN_STATE_FILE);
	if (!(f = fopen(filename, "w"))) {
		LOG_ERROR("Could not open resourcemanager state file %s\n", filename);
		goto err;
	}
	if (len != fwrite(buf, sizeof(char), len, f))
		goto err;
	ret = 0;
 err:
	if (f)
		fclose(f);
	freez(buf);

	return ret;
}

/* checks that all the entries are still valid */
static void
resourceman_check()
{
	resourceman_entry_t *entry = NULL;
	time_t now;
	void *ptr = 0, *last = 0;

	ship_lock(resources);
	now = time(0);

	while ((entry = ship_ht_next(resources, &ptr))) {
		if (entry->expire > 0 && (entry->expire + entry->created < now)) {
			ship_ht_remove(resources, entry);
			resourceman_entry_free(entry);
			ptr = last;
		}
		last = ptr;
	}
	ship_unlock(resources);
}

static int
resourceman_init(processor_config_t *config)
{
	int ret = -1;
	ASSERT_TRUE(pending_rfs = ship_list_new(), err);
	ASSERT_TRUE(resources = ship_ht_new(), err);
	ident_register_default_service(SERVICE_TYPE_RESOURCEFETCH, &resourcefetch_service);
	processor_config_set_dynamic(config, P2PSHIP_CONF_RESOURCEMAN_STATE_FILE);
	ASSERT_ZERO(resourceman_load(), err);
	ret = 0;
 err:
	return ret;
}

static void
resourceman_close()
{
	if (pending_rfs) {
		pending_rf_t *rf;
		ship_lock(pending_rfs);
		while ((rf = ship_list_pop(pending_rfs))) {
			rf->func(rf->data, rf->host, rf->rid, NULL, 0);
			resourcefetch_free(rf);
		}
		ship_list_free(pending_rfs);
		pending_rfs = 0;
	}
		
	if (resources) {
		resourceman_entry_t *val;

		resourceman_save();

		ship_lock(resources);
		while ((val = ship_ht_pop(resources))) {
			resourceman_entry_free(val);
		}
		ship_ht_free(resources);
		resources = 0;
	}
}

static int
resourcefetch_handle_message(char *data, int data_len, 
			     ident_t *target, char *source, 
			     service_type_t service_type)
{
	int ret = -1;
	char *d = 0, *rid = 0;
	char *buf = 0;
	FILE *f = 0;
	
	ASSERT_TRUE(d = strchr(data, '\n'), err);
	d[0] = 0;
	d++;

	if (str_startswith(data, "req:")) {
		resourceman_entry_t *entry = NULL;
		struct stat sdata;

		rid = data+4;
		LOG_DEBUG("got request for resource %s\n", rid);

		resourceman_check();
		ship_lock(resources);
		entry = ship_ht_get_string(resources, rid);
		ship_unlock(resources);
		
		/* read file, send the data! */
		ASSERT_TRUES(entry && !stat(entry->filename, &sdata), err, "Requested non-existing resource: %s\n", rid);
		ASSERT_ZEROS(entry->recipient && strcmp(source, entry->recipient), err, "Unauthorized request by %s for %s's resource %s\n", source, entry->recipient, rid);
		ASSERT_TRUES(sdata.st_size && (f = fopen(entry->filename, "r")), err, "Could not open requested resource: %s\n", rid);
		
		if ((buf = malloc(sdata.st_size + strlen(rid) + 32))) {
			size_t r = 0;
			int l = 0;
			
			strcpy(buf, "resp:");
			strcat(buf, rid);
			strcat(buf, "\n");
			l = strlen(buf);
			
			if (sdata.st_size)
				r = fread(buf + l, 1, sdata.st_size, f);
			if (r == sdata.st_size) {
				/* dtn: here we should just respond with the data! */
				ASSERT_ZERO(conn_send_default(source, target->sip_aor, 
							      SERVICE_TYPE_RESOURCEFETCH,
							      buf, l+r,
							      NULL, NULL), 
					    err);
				entry->access_counter++;
			}
		}
	} else if (str_startswith(data, "resp:")) {
		pending_rf_t *rf;
		void *ptr = 0, *last = 0;
		rid = data+5;
		LOG_DEBUG("got response for resource %s\n", rid);
		
		/* find the entry .. */
		ship_lock(pending_rfs);
		while ((rf = ship_list_next(pending_rfs, &ptr))) {
			if (!strcmp(rid, rf->rid) && !strcmp(source, rf->host)) {
				ship_list_remove(pending_rfs, rf);
				// halt
				rf->func(rf->data, rf->host, rf->rid, d, data_len - strlen(data) - 1);
				resourcefetch_free(rf);
				ptr = last;
			}
			last = ptr;
		}
		ship_unlock(pending_rfs);
	} else
		goto err;
	ret = 0;
 err:
	freez(buf);
	if (f)
		fclose(f);
	return ret;
}

static void
resourcefetch_get_cb(char *to, char *from, service_type_t service,
		     int code, char *return_data, int data_len, void *ptr)
{
	pending_rf_t *rf = ptr;
	if (code && (rf = ship_list_remove(pending_rfs, rf))) {
		rf->func(rf->data, rf->host, rf->rid, NULL, 0);
		resourcefetch_free(rf);
	}
}

static int
resourcefetch_get_to(void *data, processor_task_t **wait, int wait_for_code)
{
	resourcefetch_get_cb(NULL, NULL, 0, -1, NULL, 0, data);
	return 0;
}

int
resourcefetch_get(char *host, char *rid,
		  char *local_aor,
		  void (*func) (void *param, char *host, char *rid, char *data, int datalen),
		  void *data) 
{
	pending_rf_t *rf = 0;
	char *dp = 0;
	int ret = -1;
	
	/* this is quite simple for now. Just fetch the resource as one big blob. */
	LOG_DEBUG("fetching resource '%s' from '%s'\n", rid, host);
	
	/* 
	   protocol:
	   
	   the request:
	   req:<rid>\n
	   
	   the response:
	   resp:<rid>\n<data>
	*/
	
	/* create the data packet */
	ASSERT_TRUE(dp = mallocz(strlen(rid) + 64), err);
	strcpy(dp, "req:");
	strcat(dp, rid);
	strcat(dp, "\n");

	/* store the callbacks */
	ASSERT_TRUE(rf = resourcefetch_new(host, rid, func, data), err);
	ship_list_add(pending_rfs, rf);

	/* dtn: here we could actually use the ack-response data! */
	ASSERT_ZERO(conn_send_slow(host, local_aor, 
				   SERVICE_TYPE_RESOURCEFETCH,
				   dp, strlen(dp), 
				   rf, resourcefetch_get_cb), 
		    err);

	/* create some sort of timeout for this */
	processor_tasks_add_timed(resourcefetch_get_to, rf, NULL, 10000);
	
	rf = 0;
	ret = 0;
 err:
	freez(dp);
	if (rf) {
		ship_list_remove(pending_rfs, rf);
	}
	return ret;
}


/* This stores a data file into the resource-fetch service.
 
   @param recipient is the recipient. should be key, is now aor only..
*/
int
resourcefetch_store(const char *filename, const int expire, 
		    const char *recipient, char **id)
{
	resourceman_entry_t *ret = NULL, *old;
	void *ptr = NULL;
	int retval = -1;

	ship_lock(resources);
	resourceman_check();

	/* check if we already have an identical entry: same file and
	   recipient: update only the expire value */
	while (!ret && (ret = ship_ht_next(resources, &ptr)))
		if (zstrcmp(ret->filename, filename) ||
		    zstrcmp(ret->recipient, recipient))
			ret = NULL;

	if (ret) {
		/* update the old entry .. */
		ret->expire = time(0) - ret->created + expire;
		LOG_DEBUG("updating resource %s, id %s, new expire %d\n", filename, ret->id, ret->expire);
	} else {
		ASSERT_TRUE(ret = resourceman_entry_new(NULL, filename, expire, recipient), err);
		LOG_DEBUG("storing resource %s under id %s\n", filename, ret->id);
		
		if ((old = ship_ht_remove_string(resources, ret->id)))
			resourceman_entry_free(old);
		ship_ht_put_string(resources, ret->id, ret);
	}

	ASSERT_TRUE(*id = strdup(ret->id), err);

	resourceman_save();
	retval = 0;
	goto end;
 err:
	resourceman_entry_free(ret);
 end:
	ship_unlock(resources);
	return retval;
}

/* removes a resource from the resource service */
int
resourcefetch_remove(char *rid)
{
	resourceman_entry_t *tmp = 0;
	int ret = -1;

	ASSERT_TRUE(rid, err);
	ASSERT_TRUE(tmp = ship_ht_remove_string(resources, rid), err);
	resourceman_entry_free(tmp);
	resourceman_check();
	resourceman_save();
	ret = 0;
 err:
	return ret;
}

/* the netio_man register */
static struct processor_module_s processor_module = 
{
	.init = resourceman_init,
	.close = resourceman_close,
	.name = "resourceman",
	.depends = "",
};

/* register func */
void
resourceman_register() {
	processor_register(&processor_module);
}
