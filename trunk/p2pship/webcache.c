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
#include "ship_utils.h"
#include "ship_debug.h"
#include "processor_config.h"
#include "processor.h"
#include "netio_http.h"
#include "ident.h"
#include "webcache.h"
#include "conn.h"
#include "olclient.h"

/* the currently in-progree dls */
static ship_ht_t *all_dls = 0;
static ship_ht_t *webcache_cache = 0;
static ship_list_t *webcache_removed = 0;

/* config values */
static int webcache_file_limit = 1024*1024*2;
static int webcache_limit = 1024*1024*20;
static char *webcache_dir = "/tmp/webcache";
static char *webcache_index = "/tmp/webcache/index.txt";
static void webcache_p2p_update();

#define WEBCACHE_KEY_PREFIX "webcache:"

#define STRICTNESS_ALL 0
#define STRICTNESS_RELAXED 1
#define STRICTNESS_STRICT 2

static int cache_strictness = STRICTNESS_ALL;

/* the list of pending calls */
static ship_list_t *pending_rfs = 0;

void resourcefetch_close();
int resourcefetch_init(processor_config_t *config);
static int resourcefetch_handle_message(char *data, int data_len, 
					ident_t *target, char *source, 
					service_type_t service_type);

static struct service_s resourcefetch_service =
{
 	.data_received = resourcefetch_handle_message,
	.service_closed = 0,
	.service_handler_id = "resourcefetch_service"
};

/* the resource fetches */
typedef struct pending_rf_s {
	
	void (*func)(void *param, char *host, char *rid, char *data, int datalen);
	void *data;
	
	time_t start;
	char *host;
	char *rid;
	
} pending_rf_t;

/* the list tracking urls to hosts, to ids */
static ship_ht2_t *resource_id_cache = 0;

/* the list of stored resources */
static ship_ht_t *resources = 0;

/* each entry of the cache is a ht. each entry of that ht the following struct: */
typedef struct resource_id_cache_s {
	
	char *resource;
	int size;
	time_t expires;

} resource_id_cache_t;

typedef struct webcache_tracker_s {

	char *url;

	char *filename;
	int size;

	int expires;
	
	/* this is for tracking downloads */
	int cache;
	int checked;

	/* buffer for the headers */
	char *buf;
	int buflen;
	int datalen;

	/* this is for the cached entries */
	int last_access;

	/* marks that this has been put into the overlay */
	int published;
	
} webcache_tracker_t;


/* the cache of all p2p webcache resources */
static ship_ht_t *p2p_mappings = 0;

typedef struct webcache_p2p_lookup_entry_s {
	ship_obj_t parent;

	ship_list_t real_queue;
	ship_list_t *lookup_queue;
	
	void *cb_data;
	void (*func) (char *url, void *obj, char *data, int datalen);
	char *url;

	/* how many lookups are in progress .. */
	int lookups;
	
} webcache_p2p_lookup_entry_t;

/* prototypes */
static webcache_tracker_t *webcache_tracker_new(char *url);
static void webcache_p2p_lookup_entry_free(webcache_p2p_lookup_entry_t *e);
static int webcache_p2p_lookup_entry_init(webcache_p2p_lookup_entry_t *e, char *url);

/* define the types */
SHIP_DEFINE_TYPE(webcache_p2p_lookup_entry);


/* saves the list somewhere */
static void
webcache_save()
{
	int ret = -1, len = 0, size = 0, s = 0, c = 0;
	FILE *f = NULL;
	webcache_tracker_t *e = 0;
	void *ptr = 0;
	char *buf = 0, *tmp = 0, tbuf[64];
	
	LOG_DEBUG("Saving webcache list\n");

	ship_lock(webcache_cache);

	ASSERT_TRUE((tmp = append_str("# webcache index, created ", buf, &size, &len)) && (buf = tmp), err);
	ship_format_time_human(time(0), tbuf, sizeof(tbuf)-1);
	ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);
	ASSERT_TRUE((tmp = append_str("\n#\n\n", buf, &size, &len)) && (buf = tmp), err);
	
	while ((e = ship_ht_next(webcache_cache, &ptr))) {
		
		/* format: filename,expires=url */
		ASSERT_TRUE((tmp = append_str(e->filename, buf, &size, &len)) && (buf = tmp), err);
		sprintf(tbuf, ",%d,%d=", e->size, e->expires);
		ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str(e->url, buf, &size, &len)) && (buf = tmp), err);
		ASSERT_TRUE((tmp = append_str("\n", buf, &size, &len)) && (buf = tmp), err);
		s += e->size;
		c++;
	}

	sprintf(tbuf, "\n# Total %d bytes in %d entries\n\n", s, c);
	ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);
	
	if (!(f = fopen(webcache_index, "w"))) {
		LOG_ERROR("Could not open webcache index %s\n", webcache_index);
		goto err;
	}
	if (len != fwrite(buf, sizeof(char), len, f))
		goto err;
	
	ret = 0;
 err:
	ship_unlock(webcache_cache);
	if (f)
		fclose(f);
	freez(buf);
}


static void 
webcache_load_cb(void *data, int lc, char *key, char *value, char *line)
{
	char **tokens = 0;
	int toklen = 0;
	webcache_tracker_t *e = 0;

	ASSERT_ZERO(ship_tokenize_trim(key, strlen(key), &tokens, &toklen, ','), err);
	ASSERT_TRUE(toklen == 3, err);
	
	ASSERT_TRUE(e = webcache_tracker_new(value), err);
	e->filename = tokens[0];
	tokens[0] = 0;
	e->size = atoi(tokens[1]);
	e->expires = atoi(tokens[2]);
	ship_ht_put_string(webcache_cache, value, e);

	ship_tokens_free(tokens, toklen);
	return;
 err:
	ship_tokens_free(tokens, toklen);
	LOG_WARN("Error loading webcache index, line %d: %s\n", lc, line);
}

/* loads the list */
static int
webcache_load()
{
	return ship_read_file(webcache_index, NULL, webcache_load_cb, NULL);
}

static void 
webcache_tracker_free(webcache_tracker_t *tracker)
{
	if (!tracker)
		return;

	freez(tracker->url);
	freez(tracker->buf);
	freez(tracker->filename);
	free(tracker);
}

static void 
webcache_tracker_free_remove(webcache_tracker_t *tracker)
{
	/* delete the file! */
	if (tracker && tracker->filename)
		unlink(tracker->filename);
	webcache_tracker_free(tracker);
}

static webcache_tracker_t *
webcache_tracker_new(char *url)
{
	webcache_tracker_t *ret = 0;
	ASSERT_TRUE(ret = mallocz(sizeof(webcache_tracker_t)), err);
	ASSERT_TRUE(ret->url = strdup(url), err);
	return ret;
 err:
	webcache_tracker_free(ret);
	return NULL;
}

static void
webcache_flush_removed()
{
	webcache_tracker_t *cache;
	if (!webcache_cache || !webcache_removed)
		return;
	
	ship_lock(webcache_cache);
	while ((cache = ship_list_pop(webcache_removed))) {
		webcache_tracker_free(cache);
	}
	ship_unlock(webcache_cache);
}


int
webcache_get_resource(char *url, char **buf, int *len)
{
	int ret = -1;
	webcache_tracker_t *e = 0;
	FILE *f = 0;

	ship_lock(webcache_cache);
	*buf = 0;
	if ((e = ship_ht_get_string(webcache_cache, url))) {
		if (e->expires > time(0)) {
			ASSERT_TRUE(*buf = mallocz(e->size + 1), err);
			*len = e->size;
			
			ASSERT_TRUE(f = fopen(e->filename, "r"), err);
			ASSERT_TRUE(fread(*buf, sizeof(char), *len, f) == *len, err);
			e->last_access = time(0);
			ret = 0;
		} else if ((e = ship_ht_remove(webcache_cache, e))) {			
			ship_list_add(webcache_removed, e);
			webcache_save();
			webcache_flush_removed();
			processor_run_async(webcache_p2p_update);
		}
	}
 err:
	ship_unlock(webcache_cache);
	if (f) 
		fclose(f);
	if (ret && *buf)
		free(*buf);
	return ret;
}

int
webcache_record(char *tracking_id, char *url, char *data, int datalen)
{
	int ret = -1;
	netio_http_conn_t *conn = 0;
	ship_ht_t *dls;
	webcache_tracker_t *cache = 0;

	if (!url)
		return 0;

	ship_lock(all_dls);
	if (!(dls = ship_ht_get_string(all_dls, tracking_id))) {
		ASSERT_TRUE(dls = ship_ht_new(), err);
		ship_ht_put_string(all_dls, tracking_id, dls);
	}
	
	if (!(cache = ship_ht_get_string(dls, url))) {
		LOG_DEBUG("creating a new tracker for %s\n", url);
		ASSERT_TRUE(cache = webcache_tracker_new(url), err);
		ship_ht_put_string(dls, url, cache);
	}
	
	/* check if this should be cached at all */
	if (!cache->checked) {
		char *tmp = 0;
		ASSERT_TRUE(tmp = append_mem(data, datalen, cache->buf, &cache->buflen, &cache->datalen), err);
		cache->buf = tmp;

		if ((conn = netio_http_parse_header(cache->buf, cache->datalen))) {
			char *tmp;

			/* cache by default */
			cache->cache = 1;
			cache->expires = 3600*2; /* what should this be? */

			if ((tmp = netio_http_get_header(conn, "Pragma"))) {
				if (!strcmp(tmp, "no-cache"))
					cache->cache = 0;
			}

			if ((tmp = netio_http_get_header(conn, "Cache-Control"))) {
				char *param;
				
				if (!strcmp(tmp, "public")) {
					cache->cache = 1;
				} else if (str_startswith(tmp, "s-maxage") || 
					   str_startswith(tmp, "max-age")) {
					
					cache->cache = 1;
					if ((param = strchr(tmp, '='))) {
						cache->expires = atoi(param+1);
					}
				} else if (strstr(tmp, "no-cache")) {
					LOG_DEBUG("Not caching page, cache control: %s\n", tmp);
					cache->cache = 0;
				} else {
					switch (cache_strictness) {
					case STRICTNESS_ALL:
					case STRICTNESS_RELAXED:
						LOG_DEBUG("Caching page (even though we shouldn't), cache control: %s\n", tmp);
						cache->cache = 1;
						break;
					case STRICTNESS_STRICT:
					default:
						cache->cache = 0;
						break;
					}
				}
			}
			
			/* na, not for now.. */
			//if (tmp = netio_http_get_header(conn, "Expires")) {
			
			if (cache->cache) {
				int fd = -1;
				LOG_DEBUG("will cache the page %s\n", url);
				
				/* strip any cookies? */

				/* create file, start saving .. */
				ASSERT_TRUE(cache->filename = mallocz(64), err);
				strcpy(cache->filename, "/tmp/p2pship_cacheXXXXXXXX");
				ASSERT_TRUE((fd = mkstemp(cache->filename)) != -1, err);
				write(fd, cache->buf, cache->datalen);
				cache->size = cache->datalen;
				close(fd);
				freez(cache->buf);
			}
			cache->checked = 1;
		}
	} else if (cache->cache) {
		FILE *f = 0;

		/* save the piece .. */
		ASSERT_TRUE(f = fopen(cache->filename, "a"), err);
		fwrite(data, sizeof(char), datalen, f);
		fflush(f);
		cache->size += datalen;
		fclose(f);
	}
	ret = 0;
 err:
	ship_unlock(all_dls);
	netio_http_conn_close(conn);
	return ret;
}


/* clears the cache so that we have room for the given amount.
   returns true if it was successful */
static int
webcache_make_room(int size)
{
	int ret = 0;
	webcache_tracker_t *e = 0, *e2 = 0;
	time_t now;
	void *ptr = 0, *last = 0;
	int totsize;
	
	if (size > webcache_limit)
		goto err;
	
	ship_lock(webcache_cache);
	now = time(0);
	
	/* clear first all expired */
	while ((e = ship_ht_next(webcache_cache, &ptr))) {
		if (now > e->expires &&
		    (e = ship_ht_remove(webcache_cache, e))) {
			ship_list_add(webcache_removed, e);
			ptr = last;
		}
		last = ptr;
	}

	/* check size - remove one-by-one in LRU until we have enough */
	do {
		/* remove the one found during the previous round */
		if (e2 && (e = ship_ht_remove(webcache_cache, e2))) {
			ship_list_add(webcache_removed, e);
		}
		
		ptr = 0;
		e2 = 0;
		totsize = 0;
		while ((e = ship_ht_next(webcache_cache, &ptr))) {
			if (!e2 || e->last_access < e2->last_access) {
				e2 = e;
			}
			totsize += e->size;
		}
	} while (totsize && ((webcache_limit - totsize) < size));
	
	if ((webcache_limit - totsize) >= size)
		ret = 1;
 err:
	ship_unlock(webcache_cache);
	return ret;
}


static int
webcache_import_entry(char *url, char *filename, int size, int expires)
{
	webcache_tracker_t *cache = 0;
	int ret = -1;
	char *fn = 0;
	
	ship_lock(webcache_cache);
	LOG_DEBUG("should import copy of %s from %s, size %d\n", url, filename, size);

	/* check that the file size is not too big */
	if (size > webcache_file_limit)
		goto err;

	/* remove previous entry, if one exists */
	if ((cache = ship_ht_remove_string(webcache_cache, url))) {
		ship_list_add(webcache_removed, cache);
	}
	
	/* ensure that we have enough space in our quota for this one! */
	ASSERT_TRUE(webcache_make_room(size), err);

	/* move the file to the proper location */

	ASSERT_TRUE(fn = mallocz(strlen(webcache_dir) + 32), err);
	strcpy(fn, webcache_dir);
	strcat(fn, "/itemXXXXXXXX");
	ASSERT_TRUE(mkstemp(fn) != -1, err);
	
	/* create entry */
	ASSERT_TRUE(cache = webcache_tracker_new(url), err);
	cache->expires = time(0) + expires;
	cache->last_access = time(0);
	cache->size = size;
	cache->filename = fn;
	ASSERT_ZERO(ship_move(filename, cache->filename), err);
	ship_ht_put_string(webcache_cache, url, cache);
	cache = 0;
	fn = 0;
	
	/* save cache list! */
	webcache_save();
	webcache_flush_removed();
	processor_run_async(webcache_p2p_update);
	ret = 0;
 err:
	ship_unlock(webcache_cache);
	freez(fn);
	webcache_tracker_free(cache);
	return ret;
}

void
webcache_close_trackers(char *tracking_id)
{
	ship_ht_t *dls;
	ship_lock(all_dls);
	if ((dls = ship_ht_remove_string(all_dls, tracking_id))) {
		webcache_tracker_t *cache = 0;
		while ((cache = ship_ht_pop(dls))) {
			/* ok, now index & save! */
			if (cache->size > 0 && cache->expires > 0 && cache->filename)
				webcache_import_entry(cache->url, cache->filename, cache->size, cache->expires);
			webcache_tracker_free_remove(cache);
		}
		ship_ht_free(dls);
	}
	ship_unlock(all_dls);
}

static void
webcache_cb_config_update(processor_config_t *config, char *k, char *v)
{
	processor_config_get_int(config, P2PSHIP_CONF_WEBCACHE_FILELIMIT, &webcache_file_limit);
	processor_config_get_int(config, P2PSHIP_CONF_WEBCACHE_LIMIT, &webcache_limit);
	processor_config_get_enum(config, P2PSHIP_CONF_WEBCACHE_STRICTNESS, &cache_strictness);
}

static int
webcache_init(processor_config_t *config)
{
	int ret = -1;
	char *tmp;
	
	ASSERT_TRUE(all_dls = ship_ht_new(), err);
	ASSERT_TRUE(webcache_cache = ship_ht_new(), err);
	ASSERT_TRUE(webcache_removed = ship_list_new(), err);
 
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_WEBCACHE_FILELIMIT, webcache_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_WEBCACHE_LIMIT, webcache_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_WEBCACHE_STRICTNESS, webcache_cb_config_update);
	processor_config_set_dynamic_update(config, P2PSHIP_CONF_WEBCACHE_USE_P2P_LOOKUP, webcache_cb_config_update);
	webcache_cb_config_update(config, NULL, NULL);
	
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_WEBCACHE_INDEX, &tmp), err);
	ASSERT_TRUE(webcache_index = strdup(tmp), err);
	ASSERT_TRUE(webcache_dir = strdup(tmp), err);
	
	ASSERT_TRUE(tmp = strrchr(webcache_dir, '/'), err);
	tmp[0] = 0;

	ASSERT_ZERO(webcache_load(), err);
	ASSERT_ZERO(resourcefetch_init(config), err);
	processor_run_async(webcache_p2p_update);
	ret = 0;
 err:
	return ret;
}

static void
webcache_close()
{
	resourcefetch_close();
	webcache_tracker_t *cache;
	if (all_dls) {
		ship_ht_t *dl = 0;
		ship_lock(all_dls);
		
		while ((dl = ship_ht_pop(all_dls))) {
			while ((cache = ship_ht_pop(dl))) {
				webcache_tracker_free_remove(cache);
			}
			ship_ht_free(dl);
		}
		ship_ht_free(all_dls);
		all_dls = 0;
	}

	if (webcache_cache) {
		ship_lock(webcache_cache);
		while ((cache = ship_ht_pop(webcache_cache))) {
			webcache_tracker_free(cache);
		}

		webcache_flush_removed();
		ship_list_free(webcache_removed);
		ship_ht_free(webcache_cache);
	}
	freez(webcache_index);
	freez(webcache_dir);
}

/***** the p2p stuff ******/

static void
webcache_p2p_lookup_entry_free(webcache_p2p_lookup_entry_t *e)
{
	if (e->func)
		e->func(e->url, e->cb_data, NULL, 0);
	
	if (e->lookup_queue) {
		ship_list_empty_free(e->lookup_queue);
		ship_list_deinit(e->lookup_queue);
	}
	freez(e->url);
}

static int
webcache_p2p_lookup_entry_init(webcache_p2p_lookup_entry_t *e,
			       char *url)
{
	ASSERT_TRUE(e->url = strdup(url), err);
	e->lookup_queue = &e->real_queue;
	ASSERT_ZERO(ship_list_init(e->lookup_queue), err);
	return 0;
 err: 
	e->lookup_queue = 0;
	return -1;
}

/* returns all peers that have reported that they have the given url */
static int
webcache_p2p_get_resource_hosts(char *url, ship_list_t *hosts)
{
	int ret = -1;
	ship_list_t *k = 0;
	char *key = 0;

	ship_lock(resource_id_cache);
	ASSERT_TRUE(k = ship_ht2_keys(resource_id_cache, url), err);
	while ((key = ship_list_pop(k))) {
		ship_list_add(hosts, key);
	}
	ship_list_free(k);
	ret = 0;
 err:
	ship_unlock(resource_id_cache);
	return ret;
}

/* func retrieves the resource id for the given url on that hosts from
   the cache.  */
static char *
webcache_p2p_get_resource_id(char *host, char *url)
{
	char *ret = 0;
	resource_id_cache_t *rid = 0;
	ship_lock(resource_id_cache);

	if ((rid = ship_ht2_get_string(resource_id_cache, url, host))) {
		if (rid->expires >= time(0))
			ret = strdup(rid->resource);
		else {
			ship_ht2_remove_string(resource_id_cache, url, host);
			freez(rid->resource);
			free(rid);
		}
	}
	ship_unlock(resource_id_cache);
	return ret;
}

static int
webcache_p2p_has_resource_id(char *host, char *url)
{
	int ret = 0;
	resource_id_cache_t *rid = 0;
	ship_lock(resource_id_cache);

	if ((rid = ship_ht2_get_string(resource_id_cache, url, host))) {
		if (rid->expires >= time(0))
			ret = 1;
	}
	ship_unlock(resource_id_cache);
	return ret;
}


/* stores a url->resource id / host / ttl mapping. */
static void
webcache_p2p_store_resource_id(char *host, char *url, char *resource, int size, time_t expires)
{
	resource_id_cache_t *rid = 0;
	
	ship_lock(resource_id_cache);

	if ((rid = ship_ht2_remove_string(resource_id_cache, url, host))) {
		freez(rid->resource);
	} else {
		ASSERT_TRUE(rid = mallocz(sizeof(*rid)), err);
	}
	
	ASSERT_TRUE(rid->resource = strdup(resource), err);
	rid->size = size;
	rid->expires = expires;
	
	ship_ht2_put_string(resource_id_cache, url, host, rid);
	rid = 0;
 err:
	if (rid) {
		freez(rid->resource);
		free(rid);
	}
	ship_unlock(resource_id_cache);
}

static int webcache_p2p_lookup_cb_do(void *data, processor_task_t **wait, int wait_for_code);

/* the callback for the resource-lookup func */
static void
webcache_p2p_lookup_rl_cb(void *param, char *host, char *rid, char *data, int datalen)
{
	webcache_p2p_lookup_entry_t *e = param;
	
	ship_lock(e);
	e->lookups--;
	
	/* ..if we got the data */
	if (data && e->func) {
		e->func(e->url, e->cb_data, data, datalen);
		e->func = NULL;
	}
	ship_unlock(e);
	
	/* loop, fetch next if necessary */
	processor_tasks_add(webcache_p2p_lookup_cb_do, e, NULL);
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


int
resourcefetch_init(processor_config_t *config)
{
	int ret = -1;
	ASSERT_TRUE(pending_rfs = ship_list_new(), err);
	ASSERT_TRUE(resource_id_cache = ship_ht2_new(), err);
	ASSERT_TRUE(resources = ship_ht_new(), err);
	ident_register_default_service(SERVICE_TYPE_RESOURCEFETCH, &resourcefetch_service);
	ret = 0;
 err:
	return ret;
}

void
resourcefetch_close()
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
	
	if (resource_id_cache) {
		resource_id_cache_t *rid = 0;
		ship_lock(resource_id_cache);
		while ((rid = ship_ht2_pop(resource_id_cache))) {
			freez(rid->resource);
			free(rid);
		}
		ship_ht2_free(resource_id_cache);
		resource_id_cache = 0;
	}
	
	if (resources) {
		char *val;
		ship_lock(resources);
		while ((val = ship_ht_pop(resources))) {
			freez(val);
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
		char *fn = 0;
		struct stat sdata;

		rid = data+4;
		LOG_DEBUG("got request for resource %s\n", rid);

		/* todo: access control of any sort? */
		ship_lock(resources);
		fn = ship_ht_get_string(resources, rid);
		ship_unlock(resources);
		
		/* read file, send the data! */
		if (!fn || stat(fn, &sdata)) {
			LOG_WARN("Requested non-existing file %s\n", fn);
			sdata.st_size = 0;
		}
			
		/* load file .. */
		if (sdata.st_size && !(f = fopen(fn, "r")))
			sdata.st_size = 0;
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

/* this stores a data file into the resource-fetch service */
int
resourcefetch_store(char *filename, char **id)
{
	int ret = -1;
	char *dup = 0, *old = 0;
	
	ASSERT_TRUE(*id = (char*)ship_hmac_sha1_base64(filename, "todo.."), err);
	ASSERT_TRUE(dup = strdupz(filename), err);
	LOG_DEBUG("storing resource %s under id %s\n", filename, *id);
	
	ship_lock(resources);
	old = ship_ht_remove_string(resources, *id);
	freez(old);
	
	ship_ht_put_string(resources, *id, dup);
	ret = 0;
	ship_unlock(resources);
 err:
	return ret;
}

/* removes a resource from the resource service */
int
resourcefetch_remove(char *filename)
{
	char *tmp = 0, *tmp2 = 0;
	int ret = -1;

	ASSERT_TRUE(tmp = (char*)ship_hmac_sha1_base64(filename, "todo.."), err);
	tmp2 = ship_ht_remove_string(resources, tmp);
	freez(tmp2);
	freez(tmp);
	ret = 0;
 err:	
	return ret;
}

/* this func performs the lookups using the resource-transfer protocol */
static int 
webcache_p2p_lookup_cb_do(void *data, processor_task_t **wait, int wait_for_code)
{
	webcache_p2p_lookup_entry_t *e = data;
	char *host = 0;
	ident_t *ident = 0;

#define MAX_NUMBER_OF_SIMULTANEOUS_LOOKUPS 2
	
	// halt
	ship_wait("webcache lookup");
	ident = ident_get_default_ident();
	ship_complete();
	if (!ident)
		return -1;
	ship_lock(e);
	while (e->lookups < MAX_NUMBER_OF_SIMULTANEOUS_LOOKUPS && ship_list_first(e->lookup_queue)) {
		/* remove one entry. fetch it */
		if ((host = ship_list_pop(e->lookup_queue))) {
			char *rid = 0;

			/* stop if we already got the data */
			ship_obj_ref(e);
			if (e->func && 
			    (rid = webcache_p2p_get_resource_id(host, e->url)) &&
			    !resourcefetch_get(host, rid, 
					       ident->sip_aor,
					       webcache_p2p_lookup_rl_cb, e)) {
				e->lookups++;
			} else {
				ship_obj_unref(e);
			}
			freez(host);
			freez(rid);
		}
	}
	ship_obj_unlockref(ident);
	ship_obj_unlockref(e);
	return 0;
}

static void 
webcache_p2p_read_cb(void *data, int lc, char *key, char *value, char *line)
{
	char *host = data;
	char **tokens = 0;
	int toklen = 0;
	
	if (!key || !value)
		return;

	/* format : url = id,size,valid-until (urlencoded, of course) */
	ship_urldecode(key);
	if (!ship_tokenize_trim(value, strlen(value), &tokens, &toklen, ',') && toklen == 3) {
		char *id = tokens[0];
		int s = atoi(tokens[1]);
		time_t exp = ship_parse_time(tokens[2]);
		
		webcache_p2p_store_resource_id(host, key, id, s, exp);
	}
	
	ship_tokens_free(tokens, toklen);
}

static void 
webcache_p2p_lookup_cb(char *key, char *data, char *signer, void *param, int status)
{
	webcache_p2p_lookup_entry_t *e = param;
	if (data && signer && status > -1) {
		char *tmp = 0;
		
		/* parse the info into the common cache for these things */
		ship_lock(p2p_mappings);
		ship_read_mem(data, strlen(data), signer, webcache_p2p_read_cb, NULL);
		ship_unlock(p2p_mappings);
		
		/* check async whether we found that thing during the lookup */
		if ((tmp = strdup(signer))) {
			ship_lock(e);
			ship_list_add(e->lookup_queue, tmp);
			ship_obj_ref(e);
			processor_tasks_add(webcache_p2p_lookup_cb_do, e, NULL);
			ship_unlock(e);
		}
	}
	
	/* unref if we aren't getting any more */
 	if (status < 1)
		ship_obj_unref(e);
}

int
webcache_p2p_lookup(char *url, void *ptr, void (*func) (char *url, void *obj, char *data, int datalen))
{
	int ret = -1, found = 0;
	char *k = 0;
	webcache_p2p_lookup_entry_t *e = 0; // todo: ship obj this!
	ship_list_t *conn_peers = 0;
	
	/* check first whether we should use p2p lookups at all */
	if (!processor_config_is_true(processor_get_config(), P2PSHIP_CONF_WEBCACHE_USE_P2P_LOOKUP))
		return -1;

	LOG_INFO("should do a request to %s using the p2p web cache system\n", url);

	ASSERT_TRUE(e = (webcache_p2p_lookup_entry_t *)ship_obj_new(TYPE_webcache_p2p_lookup_entry, url), err);
	e->cb_data = ptr;
	e->func = func;
	ship_lock(e);

	/* here, we should first check whether the peers we are
	   connected to have this url */
	ASSERT_TRUE(conn_peers = ship_list_new(), err);
	conn_get_connected_peers(NULL, conn_peers);
	
	while ((k = ship_list_pop(conn_peers))) {
		if (!found && webcache_p2p_has_resource_id(k, e->url)) {
			ship_list_add(e->lookup_queue, k);
			found = 1;
		} else
			freez(k);
	}

	/* if we did not fetch anything, then check whether we know of
	   someone that should have it. */
	if (!found && !webcache_p2p_get_resource_hosts(e->url, conn_peers) && ship_list_first(conn_peers)) {
		while ((k = ship_list_pop(conn_peers))) {
			ship_list_add(e->lookup_queue, k);
		}
	}

	/* make a request for the mappings, but only if we aren't
	   trying to fetch it already! */
	if (ship_list_first(e->lookup_queue)) {
		ship_obj_ref(e);
		processor_tasks_add(webcache_p2p_lookup_cb_do, e, NULL);
	} else {
		ASSERT_TRUE(k = mallocz(strlen(url) + 32), err);
		strcpy(k, WEBCACHE_KEY_PREFIX);
		strcat(k, url);
	
		/* from trusted people only, please! */
		ship_obj_ref(e);
		ASSERT_ZERO(olclient_get_signed_trusted(k, e, webcache_p2p_lookup_cb), err);
	}
	
	ret = 0;
 err:
	if (conn_peers) {
		ship_list_empty_free(conn_peers);
		ship_list_free(conn_peers);
	}
	freez(k);
	ship_obj_unlockref(e);
	return ret;
}

/* this function updates what we advertize as being in our cache */
static void
webcache_p2p_update()
{
	webcache_tracker_t *e = 0;
	void *ptr = 0;
	char *buf = 0;
	ident_t *ident = 0;
	/* todo: this should actually be called also when we change networks */

	/* go through list, remove all that have been removed or validity changed */
	
	LOG_DEBUG("updating webcache adverts..\n");

	ship_wait("webcache update");
	ident = ident_get_default_ident();
	ship_complete();
	if (!ident)
		return;
	
	ship_lock(webcache_cache);
	
	/* remove removed and updated ones */
	while ((e = ship_list_next(webcache_removed, &ptr))) {
		LOG_VDEBUG("should remove advert for %s\n", e->url);
		if ((buf = mallocz(strlen(e->url) + strlen(WEBCACHE_KEY_PREFIX) + 2))) {
			strcpy(buf, WEBCACHE_KEY_PREFIX);
			strcat(buf, e->url);
			resourcefetch_remove(e->filename);
			olclient_remove(buf, NULL);
			free(buf);
		}
	}
	/* this is logic that chould be changed according to some
	   optimal algorithm / scheme */
	ptr = 0;
	while ((e = ship_ht_next(webcache_cache, &ptr))) {
		char *data = 0, *tmp = 0;
		int len = 0, size = 0;
		char *rid = 0, *u = 0;
		
		if (e->published)
			continue;
		
		LOG_VDEBUG("should advert %s\n", e->url);
		if ((buf = mallocz(strlen(e->url) + strlen(WEBCACHE_KEY_PREFIX) + 2))) {
			char b2[64];
			
			strcpy(buf, WEBCACHE_KEY_PREFIX);
			strcat(buf, e->url);

			/* we should create the mapping */
			ASSERT_ZERO(resourcefetch_store(e->filename, &rid), err);
			
			ASSERT_TRUE(u = ship_urlencode(e->url), err);
			sprintf(b2, "%d", e->size);

			/* format : url = id,size,valid-until (urlencoded, of course) */
			
			/* we should create the data packet! */
			ASSERT_TRUE((tmp = append_str(u, data, &size, &len)) && (data = tmp), err);
			ASSERT_TRUE((tmp = append_str("=", data, &size, &len)) && (data = tmp), err);
			ASSERT_TRUE((tmp = append_str(rid, data, &size, &len)) && (data = tmp), err);
			ASSERT_TRUE((tmp = append_str(",", data, &size, &len)) && (data = tmp), err);
			ASSERT_TRUE((tmp = append_str(b2, data, &size, &len)) && (data = tmp), err);
			ASSERT_TRUE((tmp = append_str(",", data, &size, &len)) && (data = tmp), err);
			ship_format_time(e->expires, b2, sizeof(b2));
			ASSERT_TRUE((tmp = append_str(b2, data, &size, &len)) && (data = tmp), err);
			ASSERT_TRUE((tmp = append_str("\n", data, &size, &len)) && (data = tmp), err);
			
			olclient_put_signed_cert(buf, data, ident, e->expires - time(0), 
						 processor_config_string(processor_get_config(), P2PSHIP_CONF_OL_SECRET));
		}
		
		e->published = 1;
	err:
		freez(u);
		freez(data);
		freez(rid);
		freez(buf);
	}
	ship_unlock(webcache_cache);
	ship_obj_unlockref(ident);
}

/* the netio_man register */
static struct processor_module_s processor_module = 
{
	.init = webcache_init,
	.close = webcache_close,
	.name = "webcache",
	.depends = "",
};

/* register func */
void
webcache_register() {
	processor_register(&processor_module);
}
