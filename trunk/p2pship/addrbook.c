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
#include "../config.h"

#define _GNU_SOURCE /* getline */
#include <stdio.h>

#ifdef CONFIG_LIBEBOOK_ENABLED
#include <libebook/e-book.h>
#include <libosso.h>
#undef LOG_DEBUG
#undef LOG_INFO
#endif

#include "addrbook.h"
#include "ident.h"
#include "ship_debug.h"
#include "ship_utils.h"
#include "processor.h"
#include "ui.h"

#ifdef CONFIG_LIBEBOOK_ENABLED

/* the ebook */
static EBook *book = 0;

static void addrbook_libebook_signal(void *obj, gpointer data);
static int addrbook_libebook_import(ship_list_t *imps, int *concount, int query);
static int addrbook_libebook_retrieve(ship_list_t *list);
#endif

/* the file where to store what we've imported */
static char *contacts_file = 0;

/* todo: see if it helps to reinit everything related to ebook for each access.
   + cache previous results for a while */
static ship_list_t *addrbook_lock = 0;


/* loads up all the contacts we already have imported */
int
addrbook_load_imported(ship_list_t *list)
{
	int ret = -1;
	struct stat sdata;
	FILE *f = 0;
	
	if (stat(contacts_file, &sdata)) {
		LOG_WARN("Contacts log file %s does not exist\n", contacts_file);
		return -2;
	}
		
	/* load file .. */
	ship_lock(addrbook_lock);
	f = fopen(contacts_file, "r");
	if (f) {
		char *buf = NULL;
		size_t len = 0;
		ssize_t got = 0;
		while ((got = getline(&buf, &len, f)) > -1) {
			/* check what we've got.. */
			buf = trim(buf);
			switch (*buf) {
			case '#':
			case ';':
			case '/':
			case 0:
				/* skip empty / comments */
				break;
			default: {
				char **tokens = 0;
				int toklen = 0;
				int ct = 0;
				if (!ship_tokenize(buf, strlen(buf), &tokens, &toklen, ',')) {
					contact_t *c = ident_contact_new();
					if (c && toklen > 3) {
						ship_urldecode(tokens[0]);
						ship_urldecode(tokens[1]);
						ship_urldecode(tokens[2]);

						ASSERT_TRUE(c->sip_aor = strdup(tokens[0]), cerr);
						ASSERT_TRUE(c->name = strdup(tokens[1]), cerr);
						ASSERT_TRUE(c->db_id = strdup(tokens[2]), cerr);
						c->added = atoi(tokens[3]);

						/* todo: load the optional stuff */
						for (ct = 4; ct < toklen; ct++) {
							char *p = strchr(tokens[ct], '=');
							if (p) {
								p[0] = 0;
								p++;

								ship_urldecode(tokens[ct]);
								ship_urldecode(p);
								
								ship_ht_put_string(c->params, tokens[ct], strdup(p));
							}
						}

						LOG_DEBUG("Loaded %s <%s>\n", c->name, c->sip_aor);
						ship_list_add(list, c);
						c = 0;
					}
				cerr:
					ship_tokens_free(tokens, toklen);
					ident_contact_free(c);
				}
			} break;
			}
		}
		fclose(f);
		freez(buf);
		ret = 0;
	} else {
		USER_ERROR("Failed to open contacts file %s\n", contacts_file);
	}
	
	LOG_DEBUG("Loaded %d entries\n", ship_list_length(list));
	ship_unlock(addrbook_lock);
	return ret;
}

/* saves the comma-separated list of contacts */
int
addrbook_save_imported(ship_list_t *list)
{
	int ret = -1;
	void *ptr = 0;
	contact_t *c = 0;
	FILE *f = NULL;
	ship_list_t *keys = 0;

	char *buf = 0, *tmp = 0, *tmp2 = 0;
	int len = 0, size = 0;
	
	while ((c = ship_list_next(list, &ptr))) {
		char tbuf[32];
		char *k = 0;

		if (c->sip_aor) {
			ASSERT_TRUE(tmp2 = ship_urlencode(c->sip_aor), err);
			ASSERT_TRUE((tmp = append_str(tmp2, buf, &size, &len)) && (buf = tmp), err);
			freez(tmp2);
		}
		ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);
		
		if (c->name) {
			ASSERT_TRUE(tmp2 = ship_urlencode(c->name), err);
			ASSERT_TRUE((tmp = append_str(tmp2, buf, &size, &len)) && (buf = tmp), err);
			freez(tmp2);
		}
		ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);

		if (c->db_id) {
			ASSERT_TRUE(tmp2 = ship_urlencode(c->db_id), err);
			ASSERT_TRUE((tmp = append_str(tmp2, buf, &size, &len)) && (buf = tmp), err);
			freez(tmp2);
		}
		ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);
		
		sprintf(tbuf, "%d", (int)c->added);
		ASSERT_TRUE((tmp = append_str(tbuf, buf, &size, &len)) && (buf = tmp), err);

		/* add the optional stuff */
		ASSERT_TRUE(keys = ship_ht_keys(c->params), err);
		while ((k = ship_list_pop(keys))) {
			char *v = ship_ht_get_string(c->params, k);

			ASSERT_TRUE((tmp = append_str(",", buf, &size, &len)) && (buf = tmp), err);
			
			ASSERT_TRUE(tmp2 = ship_urlencode(k), err);
			ASSERT_TRUE((tmp = append_str(tmp2, buf, &size, &len)) && (buf = tmp), err);
			freez(tmp2);

			ASSERT_TRUE((tmp = append_str("=", buf, &size, &len)) && (buf = tmp), err);

			ASSERT_TRUE(tmp2 = ship_urlencode(v), err);
			ASSERT_TRUE((tmp = append_str(tmp2, buf, &size, &len)) && (buf = tmp), err);
			freez(tmp2);
			freez(k);
		}
		
		ASSERT_TRUE((tmp = append_str("\n", buf, &size, &len)) && (buf = tmp), err);
		ship_list_empty_free(keys);
		ship_list_free(keys);
		keys = 0;
	}

	ship_lock(addrbook_lock);
	if (!(f = fopen(contacts_file, "w"))) {
		LOG_ERROR("Could not open contacts log file %s\n", contacts_file);
		goto err;
	}
	if (len != fwrite(buf, sizeof(char), len, f))
		goto err;
	
	ret = 0;
 err:
	if (f)
		fclose(f);
	ship_unlock(addrbook_lock);

	freez(buf);
	freez(tmp2);

	if (keys) {
		ship_list_empty_free(keys);
		ship_list_free(keys);
		keys = 0;
	}

	return ret;
}

/* 
   retrieve a list of contacts from the address book 

   The list is filled with contact_t entries. These should all be
   'normalized' already.
*/
int
addrbook_retrieve_contacts(ship_list_t *list)
{
#ifdef CONFIG_LIBEBOOK_ENABLED
	return addrbook_libebook_retrieve(list);
#else
	/* cant do anything */
	return -1;
#endif
}


/* returns a 'normalized' version of the SIP aor. currently this is
   *witout* any possible 'sip:' prefix or any suffix / parameters! */
char *
addrbook_normalize_aor(char *aor)
{
	char *start, *end;
	char *ret = 0;

	if (!aor)
		return NULL;
	
	/* skip anything before a ':' */
	if ((start = strchr(aor, ':')))
		start++;
	else
		start = aor;
	
	if (!(end = strchr(start, ';')))
		end = start + strlen(start);
	
	if ((ret = mallocz(end-start+1)))
		strncpy(ret, start, end-start);
	return ret;
}

/* checks whether the givne user's contact list contains the given
   contact */
int
addrbook_has_contact(char *user_aor, char *contact_aor)
{
	ship_list_t *list = 0;
	char *norm = 0;
	contact_t *buddy = 0;
	int ret = 0;
	
	ASSERT_TRUE(norm = addrbook_normalize_aor(contact_aor), err);
	ASSERT_TRUE(list = ship_list_new(), err);
	if (addrbook_retrieve_contacts(list))
		goto err;
	
	while ((buddy = ship_list_pop(list))) {
		if (!strcmp(norm, buddy->sip_aor))
			ret = 1;
		ident_contact_free(buddy);
	}
 err:
	freez(norm);
	ship_list_free(list);
	return ret;
}


/* imports contacts */
int
addrbook_import_contacts(ship_list_t *newco, int *concount, int query)
{
	ship_list_t *imps = 0;
	int ret = -1;
	void *ptr = 0;
	contact_t *c = 0;
	*concount = 0;

#ifdef OLD_LOGIC
	void *last = 0;
	ship_list_t *done = 0;
	ship_list_t *imported = 0;

	/* this is the 'old' way - check whether we already have
	   imported an entry, skip if so. */

	/* copy over to an array for filtering */
	ASSERT_TRUE(imps = ship_list_new(), err);
	while (c = ship_list_next(newco, &ptr))
		ship_list_add(imps, c);

	/* load up what we've imported already */
	ASSERT_TRUE(imported = ship_list_new(), err);
	ASSERT_TRUE(done = ship_list_new(), err);
	ASSERT_ZERO(addrbook_load_imported(imported), err);
	ptr = 0;
	while (c = ship_list_next(imported, &ptr))
		ship_list_add(done, c);
	
	/* filter out those we already have based on the sip aor */
	ptr = 0;
	while (c = ship_list_next(imps, &ptr)) {
		void *ptr2 = 0;
		contact_t *c2 = 0;
		int found = 0;
		
		while (!found && (c2 = ship_list_next(imported, &ptr2))) {
			if (!strcmp(c2->sip_aor, c->sip_aor)) {
				found = 1;
				/* should we query whether to update the field if something
				   has changed? */
			}
		}	
		
		/* here we just skip those we already have imported */
		if (found) {
			ptr = last;
			ship_list_remove(imps, c);
		}
		last = ptr;
	}
		
	/* todo: check for ones with same sip aor? */
	/* todo: check for ones with same name? */
#else
	/* this is another way - check if we *have* the entry, skip if so */
	ASSERT_TRUE(imps = ship_list_new(), err);
	while ((c = ship_list_next(newco, &ptr))) {
		if (!addrbook_has_contact(NULL, c->sip_aor))
			ship_list_add(imps, c);
	}
#endif


#ifdef CONFIG_LIBEBOOK_ENABLED
	ret = addrbook_libebook_import(imps, concount, query);
#else	
	*concount = ship_list_length(imps);
	
	/* print out */
	while ((c = ship_list_next(newco, &ptr))) {
		LOG_WARN("Ignoring import of contact %s, sip: %s\n",
			 c->name, c->sip_aor);
	}
	ret = 0;
#endif

 err:
#ifdef OLD_LOGIC
	if (!ret)
		addrbook_save_imported(done);
	
	if (imported) {
		while (c = ship_list_pop(imported))
			ident_contact_free(c);
		ship_list_free(imported);
	}

	ship_list_free(imps);
	ship_list_free(done);
#endif
	return ret;
}

#ifdef CONFIG_LIBEBOOK_ENABLED

/* inits the libebook logic. load the library, sets out listeners */
static int
addrbook_libebook_init()
{
	GError *error = 0;
	int ret = -1;

	/* open up the database */
#ifdef CONFIG_MAEMOEXTS_ENABLED
	book = e_book_new_from_uri("file:///home/user/.osso-abook/db", &error);
#else
	book = e_book_new_system_addressbook (&error);
#endif
	ASSERT_TRUE(book, err);
	ASSERT_TRUE(e_book_open(book, FALSE, &error), err);
	g_signal_connect(G_OBJECT(book), "backend-died", 
			 G_CALLBACK(addrbook_libebook_signal),
			 NULL);
	
	/*
	ASSERT_TRUE(book_listener = e_book_listener_new(), err);
	g_signal_connect(G_OBJECT(book_listener), "response", 
			 G_CALLBACK(addrbook_libebook_signal),
			 NULL);
	*/

	ret = 0;
err:
	if (error)
		g_error_free(error);
	return ret;
}

/* closes things .. */
static void
addrbook_libebook_close()
{
	/*
	if (book_listener) {
		e_book_listener_stop(book_listener);
		g_object_unref(book_listener);
	}
	*/
	
	/* close the database */
	if (book)
		g_object_unref(book);
}

/* callback for signals */
static void
addrbook_libebook_signal(void *obj, gpointer data)
{
	addrbook_libebook_close();
	addrbook_libebook_init();
		
}

/* calls to import contacts */
static int
addrbook_libebook_import(ship_list_t *imps, int *concount, int query)
{
	int ret = -1;
	void *ptr = 0;
	contact_t *c = 0;
	GError *error = 0;
	*concount = 0;

	/* query & import */
	ship_lock(addrbook_lock);
	if (ship_list_first(imps) && (!query || ui_query_import_contacts(imps) > 0)) {

		ptr = 0;
		while ((c = ship_list_next(imps, &ptr))) {
			EContact *contact = 0;
			EContactName name;
			char *arr[2], *ln;
			arr[1] = 0;
			bzero(&name, sizeof(name));
			ret = -1;

			/* create a new contact */
			ASSERT_TRUE(contact = e_contact_new(), cerr);
			
			/* create the name struct */
			ln = strchr(c->name, ' ');
			if (ln) {
				ASSERT_TRUE(name.given = strndup(c->name, ln - c->name), cerr);
				ASSERT_TRUE(name.family = strdup(ln+1), cerr);
			} else {
				ASSERT_TRUE(name.given = strdup(c->name), cerr);
			}

			/* simple strings */
			e_contact_set(contact, E_CONTACT_FULL_NAME, c->name);
			e_contact_set(contact, E_CONTACT_GIVEN_NAME, name.given);
			if (name.family)
				e_contact_set(contact, E_CONTACT_FAMILY_NAME, name.family);
 			if (ship_ht_get_string(c->params, "category"))
				e_contact_set(contact, E_CONTACT_CATEGORIES, ship_ht_get_string(c->params, "category"));
			
			/* EContactName */
			e_contact_set(contact, E_CONTACT_NAME, &name);

			/* array of strings */
 			if (ship_ht_get_string(c->params, "email")) {
				arr[0] = ship_ht_get_string(c->params, "email");
				e_contact_set(contact, E_CONTACT_EMAIL, arr);
			}
			arr[0] = c->sip_aor;
			e_contact_set(contact, E_CONTACT_SIP, arr);

			ASSERT_TRUE(e_book_add_contact(book, contact, &error), cerr);
			ret = 0;
		cerr:
			g_object_unref(contact);
			freez(name.family);
			freez(name.given);
			
			if (ret)
				goto err;

			/* save what we've done */
			c->added = time(NULL);
			(*concount)++;
		}
	}

	ret = 0;
 err:
	if (error) {
		if (query) 
			ui_print_error("Error importing the contacts: %s.\n", error->message);
		g_error_free(error);
	} else if (ret && query) {
		ui_print_error("An error occured while importing the contacts.\n");
	}
	ship_unlock(addrbook_lock);
	return ret;
}

/* retrieve a list of contacts from the address book */
static int
addrbook_libebook_retrieve(ship_list_t *list)
{
	int ret = -1;
	contact_t *ct = 0;
	GError *error = 0;
	GList *contacts = 0, *loop;
	EBookQuery *query = 0;

	ship_lock(addrbook_lock);
	ASSERT_TRUE(query = e_book_query_any_field_contains(""), err);
	ASSERT_TRUE(e_book_get_contacts(book, query, &contacts, &error), err);
	ASSERT_ZERO(error, err);

	for (loop = contacts; loop; loop = g_list_next(loop)) {
		EContact *c = loop->data;
		char *name = 0;
		
		name = e_contact_get(c, E_CONTACT_OSSO_CONTACT_STATE);
		if (!name || strcmp(name, "DELETED")) {
			char **arrs = 0;

			ASSERT_TRUE(ct = ident_contact_new(), cerr);
			ASSERT_TRUE(ct->name = e_contact_get(c, E_CONTACT_FULL_NAME), cerr);
			
			ASSERT_TRUE(arrs = e_contact_get(c, E_CONTACT_SIP), cerr);
			ASSERT_TRUE(ct->sip_aor = addrbook_normalize_aor(arrs[0]), cerr);
			
			/* apparently arrs doesn't need to be free'd afterwards */
			g_list_foreach((GList*)arrs, (GFunc)g_free, NULL);
			ship_list_add(list, ct);
			ct = 0;
		cerr:
			ident_contact_free(ct);
		}
		if (name)
			g_free(name);
	}
	ret = 0;
 err:
	if (contacts) {
		g_list_free(contacts);
	}
	
	if (query) {
		e_book_query_unref(query);
	}

	if (error) {
		LOG_ERROR("Error getting contacts: %s\n", error->message);
		g_error_free(error);
	}
	ship_unlock(addrbook_lock);

	return ret;
}

#endif

/* inits the  */
int 
addrbook_init(processor_config_t *config)
{
	ASSERT_ZERO(processor_config_get_string(config, P2PSHIP_CONF_CONTACTS_FILE, &contacts_file), err);
	ASSERT_TRUE(addrbook_lock = ship_list_new(), err);
#ifdef CONFIG_LIBEBOOK_ENABLED
	ASSERT_ZERO(addrbook_libebook_init(), err);
#endif
	return 0;
 err:
	return -1;
}

/* closes the addrbookity manager */
void 
addrbook_close()
{
#ifdef CONFIG_LIBEBOOK_ENABLED
	addrbook_libebook_close();
#endif
	ship_list_free(addrbook_lock);
}

/* the addrbook register */
static struct processor_module_s processor_module = 
{
	.init = addrbook_init,
	.close = addrbook_close,
	.name = "addrbook",
	.depends = "ui",
};

/* register func */
void
addrbook_register() {
	processor_register(&processor_module);
}
