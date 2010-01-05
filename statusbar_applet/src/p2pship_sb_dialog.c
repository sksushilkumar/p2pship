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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <glib/gasyncqueue.h>
#include <gtk/gtk.h>
#include <libintl.h>
#include <locale.h>
#include <hildon/hildon-hvolumebar.h>
#include <hildon/hildon-program.h>
#include <hildon/hildon-banner.h>
#include <libhildonwm/hd-wm.h>
#include <libhildonwm/hd-wm-application.h>
#include <libhildondesktop/statusbar-item.h>
#include <libhildondesktop/libhildondesktop.h>
#include <X11/X.h>
#include <X11/Xlib.h>

#include <gconf/gconf-client.h>
#include <hildon/hildon-sound.h>
#include <dirent.h>
#include <time.h>
#include <hildon/hildon-controlbar.h>
#include <hildon/hildon.h>
#include <string.h>
#include <glib/glist.h>

#include "p2pship_sb.h"

/* the dialog */
static GtkDialog *dialog = 0;

/*
  todo next up:

  - struct for storing the events
  - using those in the renderers
  - parsing events
  - thread for receiving events
  - update / create destroy logic of gobjs

  - indicate outgoing / incoming in the call log
*/

/**********************************************
 *
 * data structs
 *
 */

/* a userlist entry */
typedef struct user_entry_s
{
	char *name;
	char *aor;
} user_entry_t;

/* a log entry */
typedef struct log_entry_s 
{
	/* time */
	time_t t;
	
	/* type, just to have one less enum, this uses the icon ids */
	int type;
	
	/* direction - local or remote */
	int local;

	/* local, remote aor & name */
	char *local_aor;
	char *local_name;
	
	char *remote_aor;
	char *remote_name;
	
	/* the verdict - blocked? */
	int blocked;

	/* meta - pathlength presented */
	int pathlen;

	/* has been seen already? */
	int seen;

} log_entry_t;

/* some strings */
static const char *blacklist_name = "blacklist";
static const char *whitelist_name = "whitelist";

/* the cols */
enum {
	ID_COL, TIME_COL, DIR_COL, TYPE_COL, NAME_COL, COLS 
};

enum {
	USER_ID_COL, USER_NAME_COL, USER_COLS 
};

enum 
	{
		NO_ICON,
		CALL_ICON,
		CHAT_ICON,
		LOCAL_ICON,
		REMOTE_ICON,
		BLOCKED_LOCAL_ICON,
		BLOCKED_REMOTE_ICON,
		ICONS
	};

static GtkWidget* imgs[ICONS];

typedef struct {

	GtkTreeSelection *select;
	GtkTreeStore *store;

	/* the data list */
	GList **list;
} list_data_t;

/* the buttons for the call log view */
typedef struct {
	list_data_t parent;

	GtkButton *block_button;
	GtkButton *allow_button;
	GtkButton *clear_button;
} loglist_data_t;

/* the buttons for the call log view */
typedef struct {
	list_data_t parent;
	
	GtkButton *remove_button;

	/* the name of the list */
	char *name;

} userlist_data_t;

/* protos */
static void refetch_user_list(userlist_data_t *list);
static void reload_call_log(list_data_t *btns);
static char *get_selected(list_data_t *btns);
static void reload_user_list(userlist_data_t *btns);

/* DATA .. */
static loglist_data_t log_btns;
static loglist_data_t blocked_calls;
static userlist_data_t whitelist;
static userlist_data_t blacklist;

static GList *list_whitelist = 0;
static GList *list_blacklist = 0;
static GList *list_log = 0;
static GList *list_blockedlog = 0;


/**********************************************
 *
 * general stuff
 *
 */

#define freez(l) if (l) { free(l); l = 0; }

static void
clear_list(GList **l, void (*func) (void *))
{
	GList *e;

	while (*l) {
		e = (*l)->next;
		if (!e) e = *l;

		func(e->data);
		if (*l != e)
			g_list_delete_link(*l, e);
		else {
			g_list_free(*l);
			*l = 0;
		}
	}
}

static void
free_log_entry(log_entry_t *l)
{
	if (!l)
		return;

	freez(l->local_aor);
	freez(l->local_name);
	freez(l->remote_aor);
	freez(l->remote_name);
	freez(l);
}

static void
clear_log_list(GList **l)
{
	clear_list(l, free_log_entry);
}

static void
free_user_entry(user_entry_t *l)
{
	if (!l)
		return;

	freez(l->name);
	freez(l->aor);
	freez(l);
}

static void
clear_user_list(GList **l)
{
	clear_list(l, free_user_entry);
}

static char *
get_selected(list_data_t *btns)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	if (gtk_tree_selection_get_selected(btns->select, &model, &iter)) {
		char *char_data = 0;
		gtk_tree_model_get(model, &iter, 
				   ID_COL, &char_data,
				   -1);
		return char_data;
	}
	return NULL;
}

/* checks if the given is on the whitelist / blacklist */
static int
is_on_userlist(char *name, GList *l)
{
	while (l) {
		if (l->data) {
			user_entry_t *e = (user_entry_t *)l->data;
			if (!strcmp(e->aor, name))
				return 1;
		}
		l = l->next;
	}
	return 0;
}

static int
is_on_whitelist(char *name)
{
	return is_on_userlist(name, list_whitelist);
}

static int
is_on_blacklist(char *name)
{
	return is_on_userlist(name, list_blacklist);
}

/* parse one parameter, return strdup of it */
static char *
parse_event_next_param(char *str, int *pos, char ch)
{
	char *t, *ret = 0;

	if (str[*pos] == ch)
		(*pos)++;
	
	if (!strlen(str+(*pos)))
		return 0;
	
	if (!(t = strchr(str+(*pos), ch)))
		t = str+strlen(str);

	ret = (char*)strndup(str+(*pos), (t-str)-(*pos));
	(*pos) += t-str-(*pos);
	return ret;
}


/* parses an event-string to a struct */
static log_entry_t *
parse_event(char *str)
{
	int p = 0;
	char *tmp;
	log_entry_t *e = 0;

	if (!(e = malloc(sizeof(log_entry_t))))
		goto err;
	
	bzero(e, sizeof(log_entry_t));
	
	/* do manual parsing as we do not have any utils available */
	e->t = time(0);
	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	if (!strcmp(tmp, "conversation")) 
		e->type = CHAT_ICON;
	else 
		e->type = CALL_ICON;
	
	free(tmp);

	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	if (!strcmp(tmp, "local"))
		e->local = 1;
	free(tmp);
	
	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	e->local_aor = tmp;
	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	e->local_name = tmp;
	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	e->remote_aor = tmp;
	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	e->remote_name = tmp;

	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	if (strcmp("allow", tmp))
		e->blocked = 1;
	free(tmp);
	
	if (!(tmp = parse_event_next_param(str, &p, ';')))
		goto err;
	e->pathlen = atoi(tmp);
	free(tmp);	    

	return e;
 err:
	if (e) {
		if (e->remote_aor) free(e->remote_aor);
		if (e->remote_name) free(e->remote_name);
		if (e->local_aor) free(e->local_aor);
		if (e->local_name) free(e->local_name);
		free(e);
	}
	return 0;
}

static user_entry_t*
parse_user_entry(char *str)
{
	int p = 0;
	char *tmp;
	user_entry_t* ret = malloc(sizeof(user_entry_t));

	if (!ret)
		return ret;

	bzero(ret, sizeof(user_entry_t));
	
	if (!(tmp = parse_event_next_param(str, &p, ',')))
		goto err;
	ret->aor = tmp;

	if (!(tmp = parse_event_next_param(str, &p, ',')))
		goto err;
	ret->name = tmp;
	return ret;
 err:
	if (ret->name)
		free(ret->name);
	if (ret->aor)
		free(ret->aor);
	free(ret);
	return NULL;
}

/**********************************************
 *
 * callbacks for the userlists
 *
 */

static void 
userlist_selection_cb(GtkTreeSelection *selection, gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	userlist_data_t *btns = data;

	if (get_selected((list_data_t*)btns))
		gtk_widget_set_sensitive((GtkWidget*)btns->remove_button, TRUE);
	else
		gtk_widget_set_sensitive((GtkWidget*)btns->remove_button, FALSE);
}

static void 
remove_clicked_cb(GtkButton *button, gpointer data)
{
	userlist_data_t *btns = data;
	char *name = 0;
	char *tmp = 0;
	
	name = get_selected((list_data_t*)btns);
	/* do a remove */
	if (name && (tmp = malloc(strlen(name) + 32))) {
		sprintf(tmp, "ac:remove:%s:", btns->name);
		strcat(tmp, name);
		
		p2pship_sendrecv_str(tmp, NULL);
		free(tmp);
	}

	refetch_user_list(btns);
	reload_call_log(&log_btns);
	reload_call_log(&blocked_calls);
}

/**********************************************
 *
 * user list
 *
 */

static void 
populate_user_list(user_entry_t *entry,
		   list_data_t* lbtns)
{
 	GtkTreeIter iter;
	char *tmp = 0;

	if (!entry)
		return;

	tmp = malloc(strlen(entry->aor) + strlen(entry->name) + 16);
	if (!tmp)
		return;
	strcpy(tmp, entry->name);
	strcat(tmp, " (");
	strcat(tmp, entry->aor);
	strcat(tmp, ")");

	gtk_tree_store_append(lbtns->store, &iter, NULL);
	gtk_tree_store_set(lbtns->store, &iter, 
			   USER_ID_COL, entry->aor,
			   USER_NAME_COL, tmp,
			   -1);
	free(tmp);
}

static void
reload_user_list(userlist_data_t *btns)
{
	list_data_t *lbtns = (list_data_t*)btns;

	if (dialog) {
		gtk_tree_store_clear(lbtns->store);
		g_list_foreach(*lbtns->list, populate_user_list, btns);
	}
}

static GtkWidget *
construct_user_list(userlist_data_t *btns)
{
	GtkWidget *list;
	GtkTreeIter iter;
	GtkCellRenderer *renderer;
	GtkWidget *tree;
	GtkTreeViewColumn *column;
	GtkContainer *vbox, *hbox;
	GtkWidget *sb;
	list_data_t *lbtns = (list_data_t *)btns;

 	lbtns->store = gtk_tree_store_new(USER_COLS, G_TYPE_STRING, G_TYPE_STRING);
	renderer = gtk_cell_renderer_text_new ();

	tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (lbtns->store));
	
	column = gtk_tree_view_column_new_with_attributes("SIP AOR", renderer, "text", USER_NAME_COL, NULL);
	gtk_tree_view_column_set_spacing(column, 2);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);

	/* the layout */
	vbox = (GtkContainer*)gtk_vbox_new(FALSE, 0);
	
	sb = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(sb), tree);
	gtk_container_add(vbox, sb);

	hbox = (GtkContainer*)gtk_hbox_new(FALSE, 0);
	btns->remove_button = (GtkButton*)gtk_button_new_with_label("Remove");
	g_signal_connect(G_OBJECT(btns->remove_button), "clicked", 
			 G_CALLBACK(remove_clicked_cb),
			 btns);
	gtk_widget_set_sensitive((GtkWidget*)btns->remove_button, FALSE);

	gtk_box_pack_start(hbox, btns->remove_button, FALSE, FALSE, 1);
	gtk_box_pack_end(vbox, hbox, FALSE, FALSE, 1);

	/* Setup the selection handler */
	lbtns->select = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
	gtk_tree_selection_set_mode(lbtns->select, GTK_SELECTION_SINGLE);
	g_signal_connect(G_OBJECT(lbtns->select), "changed", 
			 G_CALLBACK(userlist_selection_cb),
			 btns);

	return (GtkWidget*)vbox;
}

/**********************************************
 *
 * log stuff
 *
 */

static void 
block_clicked_cb(GtkButton *button, gpointer data)
{
	loglist_data_t *btns = data;
	char *name = 0;
	char *tmp = 0;

	name = get_selected((list_data_t*)btns);
	if (name && (tmp = malloc(strlen(name) + 32))) {
		sprintf(tmp, "ac:add:blacklist:%s", name);
		p2pship_sendrecv_str(tmp, NULL);
		sprintf(tmp, "ac:remove:whitelist:%s", name);
		p2pship_sendrecv_str(tmp, NULL);
		free(tmp);
	}

	refetch_user_list(&whitelist);
	refetch_user_list(&blacklist);
	reload_call_log((list_data_t*)btns);
}

static void 
allow_clicked_cb(GtkButton *button, gpointer data)
{
	loglist_data_t *btns = data;
	char *name = 0;
	char *tmp = 0;

	name = get_selected((list_data_t *)btns);
	if (name && (tmp = malloc(strlen(name) + 32))) {
		sprintf(tmp, "ac:add:whitelist:%s", name);
		p2pship_sendrecv_str(tmp, NULL);
		sprintf(tmp, "ac:remove:blacklist:%s", name);
		p2pship_sendrecv_str(tmp, NULL);
		free(tmp);
	}

	refetch_user_list(&whitelist);
	refetch_user_list(&blacklist);
	reload_call_log((list_data_t *)btns);
}

static void 
clear_clicked_cb(GtkButton *button, gpointer data)
{
	loglist_data_t *btns = data;
	list_data_t *btns2 = (list_data_t *)btns;

	clear_log_list(btns2->list);
	reload_call_log(btns2);
}

/* Prototype for selection handler callback */
static void 
list_selection_cb(GtkTreeSelection *selection, gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	loglist_data_t *btns = data;
	char *char_data = 0;

	if (char_data = get_selected((list_data_t *)btns)) {	       
		if (is_on_whitelist(char_data) && !is_on_blacklist(char_data)) {
			gtk_widget_set_sensitive((GtkWidget*)btns->allow_button, FALSE);
			//gtk_button_set_label(btns->allow_button, "Remove from allowed");
		} else {
			//gtk_button_set_label(btns->allow_button, "Allow");
			gtk_widget_set_sensitive((GtkWidget*)btns->allow_button, TRUE);
		}

		if (is_on_blacklist(char_data)) {
			gtk_widget_set_sensitive((GtkWidget*)btns->block_button, FALSE);
			//gtk_button_set_label(btns->block_button, "Unblock");
		} else {
			//gtk_button_set_label(btns->block_button, "Block");
			gtk_widget_set_sensitive((GtkWidget*)btns->block_button, TRUE);
		}

	} else {
		//gtk_button_set_label(btns->block_button, "Block");
		//gtk_button_set_label(btns->allow_button, "Allow");
		gtk_widget_set_sensitive((GtkWidget*)btns->allow_button, FALSE);
		gtk_widget_set_sensitive((GtkWidget*)btns->block_button, FALSE);
	}
}

/**********************************************
 *
 * call log
 *
 */

#define maxlen(a, b) (strln(a) > strlen(b)? strlen(a) : strlen(b))

/* creates a human-readable date string */
static int
create_date_str(time_t t, char *buf, int len)
{
	struct tm tm;
	int diff;
	memset(&tm, 0, sizeof(struct tm));
	
	if (!localtime_r(&t, &tm))
		return 0;
	
	diff = time(0) - t;
	if (diff < (24 * 60 * 60))
		return strftime(buf, len, "%H:%M", &tm);
	else if (diff < (24 * 60 * 60 * 7))
		return strftime(buf, len, "%a, %H:%M", &tm);
	else
		return strftime(buf, len, "%d %b, %H:%M:%S (%z)", &tm);
}

/* returns the number of blocked calls */
int
get_blocked_calls_count()
{
	int ret = 0;
	GList *l = list_blockedlog;

	while (l) {
		if (l->data) {
			log_entry_t *e = (log_entry_t*)l->data;
			if (!e->seen)
				ret++;
		}
		l = l->next; 
	}

	return ret;
}

static int
get_dir_icon(log_entry_t *e) 
{
	if (e->local && e->blocked)
		return BLOCKED_LOCAL_ICON;
	else if (e->local)
		return LOCAL_ICON;
	else if (e->blocked)
		return BLOCKED_REMOTE_ICON;
	else
		return REMOTE_ICON;
}

static void 
populate_call_log(gpointer data,
		  gpointer user_data)
{
	list_data_t *btns = user_data;
	log_entry_t *e = data;
	GtkTreeIter iter;
	int len = 0;
	char tmp[64], *tmp2 = 0;

	if (!data)
		return;

	create_date_str(e->t, &tmp[1], sizeof(tmp)-2);
	if (!e->seen) tmp[0] = 'b';
	else tmp[0] = 'n';
	
	tmp2 = malloc(strlen(e->remote_aor) + strlen(e->remote_name) + 32);
	if (tmp2) {
		if (!e->seen) tmp2[0] = 'b';
		else tmp2[0] = 'n';
		strcpy(tmp2+1, e->remote_name);
		strcat(tmp2, " (");
		strcat(tmp2, e->remote_aor);
		strcat(tmp2, ")");
		
		/* this crashes.. clearly not thread safe.. ?
		   ups.. hadn't gdk_init_threads()... */
		gtk_tree_store_append(btns->store, &iter, NULL);
		gtk_tree_store_set(btns->store, &iter, 
				   ID_COL, e->remote_aor,
				   TIME_COL, tmp,
				   DIR_COL, get_dir_icon(e),
				   TYPE_COL, e->type,
				   NAME_COL, tmp2,				   
				   -1);
		free(tmp2);
	}
}

static void
reload_call_log(list_data_t *btns)
{
	if (dialog) {
		gtk_tree_store_clear(btns->store);
		g_list_foreach(*btns->list, populate_call_log, btns);
	}
}

static void 
set_text(GtkTreeViewColumn *tree_column,
	 GtkCellRenderer *cell,
	 GtkTreeModel *tree_model,
	 GtkTreeIter *iter,
	 gpointer data)
{
	char *char_data = 0;
	gtk_tree_model_get(tree_model, iter, 
			   (int)data, &char_data,
			   -1);
	
	if (char_data[0] == 'b')
		g_object_set(cell, "weight", PANGO_WEIGHT_BOLD, NULL);
	else 
		g_object_set(cell, "weight", PANGO_WEIGHT_NORMAL, NULL);
	
	g_object_set(cell, "text", char_data+1, NULL);
}

static void 
choose_icon(GtkTreeViewColumn *tree_column,
	    GtkCellRenderer *cell,
	    GtkTreeModel *tree_model,
	    GtkTreeIter *iter,
	    gpointer data)
{
	int int_data = 0;
	gtk_tree_model_get(tree_model, iter, 
			   (int)data, &int_data,
			   -1);
	g_object_set(cell, "pixbuf", gtk_image_get_pixbuf(imgs[int_data]), NULL);
}

static GtkWidget *
construct_call_log(loglist_data_t *btns, int show_verdict)
{
	GtkWidget *list;
	GtkCellRenderer *time_renderer, *renderer, *type_renderer, *verdict_renderer;
	GtkWidget *tree;
	GtkTreeViewColumn *column;
	GtkContainer *vbox, *hbox;
	GtkWidget *sb;
	list_data_t *lbtns = (list_data_t *)btns;

	lbtns->store = gtk_tree_store_new(COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT,
					  G_TYPE_STRING);

	/* renderers */
	renderer = gtk_cell_renderer_text_new ();
	time_renderer = gtk_cell_renderer_text_new ();
	g_object_set(time_renderer, "alignment", PANGO_ALIGN_RIGHT, NULL);

	type_renderer = gtk_cell_renderer_pixbuf_new();
	verdict_renderer = gtk_cell_renderer_pixbuf_new();

	tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (lbtns->store));

	column = gtk_tree_view_column_new_with_attributes ("Time", time_renderer, "text", TIME_COL, NULL);
	gtk_tree_view_column_set_spacing(column, 2);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);
	gtk_tree_view_column_set_cell_data_func(column, time_renderer, set_text, TIME_COL, (void*)NULL);

	column = gtk_tree_view_column_new_with_attributes ("Direction", type_renderer, "pixbuf", DIR_COL, NULL);
	gtk_tree_view_column_set_spacing(column, 0);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);
	gtk_tree_view_column_set_cell_data_func(column, type_renderer, choose_icon, DIR_COL, (gpointer)NULL);

	column = gtk_tree_view_column_new_with_attributes ("Type", type_renderer, "pixbuf", TYPE_COL, NULL);
	gtk_tree_view_column_set_spacing(column, 0);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);
	gtk_tree_view_column_set_cell_data_func(column, type_renderer, choose_icon, TYPE_COL, (gpointer)NULL);

	column = gtk_tree_view_column_new_with_attributes("SIP AOR", renderer, "text", NAME_COL, NULL);
	gtk_tree_view_column_set_spacing(column, 2);
	gtk_tree_view_append_column (GTK_TREE_VIEW (tree), column);
	gtk_tree_view_column_set_cell_data_func(column, renderer, set_text, NAME_COL, (gpointer)NULL);

	/* the layout */
	vbox = gtk_vbox_new(FALSE, 0);
	
	sb = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(sb), tree);
	gtk_container_add(vbox, sb);

	hbox = gtk_hbox_new(FALSE, 0);
	btns->block_button = gtk_button_new_with_label("Block");
	btns->allow_button = gtk_button_new_with_label("Allow always");
	btns->clear_button = gtk_button_new_with_label("Clear log");
	gtk_widget_set_sensitive(btns->allow_button, FALSE);
	gtk_widget_set_sensitive(btns->block_button, FALSE);
	g_signal_connect(G_OBJECT(btns->block_button), "clicked", 
			 G_CALLBACK(block_clicked_cb),
			 btns);
	g_signal_connect(G_OBJECT(btns->allow_button), "clicked", 
			 G_CALLBACK(allow_clicked_cb),
			 btns);
	g_signal_connect(G_OBJECT(btns->clear_button), "clicked", 
			 G_CALLBACK(clear_clicked_cb),
			 btns);

	gtk_box_pack_start(hbox, btns->block_button, FALSE, FALSE, 1);
	gtk_box_pack_start(hbox, btns->allow_button, FALSE, FALSE, 1);
	gtk_box_pack_end(hbox, btns->clear_button, FALSE, FALSE, 1);
	gtk_box_pack_end(vbox, hbox, FALSE, FALSE, 1);

	/* Setup the selection handler */
	lbtns->select = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree));
	gtk_tree_selection_set_mode(lbtns->select, GTK_SELECTION_SINGLE);
	g_signal_connect(G_OBJECT(lbtns->select), "changed", 
			 G_CALLBACK(list_selection_cb),
			 btns);

	return vbox;
}


/**********************************************
 *
 * main construct
 *
 */


static GtkWidget*
load_icon_from_file(char *icon)
{
	GtkWidget* ret = 0;
	char *tmp = malloc(strlen(icon) + strlen(ICON_ROOT) + 5);
	if (tmp) {
		strcpy(tmp, ICON_ROOT);
		strcat(tmp, "/");
		strcat(tmp, icon);
		ret = gtk_image_new_from_file(tmp);
		free(tmp);
	}

	return ret;
}

static GtkDialog *
construct_dialog()
{
	GtkDialog *dialog;
	GtkWidget *vbox;
	GtkWidget *view;
	GtkWidget *sb;
	GtkWidget *notebook;
	GList *l;

	dialog = gtk_dialog_new_with_buttons("Call filtering", NULL, 
					     GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
					     GTK_STOCK_CLOSE, NULL, NULL);
	vbox = gtk_vbox_new(FALSE, 0);
	
	/* create the pages */
	notebook = gtk_notebook_new();

	/* the blocked calls */
	view = construct_call_log(&blocked_calls, 0);
	reload_call_log(&blocked_calls);

	gtk_widget_set_size_request(view, 650, 200);
	gtk_notebook_append_page(notebook,
				 view,
				 gtk_label_new("Blocked calls"));

	/* the call log */
	view = construct_call_log(&log_btns, 1);
	reload_call_log(&log_btns);

	gtk_widget_set_size_request(view, 650, 200);
	gtk_notebook_append_page(notebook,
				 view,
				 gtk_label_new("Call log"));

	/* white / black lists */
	view = construct_user_list(&blacklist);
	reload_user_list(&blacklist);

	gtk_widget_set_size_request(view, 650, 200);
	gtk_notebook_append_page(notebook,
				 view,
				 gtk_label_new("Blocked users"));
	
	/* white */
	view = construct_user_list(&whitelist);
	reload_user_list(&whitelist);

	gtk_widget_set_size_request(view, 650, 200);
	gtk_notebook_append_page(notebook,
				 view,
				 gtk_label_new("Allowed users"));
	
	/* show 'em */
	gtk_container_add(GTK_CONTAINER(dialog->vbox), notebook);
	gtk_widget_set_style(dialog, NULL);

	/* .. */
	return dialog;
}

static int listener_active = 1;
static GThread *listener_thread = 0;

static void 
sipevent_cb(char *str, int len, void *data)
{
	log_entry_t *e = 0;
	if (e = parse_event(str)) {
		gdk_threads_enter();
		list_log = g_list_append(list_log, e);
		reload_call_log(&log_btns);
		
		if (e->blocked) {
			/* if blocked, then do this also: */
			list_blockedlog = g_list_append(list_blockedlog, parse_event(str));
			reload_call_log(&blocked_calls);
		}
		gdk_threads_leave();
	}
}

static void
refetch_user_list(userlist_data_t *list)
{
	GList **l = ((list_data_t*)list)->list;
	char *resp = 0;
	char cmd[512];
	
	sprintf(cmd, "ac:show:%s", list->name);

	/* clear the lists */
	clear_user_list(l);
	if (!p2pship_sendrecv_str(cmd, &resp)) {
		int p = 0;
		char *tmp = 0;
		while (tmp = parse_event_next_param(resp, &p, '\n')) {
			*(l) = g_list_append(*(l), parse_user_entry(tmp));
		}
		free(resp);
	}
	reload_user_list(list);
}

static void
listener_thread_run(void *data)
{
	while (listener_active) {
		gdk_threads_enter();
		refetch_user_list(&whitelist);
		refetch_user_list(&blacklist);
		gdk_threads_leave();

		p2pship_sendrecv_strloop("events:sip_log",
					 sipevent_cb, NULL);

		gdk_threads_enter();
		refetch_user_list(&whitelist);
		refetch_user_list(&blacklist);
		gdk_threads_leave();
		sleep(1);
	}
}


/* starts the thread that listens for events from the p2psip proxy */
static int
start_listener_thread()
{
	GError *err = 0;
	
	if (listener_thread = g_thread_create(&listener_thread_run, NULL, TRUE, &err))
		return 0;
	else
		return -1;
}

void
init_p2pship_dialog()
{
	/* common pre-loading & init */
	gdk_threads_init();
	imgs[NO_ICON] = load_icon_from_file("call.png");
	imgs[CALL_ICON] = load_icon_from_file("call.png");
	imgs[CHAT_ICON] = load_icon_from_file("chat.png");

	imgs[LOCAL_ICON] = load_icon_from_file("local.png");
	imgs[REMOTE_ICON] = load_icon_from_file("remote.png");
	imgs[BLOCKED_LOCAL_ICON] = load_icon_from_file("local_block.png");
	imgs[BLOCKED_REMOTE_ICON] = load_icon_from_file("remote_block.png");

	blocked_calls.parent.list = &list_blockedlog;
	log_btns.parent.list = &list_log;
	blacklist.parent.list = &list_blacklist;
	blacklist.name = blacklist_name;
	whitelist.parent.list = &list_whitelist;
	whitelist.name = whitelist_name;

	/*
	log_btns.parent.store = gtk_tree_store_new(USER_COLS, G_TYPE_STRING, G_TYPE_STRING);
	blocked_calls.parent.store = gtk_tree_store_new(USER_COLS, G_TYPE_STRING, G_TYPE_STRING);
	whitelist.parent.store = gtk_tree_store_new(USER_COLS, G_TYPE_STRING, G_TYPE_STRING);
	blacklist.parent.store = gtk_tree_store_new(USER_COLS, G_TYPE_STRING, G_TYPE_STRING);
	*/
	
	start_listener_thread();
}

static void 
set_seen(gpointer data,
	 gpointer user_data)
{
	log_entry_t *e = data;

	if (!data)
		return;
	e->seen = 1;
}

void 
show_p2pship_dialog()
{
	/* the dialog */	
	int resp = 0;
	
	/* just so we get to populate the list */
	dialog = 1;
	dialog = construct_dialog();
	
	gtk_widget_show_all(dialog);
	resp = gtk_dialog_run(dialog);

	gtk_widget_destroy(dialog);
	dialog = 0;

	/* mark all log entries as seen */
	/* we should convert all last-seen's to seens, and *all* to last-seen */
	g_list_foreach(list_log, set_seen, NULL);
	g_list_foreach(list_blockedlog, set_seen, NULL);
}

void
finalize_p2pship_dialog()
{
	/* hm.. how do we interrupt this one.. ? */
	listener_active = 0;
}

