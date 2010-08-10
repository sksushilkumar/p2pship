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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <gtk/gtk.h>
#include <glib-object.h>
#include <libhildondesktop/libhildondesktop.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "p2pship_sb.h"

/* Utility macro which defines the plugin dynamic type bits */
HD_DEFINE_PLUGIN (P2pshipPlugin, p2pship, STATUSBAR_TYPE_ITEM);

/* the levels served here .. */
static const int p2pship_levels[5] = { 0, 10, 2, 1, -1 };

/* is this wrong? using static data in this plugin? */
static GtkWidget *btn = 0;
static guint poller = 0;

/* the last len we have set */
static int last_set_pathlen = -9923;

void
_do_log(const char *template, ...)
{
	va_list ap;
	FILE *f = NULL;
	va_start(ap, template);
	if (f = fopen("/tmp/sb_log.log", "a")) {
		vfprintf(f, template, ap);
		fclose(f);	
	}
	va_end(ap);
}

#define UAMODE_UNKNOWN 0
#define UAMODE_OPEN 1
#define UAMODE_RELAX 2
#define UAMODE_PARANOID 3

static void p2pship_init (P2pshipPlugin *statusbar_plugin);
static void p2pship_class_init (P2pshipPluginClass *class);
static int p2pship_get_current_pathlen();
static void p2pship_set_current_pathlen(int len);
static void p2pship_set_button(GtkWidget *button);
static void p2pship_set_current_uamode(int len);
static void p2pship_set_current_status(char *status);

/* normalizes the pathlen to something we have */
static int 
p2pship_normalize_pathlen(int len)
{
	int i;

	if (len < 0)
		return -1;

	for (i=0; p2pship_levels[i] != -1; i++)
		if (len == p2pship_levels[i])
			return len;
	return 10; /* default value */
}

/* gets the image associated with the given pathlen */
static void
p2pship_get_img(int pathlen, char *root, char *str)
{
	char *img = "/unknown.png";
	
	if (pathlen > -1) {
		switch (pathlen) {
		case 0: img = "/open.png"; break;
		case 1: img = "/friends.png"; break;
		case 2: img = "/ff.png"; break;
		default: img = "/network.png"; break;
		}
	}
	
	strcpy(str, root);
	strcat(str, img);
}

/* gets the descriptive string associate with a pathlen */
static void
p2pship_get_str(int pathlen, char *str)
{
	char *label = "Could not get state!";

	if (pathlen > -1) {
		switch (pathlen) {
		case 0: label = "Open";
			break;
		case 1: label = "Friends only";
			break;
		case 2: label = "Friends of friends";
			break;
		default: label = "In your network";
			break;
		}
	}

	strcpy(str, label);
}


/* gets the descriptive string associate with a pathlen */
static void
p2pship_get_head_str(int pathlen, int uamode, char *str)
{
	p2pship_get_str(pathlen, str);
	strcat(str, " / ");

	switch (uamode) {
	case UAMODE_OPEN:
		strcat(str, "Open");
		break;
	case UAMODE_RELAX:
		strcat(str, "Relax");
		break;
	case UAMODE_PARANOID:
		strcat(str, "Paranoid");
		break;
	default:
		strcat(str, "??");
		break;
	}
}

/* creates a menuitem */
static GtkWidget *
p2pship_create_menuitem(char *label, char *icon, 
			void (*callback) (GtkWidget *, guint),
			guint param)
{
	GtkWidget *itemw, *iconw;
	
	if (icon) {
		itemw = gtk_image_menu_item_new_with_label(label);
		iconw = gtk_image_new_from_file(icon);
		gtk_image_menu_item_set_image (GTK_IMAGE_MENU_ITEM (itemw),
					       iconw);
	} else {
		itemw = gtk_menu_item_new_with_label(label);
	}

	if (callback) {
		g_signal_connect (itemw, "activate",
				  G_CALLBACK (callback),
				  GINT_TO_POINTER(param));
	}
	return itemw;
}

/* calculates the place for the menu */
static void
p2pship_popup_place(GtkMenu *menu,
		    gint *x,
		    gint *y,
		    gboolean *push_in,
		    gpointer user_data)
{
	GtkRequisition req;
	GtkWidget *btn = GTK_WIDGET(user_data);
	gint sw;

	gtk_widget_size_request(GTK_WIDGET(menu), &req);
	sw = gdk_screen_get_width(gtk_widget_get_screen(btn));
	gdk_window_get_position(btn->window, x, y);
	
	*y += btn->allocation.y + btn->allocation.height + 10;
	*x += btn->allocation.x;
	
	if (*x + req.width > sw) {
		*x -= req.width - btn->allocation.width;
	}
}

static void
p2pship_item_clicked(GtkWidget *menu_item,
		     guint item)
{
	int i = item;
	char *tmp = 0;
	
	/* set path len it so .. */
	if (i > -1) {
		p2pship_set_current_pathlen(i);
		p2pship_set_button(btn);
	} else {
		switch (item) {
		case -1:
			/* show recently blocked .. */
			show_p2pship_dialog();
			break;

		case -2:
			p2pship_set_current_uamode(UAMODE_OPEN);
			break;
		case -3:
			// relax
			p2pship_set_current_uamode(UAMODE_RELAX);
			break;
		case -4:
			// paranoid
			p2pship_set_current_uamode(UAMODE_PARANOID);
			break;
		case -5:
			/* set status */
			if (!p2pship_get_current_status(&tmp)) {
				char *new_status = 0;
				if (!run_input_dialog("Status", "Your status:",
						      tmp, &new_status)) {
					p2pship_set_current_status(new_status);
					free(new_status);
				}
				free(tmp);
			}
			break;
		default:
			/* .. */

			show_p2pship_dialog();
			break;
		}
	}
}

static void
p2pship_clicked (GtkWidget *button, P2pshipPlugin *self)
{
	GtkWidget *item, *theone = 0;
	GtkWidget *main_menu;
	int sel, pathlen = p2pship_get_current_pathlen();
	char label[128], img[128];
	int i;
	char *status = 0;

	main_menu = gtk_menu_new();

	p2pship_get_head_str(pathlen, p2pship_get_current_uamode(), label);

	/* status */
	if (!p2pship_get_current_status(&status) && strlen(status)) {
		if (strlen(status) > 15) {
			status[12] = '.';
			status[13] = '.';
			status[14] = 0;
		}
		
		item = p2pship_create_menuitem(status, NULL, NULL, 0);
		gtk_widget_set_state(item, GTK_STATE_INSENSITIVE);
		gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
				      item);
	}
	if (status) free(status);
	
	/* mode */
	item = p2pship_create_menuitem(label, NULL, NULL, 0);
	gtk_widget_set_state(item, GTK_STATE_INSENSITIVE);
	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
			      item);

	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
			      gtk_separator_menu_item_new());
	
	for (i=0; p2pship_levels[i] > -1; i++) {
		p2pship_get_str(p2pship_levels[i], label);
		p2pship_get_img(p2pship_levels[i], ICON_ROOT, img);
		item = p2pship_create_menuitem(label, img, p2pship_item_clicked, p2pship_levels[i]);

		if (pathlen < 0)
			gtk_widget_set_state(item, GTK_STATE_INSENSITIVE);
		else if (p2pship_levels[i] == pathlen)
			theone = item;
		
		gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), item);
	}

	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
 			      gtk_separator_menu_item_new());

	if (i = get_blocked_calls_count())
		sprintf(label, "Call log (%d)", i);
	else
		sprintf(label, "Call log");

	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
			      p2pship_create_menuitem(label, NULL, p2pship_item_clicked, -1));

	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
			      p2pship_create_menuitem("Set status", NULL, p2pship_item_clicked, -5));

	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu), 
 			      gtk_separator_menu_item_new());

 	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu),  
 			      p2pship_create_menuitem("Open", NULL, p2pship_item_clicked, -2));
 	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu),  
 			      p2pship_create_menuitem("Relax", NULL, p2pship_item_clicked, -3));
 	gtk_menu_shell_append(GTK_MENU_SHELL(main_menu),  
 			      p2pship_create_menuitem("Paranoid", NULL, p2pship_item_clicked, -4));
	
	gtk_widget_show_all(GTK_WIDGET(main_menu));
	gtk_menu_popup(GTK_MENU(main_menu), NULL, NULL,
		       p2pship_popup_place, button, 1,
		       gtk_get_current_event_time());

	gtk_menu_shell_deselect((GtkMenuShell*)main_menu);
	if (theone)
		gtk_menu_shell_select_item((GtkMenuShell*)main_menu, theone);
}


/* send / receives */
static int
p2pship_sendrecv(char *buf, int buf_len, char **resp, int *resp_len)
{
	int s, t, len;
        struct sockaddr_un remote;
        char str[1024];
	*resp_len = 0;
	if (resp)
		*resp = 0;

        if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
        }

        remote.sun_family = AF_UNIX;
        strcpy(remote.sun_path, SOCK_PATH);
        len = strlen(remote.sun_path) + sizeof(remote.sun_family);
        if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		return -2;
        }
	
	t = -3;
	if (send(s, buf, buf_len, 0) != -1) {
		do {
			int flags;
			t = recv(s, str, sizeof(str), 0);
			if (t > 0 && resp) {
				char *tmp = malloc((*resp_len) + t + 1);
				if (tmp) {
					if (!*resp) {
						memcpy(tmp, *resp, *resp_len);
						free(*resp);
						*resp = tmp;
					}
					memcpy(*resp + *resp_len, str, t);
					*resp_len += t;
				}
			}
			
			/* make non-blocking */
			flags = fcntl(s, F_GETFL, 0);
			fcntl(s, F_SETFL, flags | O_NONBLOCK);
		} while (t > 0);
        }
	close(s);
	
	if (resp && *resp)
		return 0;
	else
		return -1;
}


/* send / receives */
static int
p2pship_sendrecvloop(char *buf, int buf_len, 
		     void (*func) (char *, int, void *), void *data)
{
	int s, t, len;
        struct sockaddr_un remote;
        char str[1014];
	
        if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
        }

        remote.sun_family = AF_UNIX;
        strcpy(remote.sun_path, SOCK_PATH);
        len = strlen(remote.sun_path) + sizeof(remote.sun_family);
        if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		return -2;
        }
	
	t = -3;
	if (send(s, buf, buf_len, 0) != -1) {
		while ((t = recv(s, str, sizeof(str)-1, 0)) > 0) {
			str[t] = 0;
			//printf("Got (%d): %s\n", t, str);
			func(str, t, data);
		}
	}
	close(s);
	return t;
}

/* send / receives strings */
int
p2pship_sendrecv_str(char *cmd, char **resp)
{
	int len;
	if (!p2pship_sendrecv(cmd, strlen(cmd)+1, resp, &len)) {
		(*resp)[len] = 0;
		return 0;
	} else 
		return -1;
}

/* send / receives strings */
int
p2pship_sendrecv_strloop(char *cmd, void (*func) (char *, int, void *), void *data)
{
	return p2pship_sendrecvloop(cmd, strlen(cmd)+1, func, data);
}

/* retrieves the current max path */
static int
p2pship_get_current_pathlen()
{
	char *resp = 0;
	int ret = -1;
	if (!p2pship_sendrecv_str("get_conf:" PATHLEN_CONF_KEY, &resp)) {
		char *val = 0;

		if (val = strchr(resp, ':')) {
			val++;
			ret = p2pship_normalize_pathlen(atoi(val));
		}
		free(resp);
	}
	return ret;
}

/* retrieves the current ua mode. */
static int
p2pship_get_current_uamode()
{
	char *resp = 0;
	int ret = UAMODE_UNKNOWN;
	if (!p2pship_sendrecv_str("get_conf:" UAMODE_CONF_KEY, &resp)) {
		char *val = 0;
		if (val = strchr(resp, ':')) {
			val++;
			if (!strcmp(val, "relax"))
				ret = UAMODE_RELAX;
			else if (!strcmp(val, "open"))
				ret = UAMODE_OPEN;
			else if (!strcmp(val, "paranoid"))
				ret = UAMODE_PARANOID;
		}
		free(resp);
	}
	return ret;
}

/*  */
static int
p2pship_get_current_status(char **r)
{
	return p2pship_sendrecv_str("get_status:", r);
}

/*  */
static void
p2pship_set_current_status(char *status)
{
	char *resp = malloc(strlen(status) + 64);
	if (!resp)
		return;
	sprintf(resp, "set_status::%s", status);
	p2pship_sendrecv_str(resp, NULL);
	free(resp);
}

/* sets the current uamode */
static void
p2pship_set_current_uamode(int len)
{
	char resp[1024];
	sprintf(resp, "set_conf:" UAMODE_CONF_KEY "=");
	switch (len) {
	case UAMODE_OPEN: strcat(resp, "open"); break;
	case UAMODE_RELAX: strcat(resp, "relax"); break;
	case UAMODE_PARANOID: strcat(resp, "paranoid"); break;
	}
	p2pship_sendrecv_str(resp, NULL);
}

/* sets the current max path */
static void
p2pship_set_current_pathlen(int len)
{
	char resp[1024];
	sprintf(resp, "set_conf:" PATHLEN_CONF_KEY "=%d", len);
	p2pship_sendrecv_str(resp, NULL);
}

static void
p2pship_set_button(GtkWidget *button)
{
	int pathlen = p2pship_get_current_pathlen();
	char img[128];

	if (pathlen != last_set_pathlen) {
		last_set_pathlen = pathlen;
		p2pship_get_img(pathlen, IMG_ROOT, img);
		gtk_button_set_image (GTK_BUTTON (button), 
				      gtk_image_new_from_file(img));
	}
}

static gboolean
p2pship_maintain(gpointer data)
{
	GtkWidget *button = data;

	p2pship_set_button(button);
	return TRUE;
}

static void
p2pship_init (P2pshipPlugin *statusbar_plugin)
{
	P2pshipPluginPrivate *priv = 0;
	GtkWidget *button;

	/* create the button, connect the signals */
	btn = button = gtk_button_new();
	p2pship_set_button(button);
	g_signal_connect(button, "clicked",
			 G_CALLBACK (p2pship_clicked), statusbar_plugin);
	gtk_container_add (GTK_CONTAINER (statusbar_plugin), button);
	gtk_widget_show_all (button);

	init_p2pship_dialog();

	/* set a timeout ticking .. */
	poller = g_timeout_add(1000, p2pship_maintain, button);
}

static void 
p2pship_finalize(GObject *self)
{
	g_source_remove(poller);
	finalize_p2pship_dialog();
}

static void
p2pship_class_init (P2pshipPluginClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS(class);
	object_class->finalize = p2pship_finalize;
}
