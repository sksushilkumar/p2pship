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

int
run_input_dialog(const char *heading, const char *prompt,
		 const char *initial_text,
		 char **result)
{
	GtkDialog *dialog;
	GtkWidget *vbox;
	GtkEntry *entry;
	GtkLabel *label;
	int res = 0;
	
	dialog = gtk_dialog_new_with_buttons(heading, NULL, 
					     GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
					     GTK_STOCK_OK,
					     1,
					     GTK_STOCK_CANCEL,
					     0,
					     NULL);
	vbox = gtk_hbox_new(FALSE, 0);
	entry = gtk_entry_new();
	gtk_entry_set_text(entry, initial_text);
	gtk_entry_set_editable(entry, TRUE);
	gtk_entry_set_position(entry, strlen(initial_text));

	label = gtk_label_new(prompt);

	gtk_entry_set_width_chars(entry, 20);
	gtk_box_pack_start(vbox, label, FALSE, FALSE, 1);
	gtk_box_pack_end(vbox, entry, FALSE, FALSE, 1);
	
	/* show 'em */
	gtk_container_add(GTK_CONTAINER(dialog->vbox), vbox);
	gtk_widget_set_style(dialog, NULL);

	gtk_widget_show_all(dialog);
	if (!gtk_dialog_run(dialog)) {
		res = -1;
	} else {
		prompt = gtk_entry_get_text(entry);
		if (*result = malloc(strlen(prompt) + 1)) {
			strcpy(*result, prompt);
			res = 0;
		} else
			res = -1;
	}

	gtk_widget_destroy(dialog);
	return res;
}


static int
main(int argc, char **argv)
{
	GtkDialog *dialog = 0;
	char *p;
	
	//init_logs();
	
	/* start the show.. */
	g_thread_init(NULL);
	gdk_threads_init();
	gdk_threads_enter();

	gtk_init(&argc, &argv);

	if (!run_input_dialog("Status", "Your status:", "none", &p))
		printf("got '%s'\n", p);
	else
		printf("forget it..\n");

	gdk_threads_leave();

	//gtk_main();

	// gtk_widget_destroy(dialog);

	return 0;
}
