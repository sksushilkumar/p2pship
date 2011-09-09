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
#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <gtk/gtkmain.h>
#include <ctype.h>
#include "ship_utils.h"
#include "processor_config.h"
#include "ui.h"
#include "ident.h"
#include "processor.h"


static int
ui_gtk_query_import_contacts(ship_list_t *list)
{
	GtkDialog *diag = 0;
	int ret = 0;
	char *str = 0, *tmp = 0;
	int len = 0, size = 0, i;
	char *tmp2 = 0;

	gdk_threads_enter();
	ASSERT_TRUE(str = append_str("<big>Add Contacts?</big>\n\nDo you want to add the following people to your addressbook?\n", str, &size, &len), err);
	
	for (i=0; i < 4 && i < ship_list_length(list); i++) {
		contact_t *c = ship_list_get(list, i);
		
		ASSERT_TRUE((tmp = append_str("   ", str, &size, &len)) && (str = tmp), err);
		ASSERT_TRUE(tmp2 = ship_pangoify(c->name), err);
		ASSERT_TRUE((tmp = append_str(tmp2, str, &size, &len)) && (str = tmp), err);
		freez(tmp2);
		
		ASSERT_TRUE((tmp = append_str(" <i>(", str, &size, &len)) && (str = tmp), err);

		ASSERT_TRUE(tmp2 = ship_pangoify(c->sip_aor), err);
		ASSERT_TRUE((tmp = append_str(tmp2, str, &size, &len)) && (str = tmp), err);
		freez(tmp2);

		ASSERT_TRUE((tmp = append_str(")</i>\n", str, &size, &len)) && (str = tmp), err);
	}
	
	if (i < ship_list_length(list)) {
		ASSERT_TRUE(tmp2 = mallocz(64), err);
		sprintf(tmp2, ".. and <b>%d</b> others\n", ship_list_length(list) - i);
		ASSERT_TRUE((tmp = append_str(tmp2, str, &size, &len)) && (str = tmp), err);
		freez(tmp2);
	}

	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_QUESTION,
									  GTK_BUTTONS_YES_NO,
									  str,
									  NULL), err);

	ret = gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
	if (ret == -8)
		ret = 1;
	else
		ret = 0;
 err:
	gdk_threads_leave();
	freez(str);
	freez(tmp2);
	return ret;
}

static int
ui_gtk_print_import_result(char *buf)
{
	GtkDialog *diag = 0;
	char *str = 0, *tmp = 0;
	
	gdk_threads_enter();
	ASSERT_TRUE(tmp = ship_pangoify(buf), err);
	ASSERT_TRUE(str = mallocz(strlen(tmp) + 64), err);
	sprintf(str, "<big>Import complete!</big>\n\n%s", tmp);
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_INFO,
									  GTK_BUTTONS_OK,
									  str,
									  NULL), err);
	gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();

	freez(str);
	freez(tmp);
	return 0;
}

#ifdef CONFIG_MAEMOUI_ENABLED
#include <hildon/hildon-program.h>
#include <hildon/hildon-banner.h>
#endif

#ifdef HAVE_LIBNOTIFY
#include <libnotify/notify.h>
#endif

static int
ui_gtk_popup(char *buf)
{
#ifdef CONFIG_MAEMOUI_ENABLED
	GtkWidget *w = NULL;
	
	gdk_threads_enter();
	w = hildon_banner_show_information(NULL /* GTK_WIDGET(window) */, NULL, buf);
	gtk_widget_show_all(w);
	gdk_flush();
	gdk_threads_leave();

 	USER_PRINT("We should print: %s\n", buf);
#else

#ifndef HAVE_LIBNOTIFY
	GtkDialog *diag = 0;
	char *str = 0, *tmp = 0;
	
	gdk_threads_enter();
	ASSERT_TRUE(tmp = ship_pangoify(buf), err);
	ASSERT_TRUE(str = mallocz(strlen(tmp) + 64), err);
	sprintf(str, "<big>%s</big>", tmp);
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  /* GTK_DIALOG_MODAL */0,
									  GTK_MESSAGE_INFO,
									  GTK_BUTTONS_OK,
									  str), err);
	gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();
	freez(str);
	freez(tmp);
#else
	/* new, libnotify-based notifications */
	// thanks zenity; http://svn.gnome.org/viewvc/zenity/trunk/src/notification.c?view=markup

	NotifyNotification *notif;

	gdk_threads_enter();

	/* this has changed with version 0.7xx */
#ifdef HAVE_LIBNOTIFY_NEW
	notif = notify_notification_new("p2pship", buf,
					GTK_STOCK_DIALOG_WARNING);
#else
	notif = notify_notification_new("p2pship", buf,
					GTK_STOCK_DIALOG_WARNING,
					//GTK_STOCK_DIALOG_INFO, 
					NULL);
#endif
	notify_notification_show(notif, NULL);
	g_object_unref(notif);
	gdk_threads_leave();
#endif

#endif
	return 0;
}

static int
ui_gtk_print_error(char *buf)
{
	GtkDialog *diag = 0;
	char *str = 0, *tmp = 0;
	
	gdk_threads_enter();
	ASSERT_TRUE(tmp = ship_pangoify(buf), err);
	ASSERT_TRUE(str = mallocz(strlen(tmp) + 64), err);
	sprintf(str, "<big>Error!</big>\n\n%s", tmp);
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_ERROR,
									  GTK_BUTTONS_OK,
									  str,
									  NULL), err);
	gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();
	freez(str);
	freez(tmp);
	return 0;
}

static int
ui_gtk_open_frontpage()
{
	/* execute the browser to open at the webconf */
	LOG_INFO("should be opening browser now .. \n");
	if (!fork()) {
		execl("/usr/bin/browser", "/usr/bin/browser", "--url=http://localhost:9080/web/start.html", NULL);
	}
	return 0;
}

static int
ui_gtk_query_ca_operation(ca_t *ca, const char *operation, 
			    const char* true_op, const char *false_op)
{
	const char *templ = 
		"<big>%s CA certificate?</big>\n\nYour confirmation is required for %sing the CA certificate for <b>%s</b> %s:\n  Name: <i>%s</i>\n  Certified name: <i>%s</i>\n  Issued by: <i>%s</i>\n  Valid from: <i>%s</i>\n  Until: <i>%s</i>\n\nThis certificate is needed to be able to communicate with identities issued by this CA.";
	char *str = 0;
	time_t start, end;
	GtkDialog *diag = 0;
	char startb[64], endb[64], *issuer = 0, *cname = 0, *op2 = 0, *tmp, *uname = 0;
	int ret = 0;

	gdk_threads_enter();
		
	/* cert data */
	if (!(issuer = ident_data_x509_get_cn(X509_get_issuer_name(ca->cert)))) {
		ASSERT_TRUE(issuer = strdup("UNKNOWN ISSUER"), err);
	}

	if (!(cname = ident_data_x509_get_cn(X509_get_subject_name(ca->cert)))) {
		ASSERT_TRUE(cname = strdup("UNKNOWN SUBJECT"), err);
	}
	
	/* validity */
	ASSERT_ZERO(ident_data_x509_get_validity(ca->cert, &start, &end), err);
	ship_format_time_human(start, startb, sizeof(startb));
	ship_format_time_human(end, endb, sizeof(endb));
	
	ASSERT_TRUE(op2 = strdup(operation), err);
	ASSERT_TRUE(uname = ship_pangoify(ca->name), err);
	ASSERT_TRUE(tmp = ship_pangoify(cname), err);
	freez(cname); cname = tmp;

	str = malloc(strlen(templ) + strlen(startb) + strlen(endb) + strlen(issuer) 
		     + strlen(cname) 
		     + strlen(uname)
		     + 1024);

	op2[0] = toupper(op2[0]);
	if (!strcmp(operation, "replace")) {
		sprintf(str, templ,
			"Replace", "replace", uname, "New CA certificate details", uname,
			cname, issuer, startb, endb);
	} else {
		sprintf(str, templ,
			op2, operation, uname, "Details", uname,
			cname, issuer, startb, endb);
	}
	
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_QUESTION,
									  GTK_BUTTONS_NONE,
									  str,
									  NULL), err);
	gtk_dialog_add_buttons(diag, op2, 1, "Cancel", 0, NULL);
	
	ret = gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();
	freez(op2);
	freez(str);
	freez(issuer);
	freez(cname);
	freez(uname);
	return ret;
}

static int
ui_gtk_query_ident_operation(ident_t *ident, const char *operation, 
			       const char* true_op, const char *false_op)
{
	const char *templ = 
		"<big>%s identity?</big>\n\nYour confirmation is required for %sing the identity <b>%s</b> %s:\n  Name: <i>%s</i>\n  Certified name: <i>%s</i>\n  Issued by: <i>%s</i>\n  Valid from: <i>%s</i>\n  Until: <i>%s</i>\n";
	char *str = 0;
	time_t start, end;
	GtkDialog *diag = 0;
	char startb[64], endb[64], *issuer = 0, *cname = 0, *op2 = 0, *tmp, *aor = 0, *uname = 0;
	int ret = 0;

	gdk_threads_enter();
		
	/* cert data */
	if (!(issuer = ident_data_x509_get_cn(X509_get_issuer_name(ident->cert)))) {
		ASSERT_TRUE(issuer = strdup("UNKNOWN ISSUER"), err);
	}

	if (!(cname = ident_data_x509_get_cn(X509_get_subject_name(ident->cert)))) {
		ASSERT_TRUE(cname = strdup("UNKNOWN SUBJECT"), err);
	}
	
	/* validity */
	ASSERT_ZERO(ident_data_x509_get_validity(ident->cert, &start, &end), err);
	ship_format_time_human(start, startb, sizeof(startb));
	ship_format_time_human(end, endb, sizeof(endb));
	
	ASSERT_TRUE(op2 = strdup(operation), err);
	ASSERT_TRUE(aor = ship_pangoify(ident->sip_aor), err);
	ASSERT_TRUE(uname = ship_pangoify(ident->username), err);
	ASSERT_TRUE(tmp = ship_pangoify(cname), err);
	freez(cname); cname = tmp;
	ASSERT_TRUE(tmp = ship_pangoify(issuer), err);
	freez(issuer); issuer = tmp;
	
	str = malloc(strlen(templ) + strlen(startb) + strlen(endb) + strlen(issuer) 
		     + strlen(cname) 
		     + strlen(aor) + strlen(uname)
		     + 1024);

	op2[0] = toupper(op2[0]);
	if (!strcmp(operation, "replace")) {
		sprintf(str, templ,
			"Replace", "replace", aor, "New identity", uname,
			cname, issuer, startb, endb);
	} else {
		sprintf(str, templ,
			op2, operation, aor, "Details", uname,
			cname, issuer, startb, endb);
	}
	
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_QUESTION,
									  GTK_BUTTONS_NONE,
									  str,
									  NULL), err);
	gtk_dialog_add_buttons(diag, op2, 1, "Cancel", 0, NULL);
	
	ret = gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();

	freez(op2);
	freez(str);
	freez(issuer);
	freez(cname);
	freez(uname);
	freez(aor);
	return ret;
}

static int
ui_gtk_query_simple(char *header, char *body,
		      const char* true_op, const char *false_op)
{
	const char *templ = 
		"<big>%s</big>\n\n%s\n";
	char *str = 0, *tmp = 0, *tmp2 = 0, *op1 = 0, *op2 = 0;
	GtkDialog *diag = 0;
	int ret = 0;
	
	gdk_threads_enter();
	ASSERT_TRUE(tmp = ship_pangoify(header), err);
	ASSERT_TRUE(tmp2 = ship_pangoify(body), err);
	ASSERT_TRUE(op1 = strdup(true_op), err);
	ASSERT_TRUE(op2 = strdup(false_op), err);
	
	ASSERT_TRUE(str = malloc(strlen(templ) + strlen(tmp) + strlen(tmp2)+10), err);
	sprintf(str, templ, tmp, tmp2);
	
	op1[0] = toupper(op1[0]);
	op2[0] = toupper(op2[0]);
	
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_QUESTION,
									  GTK_BUTTONS_NONE,
									  str,
									  NULL), err);
	gtk_dialog_add_buttons(diag, op1, 1, op2, 0, NULL);
	ret = gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();
	freez(op2);
	freez(op1);
	freez(tmp2);
	freez(tmp);
	freez(str);
	return ret;
}

static int
ui_gtk_query_three(char *header, char *body,
		     const char* one_op, const char *two_op, const char *three_op)
{
	const char *templ = 
		"<big>%s</big>\n\n%s\n";
	char *str = 0, *tmp = 0, *tmp2 = 0, *op1 = 0, *op2 = 0, *op3 = 0;
	GtkDialog *diag = 0;
	int ret = 0;
	
	gdk_threads_enter();
	ASSERT_TRUE(tmp = ship_pangoify(header), err);
	ASSERT_TRUE(tmp2 = ship_pangoify(body), err);
	ASSERT_TRUE(op1 = strdup(one_op), err);
	ASSERT_TRUE(op2 = strdup(two_op), err);
	ASSERT_TRUE(op3 = strdup(three_op), err);
	
	ASSERT_TRUE(str = malloc(strlen(templ) + strlen(tmp) + strlen(tmp2)+10), err);
	sprintf(str, templ, tmp, tmp2);
	
	op1[0] = toupper(op1[0]);
	op2[0] = toupper(op2[0]);
	op3[0] = toupper(op3[0]);
	
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_QUESTION,
									  GTK_BUTTONS_NONE,
									  str,
									  NULL), err);
	gtk_dialog_add_buttons(diag, op1, 0, op2, 1, op3, 2, NULL);
	ret = gtk_dialog_run(diag);
	gtk_widget_destroy((GtkWidget*)diag);
 err:
	gdk_threads_leave();
	freez(op3);
	freez(op2);
	freez(op1);
	freez(tmp2);
	freez(tmp);
	freez(str);
	return ret;
}

static int 
ui_gtk_query_filechooser(const char *header, const char *title, const char *dir, ship_list_t *filetypes, char **filename)
{
	GtkDialog *diag = NULL;
	int ret =  -1;
	GtkFileFilter *filter = NULL;


		

	gdk_threads_enter();
	ASSERT_TRUE(diag = (GtkDialog*)gtk_file_chooser_dialog_new(header, NULL, 
								   GTK_FILE_CHOOSER_ACTION_OPEN,
								   GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
								   GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
								   NULL), err);

	if (filetypes && ship_list_length(filetypes)) {
		void *ptr = NULL;
		char *t = NULL;
		
		ASSERT_TRUE(filter = gtk_file_filter_new(), err);
		while ((t = ship_list_next(filetypes, &ptr))) {
			gtk_file_filter_add_pattern(filter, t);
		}
		gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(diag), filter);
	}
		
	gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(diag), dir);
	if ((ret = gtk_dialog_run(diag)) == GTK_RESPONSE_ACCEPT) {
		*filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(diag));
		ret = 0;
	}

 err:
	if (filter)
		gtk_object_unref(GTK_OBJECT(filter));
	if (diag)
		gtk_widget_destroy((GtkWidget*)diag);

	gdk_threads_leave();
	return ret;
}

static int
ui_gtk_query_listchooser(const char *header, const char *title, ship_list_t *options, char **ret)
{
	return -1;
}


static int
ui_gtk_init(processor_config_t *config)
{
	ui_reg_handler("ui_open_frontpage", ui_gtk_open_frontpage);
 	ui_reg_handler("ui_query_ident_operation", ui_gtk_query_ident_operation);
	ui_reg_handler("ui_query_ca_operation", ui_gtk_query_ca_operation);
	ui_reg_handler("ui_print_import_result", ui_gtk_print_import_result);
	ui_reg_handler("ui_query_import_contacts", ui_gtk_query_import_contacts);

	ui_reg_handler("ui_print_error", ui_gtk_print_error);
	ui_reg_handler("ui_query_simple", ui_gtk_query_simple);
	ui_reg_handler("ui_query_three", ui_gtk_query_three);

	ui_reg_handler("ui_popup", ui_gtk_popup);

	ui_reg_handler("ui_query_filechooser", ui_gtk_query_filechooser);
	ui_reg_handler("ui_query_listchooserx", ui_gtk_query_listchooser);

#ifdef HAVE_LIBNOTIFY_NEW
	notify_init("p2pship");
#endif
	return 0;
}

static void
ui_gtk_close()
{
#ifdef HAVE_LIBNOTIFY
	notify_uninit();
#endif
}

/* the ui_gtk register */
static struct processor_module_s processor_module = 
{
	.init = ui_gtk_init,
	.close = ui_gtk_close,
	.name = "ui_gtk",
	.depends = "ui",
};

/* register func */
void
ui_gtk_register() 
{
	processor_register(&processor_module);
}
