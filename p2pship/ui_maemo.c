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
#include "processor_config.h"
#include "ui.h"
#include "ident.h"
#include "processor.h"
#include <glib.h>
#include <gtk/gtk.h>
#include <gdk/gdk.h>
#include <gtk/gtkmain.h>
#include "ship_utils.h"


int
ui_maemo_query_import_contacts(ship_list_t *list)
{
	GtkDialog *diag = 0;
	int ret = 0;
	char *str = 0, *tmp = 0;
	int len = 0, size = 0, i;
	char *tmp2 = 0;

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
	gtk_widget_destroy(diag);
	if (ret == -8)
		ret = 1;
	else
		ret = 0;
 err:
	freez(str);
	freez(tmp2);
	return ret;
}

int
ui_maemo_print_import_result(char *buf)
{
	GtkDialog *diag = 0;
	int ret = 0;
	char *str = 0, *tmp = 0;
	
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
	gtk_widget_destroy(diag);
 err:
	freez(str);
	freez(tmp);
	return 0;
}

#include <hildon/hildon-program.h>
#include <hildon/hildon-banner.h>

int
ui_maemo_popup(char *buf)
{
	//HildonWindow *window = HILDON_WINDOW(hildon_window_new());
	//gtk_widget_show_all(GTK_WIDGET(window));
	GtkWidget *w = NULL;
	
	gdk_threads_enter();
	w = hildon_banner_show_information(NULL /* GTK_WIDGET(window) */, NULL, buf);
	gtk_widget_show_all(w);
	gdk_flush();
	gdk_threads_leave();

 	USER_PRINT("We should print: %s\n", buf);
 	return 0;

	GtkDialog *diag = 0;
	int ret = 0;
	char *str = 0, *tmp = 0;
	
	ASSERT_TRUE(tmp = ship_pangoify(buf), err);
	ASSERT_TRUE(str = mallocz(strlen(tmp) + 64), err);
	sprintf(str, "<big>Note!</big>\n\n%s", tmp);
	ASSERT_TRUE(diag = (GtkDialog*)gtk_message_dialog_new_with_markup(NULL,
									  GTK_DIALOG_MODAL,
									  GTK_MESSAGE_INFO,
									  GTK_BUTTONS_OK,
									  str,
									  NULL), err);
	gtk_dialog_run(diag);
	gtk_widget_destroy(diag);
 err:
	freez(str);
	freez(tmp);
	return 0;
}

int
ui_maemo_print_error(char *buf)
{
	GtkDialog *diag = 0;
	int ret = 0;
	char *str = 0, *tmp = 0;
	
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
	gtk_widget_destroy(diag);
 err:
	freez(str);
	freez(tmp);
	return 0;
}

int
ui_maemo_open_frontpage()
{
	/* execute the browser to open at the webconf */
	LOG_INFO("should be opening browser now .. \n");
	if (!fork()) {
		execl("/usr/bin/browser", "/usr/bin/browser", "--url=http://localhost:9080/web/start.html", NULL);
	}
	return 0;
}

int
ui_maemo_query_ca_operation(ca_t *ca, const char *operation, 
			    const char* true_op, const char *false_op)
{
	const char *templ = 
		"<big>%s CA certificate?</big>\n\nYour confirmation is required for %sing the CA certificate for <b>%s</b> %s:\n  Name: <i>%s</i>\n  Certified name: <i>%s</i>\n  Issued by: <i>%s</i>\n  Valid from: <i>%s</i>\n  Until: <i>%s</i>\n\nThis certificate is needed to be able to communicate with identities issued by this CA.";
	char *str = 0;
	time_t start, end;
	GtkDialog *diag = 0;
	char startb[64], endb[64], *issuer = 0, *cname = 0, *op2 = 0, *tmp, *uname = 0;
	int ret = 0;
		
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
	gtk_widget_destroy(diag);
 err:
	freez(op2);
	freez(str);
	freez(issuer);
	freez(cname);
	freez(uname);
	return ret;
}

int
ui_maemo_query_ident_operation(ident_t *ident, const char *operation, 
			       const char* true_op, const char *false_op)
{
	const char *templ = 
		"<big>%s identity?</big>\n\nYour confirmation is required for %sing the identity <b>%s</b> %s:\n  Name: <i>%s</i>\n  Certified name: <i>%s</i>\n  Issued by: <i>%s</i>\n  Valid from: <i>%s</i>\n  Until: <i>%s</i>\n";
	char *str = 0;
	time_t start, end;
	GtkDialog *diag = 0;
	char startb[64], endb[64], *issuer = 0, *cname = 0, *op2 = 0, *tmp, *aor = 0, *uname = 0;
	int ret = 0;
		
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
	gtk_widget_destroy(diag);
 err:
	freez(op2);
	freez(str);
	freez(issuer);
	freez(cname);
	freez(uname);
	freez(aor);
	return ret;
}

int
ui_maemo_query_simple(char *header, char *body,
		      const char* true_op, const char *false_op)
{
	const char *templ = 
		"<big>%s</big>\n\n%s\n";
	char *str = 0, *tmp = 0, *tmp2 = 0, *op1 = 0, *op2 = 0;
	GtkDialog *diag = 0;
	int ret = 0;
	
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
	gtk_widget_destroy(diag);
 err:
	freez(op2);
	freez(op1);
	freez(tmp2);
	freez(tmp);
	freez(str);
	return ret;
}

int
ui_maemo_query_three(char *header, char *body,
		     const char* one_op, const char *two_op, const char *three_op)
{
	const char *templ = 
		"<big>%s</big>\n\n%s\n";
	char *str = 0, *tmp = 0, *tmp2 = 0, *op1 = 0, *op2 = 0, *op3 = 0;
	GtkDialog *diag = 0;
	int ret = 0;
	
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
	gtk_widget_destroy(diag);
 err:
	freez(op3);
	freez(op2);
	freez(op1);
	freez(tmp2);
	freez(tmp);
	freez(str);
	return ret;
}

int
ui_maemo_init(processor_config_t *config)
{
	ui_reg_handler("ui_open_frontpage", ui_maemo_open_frontpage);
 	ui_reg_handler("ui_query_ident_operation", ui_maemo_query_ident_operation);
	ui_reg_handler("ui_query_ca_operation", ui_maemo_query_ca_operation);
	ui_reg_handler("ui_print_import_result", ui_maemo_print_import_result);
	ui_reg_handler("ui_query_import_contacts", ui_maemo_query_import_contacts);

	ui_reg_handler("ui_print_error", ui_maemo_print_error);
	ui_reg_handler("ui_query_simple", ui_maemo_query_simple);
	ui_reg_handler("ui_query_three", ui_maemo_query_three);

	ui_reg_handler("ui_popup", ui_maemo_popup);

	return 0;
}

void
ui_maemo_close()
{

}

/* the ui_maemo register */
static struct processor_module_s processor_module = 
{
	.init = ui_maemo_init,
	.close = ui_maemo_close,
	.name = "ui_maemo",
	.depends = "ui",
};

/* register func */
void
ui_maemo_register() 
{
	processor_register(&processor_module);
}
