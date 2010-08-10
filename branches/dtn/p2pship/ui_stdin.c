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

#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "processor_config.h"
#include "ui.h"
#include "ident.h"
#include "processor.h"

int
ui_stdin_query_operation(const char *operation, 
			 const char* true_op, const char *false_op);

int
ui_stdin_query_import_contacts(ship_list_t *list)
{
	void *ptr = 0;
	contact_t *c = 0;
	
	USER_PRINT("Import these contacts:\n");
	while ((c = ship_list_next(list, &ptr))) {
		USER_PRINT("\t%s <%s>: %s\n", c->name, c->sip_aor);
	}
	return ui_stdin_query_operation("import", "yes", "no");
}

int
ui_stdin_query_ident_operation(ident_t *ident, const char *operation, 
			       const char* true_op, const char *false_op)
{

	USER_PRINT("Identity: %s <%s>\n", ident->username, ident->sip_aor);
	ident_data_print_cert("\t", ident->cert);
	return ui_stdin_query_operation(operation, true_op, false_op);
}

int
ui_stdin_query_ca_operation(ca_t *ca, const char *operation, 
			    const char* true_op, const char *false_op)
{
	USER_PRINT("Certificate: %s\n", ca->name);
	ident_data_print_cert("\t", ca->cert);
	return ui_stdin_query_operation(operation, true_op, false_op);
}

int
ui_stdin_query_operation(const char *operation, 
			 const char* true_op, const char *false_op)
{
	size_t len = 64;
	char *buf = NULL;
	char *q = mallocz(strlen(operation) + strlen(true_op) + strlen(false_op) + 20);

	strcpy(q, operation);
	strcat(q, " [");
	strcat(q, true_op);
	strcat(q, ", ");
	strcat(q, false_op);
	strcat(q, "]: ");
	q[0] = toupper(q[0]);

	buf = (char*)mallocz(len+1);
	do {
		USER_PRINT(q);
		len = 64;
		getline(&buf, &len, stdin);
		trim(buf);
		if (strstr(true_op, buf) == true_op) {
			len = 1;
		} else if (strstr(false_op, buf) == false_op) {
			len = -1;
		} else {
			len = 0;
		}
	} while (!len);

	if (len == 1)
		return 1;
	else
		return 0;
}

int
ui_stdin_print_import_result(char *buf)
{
	USER_PRINT(buf);
	return 0;
}

int
ui_stdin_print_error(char *buf)
{
	USER_PRINT(buf);
	return 0;
}

int
ui_stdin_query_simple(char *header, char *body, char *true_op, char *false_op)
{
	return ui_stdin_query_operation(body, true_op, false_op);
}

int
ui_stdin_query_three(char *header, char *body, char *one_op, char *two_op, char *three_op)
{
	size_t len = 64;
	char *buf = NULL;
	char *q = mallocz(strlen(body) + strlen(one_op) + strlen(two_op) + strlen(three_op) + 20);

	strcpy(q, body);
	strcat(q, " [");
	strcat(q, one_op);
	strcat(q, ", ");
	strcat(q, two_op);
	strcat(q, ", ");
	strcat(q, three_op);
	strcat(q, "]: ");
	q[0] = toupper(q[0]);

	buf = (char*)mallocz(len+1);
	do {
		USER_PRINT(q);
		len = 64;
		getline(&buf, &len, stdin);
		trim(buf);
		if (strstr(one_op, buf) == one_op) {
			len = 0;
		} else if (strstr(two_op, buf) == two_op) {
			len = 1;
		} else if (strstr(three_op, buf) == three_op) {
			len = 2;
		} else {
			len = -1;
		}
	} while (len < 0);

	return len;
}

int
ui_stdin_init(processor_config_t *config)
{
	ui_reg_handler("ui_query_ident_operation", ui_stdin_query_ident_operation);
	ui_reg_handler("ui_query_ca_operation", ui_stdin_query_ca_operation);
	ui_reg_handler("ui_print_import_result", ui_stdin_print_import_result);
	ui_reg_handler("ui_query_import_contacts", ui_stdin_query_import_contacts);
	ui_reg_handler("ui_print_error", ui_stdin_print_error);
	ui_reg_handler("ui_query_simple", ui_stdin_query_simple);
	ui_reg_handler("ui_query_three", ui_stdin_query_three);
	ui_reg_handler("ui_popup", ui_stdin_print_import_result);
	return 0;
}

void
ui_stdin_close()
{

}

/* the ui_stdin register */
static struct processor_module_s processor_module = 
{
	.init = ui_stdin_init,
	.close = ui_stdin_close,
	.name = "ui_stdin",
	.depends = "ui",
};

/* register func */
void
ui_stdin_register() 
{
	processor_register(&processor_module);
}
