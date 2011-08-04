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
#include "ui.h"
#include "processor.h"
#include "processor_config.h"
#include "ship_utils.h"
#include "ship_debug.h"
#include "ident.h"

/* the list of ui handler functions */
static ship_ht_t *handler_funcs = 0;

/* handler func registration */
void
ui_reg_handler(char *func_name, void *func)
{
	ship_ht_put_string(handler_funcs, func_name, func);
}

int 
ui_init(processor_config_t *config)
{
	int ret = -1;
	LOG_DEBUG("Initing ui..\n");
	ASSERT_TRUE(handler_funcs = ship_ht_new(), err);
	ret = 0;
 err:
	return ret;
}

void
ui_close()
{
	ship_ht_free(handler_funcs);
}

/* function declarations */
ui_define_operation(ui_query_ident_operation, "ui_query_ident_operation",
		    (const ident_t *ident, const char *operation, 
		     const char* true_op, const char *false_op),
		    (ident, operation, true_op, false_op));

ui_define_operation(ui_query_ca_operation, "ui_query_ca_operation",
		    (const ca_t *cert, const char *operation, 
		     const char* true_op, const char *false_op),
		    (cert, operation, true_op, false_op));

ui_define_operation(ui_open_frontpage, "ui_open_frontpage",
		    (), ());

ui_define_operation(_ui_print_error, "ui_print_error",
		    (char *buf), (buf));

ui_define_operation(_ui_print_import_result, "ui_print_import_result",
		    (char *buf), (buf));

ui_define_operation(_ui_popup, "ui_popup",
		    (char *buf), (buf));

ui_define_operation(ui_query_import_contacts, "ui_query_import_contacts",
		    (ship_list_t *list), (list));

ui_define_operation(ui_query_simple, "ui_query_simple",
		    (char *header, char *body, char *true_op, char *false_op), 
		    (header, body, true_op, false_op));

ui_define_operation(ui_query_three, "ui_query_three",
		    (char *header, char *body, char *one_op, char *two_op, char *three_op), 
		    (header, body, one_op, two_op, three_op));

/* new ones */
ui_define_operation(ui_query_filechooser, "ui_query_filechooser",
		    (const char *header, const char *title, const char *dir, ship_list_t *filetypes, char **ret),
		    (header, title, dir, filetypes, ret));

ui_define_operation(ui_query_listchooser, "ui_query_listchooser",
		    (const char *header, const char *title, ship_list_t *options, char **ret),
		    (header, title, options, ret));


/* these require wrappers for the variable arguments .. */
void
ui_popup(const char *template, ...)
{
	char *buf = mallocz(strlen(template) + 2048);
	
	va_list ap;
	va_start(ap, template);
	vsprintf(buf, template, ap);
	va_end(ap);

	_ui_popup(buf);
	free(buf);
}

void
ui_print_import_result(const char *template, ...)
{
	char *buf = mallocz(strlen(template) + 2048);
	
	va_list ap;
	va_start(ap, template);
	vsprintf(buf, template, ap);
	va_end(ap);

	_ui_print_import_result(buf);
	free(buf);
}

void
ui_print_error(const char *template, ...)
{
	char *buf = mallocz(strlen(template) + 2048);
	
	va_list ap;
	va_start(ap, template);
	vsprintf(buf, template, ap);
	va_end(ap);

	_ui_print_error(buf);
	free(buf);
}

/* the ui register */
static struct processor_module_s processor_module = 
{
	.init = ui_init,
	.close = ui_close,
	.name = "ui",
	.depends = "",
};

/* register func */
void
ui_register() 
{
	processor_register(&processor_module);
}
