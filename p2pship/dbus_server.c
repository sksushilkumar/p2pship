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
#include "dbus_server.h"
#include "processor.h"
#include "processor_config.h"

#include "ship_utils.h"

#ifdef CONFIG_MAEMOEXTS_ENABLED
#include <libosso.h>
static osso_context_t *osso_context = 0;
#endif

#undef LOG_DEBUG
#undef LOG_INFO
#include "ship_debug.h"
#include "ui.h"

#ifdef CONFIG_MAEMOEXTS_ENABLED
/* callback for the dbus calls */
static gint 
dbus_req_handler(const gchar *interface, const gchar *method,
		 GArray *arguments, gpointer data,
		 osso_rpc_t *retval)
{
	osso_context_t *ctx;
	int i;
	ctx = (osso_context_t *)data;
	
	LOG_INFO("We got D-BUS message %s\n", method);
	
	if (!strcmp(method, "top_application")) {
		/* ui_open_frontpage */
		ui_open_frontpage();
	} else if (!strcmp(method, "mime_open")) {
		/* import .. */
		for (i = 0; i < arguments->len; i++) {
			osso_rpc_t val = g_array_index(arguments, osso_rpc_t, i);
			if (val.type == DBUS_TYPE_STRING && val.value.s != NULL) {
				LOG_INFO("\tparam %s\n", val.value.s);
				
				/* the file might be as an url or just the path */
				if (strstr(val.value.s, "file://") == val.value.s) {
					ident_import_file((char*)(val.value.s + strlen("file://")), 1);
				} else {
					ident_import_file((char*)(val.value.s), 1);
				}
				
				/* we should save the idents stuff now .. */
			}
		}
	} else {
		osso_system_note_infoprint(ctx, method, retval);
	}
	osso_rpc_free_val(retval);
	
	return OSSO_OK;
}
#endif

int 
dbus_init(processor_config_t *config)
{
	int ret = -1;

	LOG_DEBUG("Initing dbus..\n");
	
#ifdef CONFIG_MAEMOEXTS_ENABLED
	osso_return_t result;
	ASSERT_TRUE(osso_context = osso_initialize("org.p2pship.p2pship_libosso",
						   "0.0.1", TRUE, NULL), err);
	
	/* Add handler for session bus D-BUS messages */
	result = osso_rpc_set_cb_f(osso_context, 
				   "org.p2pship.p2pship_libosso", 
				   "/org/p2pship/p2pship_libosso", 
				   "org.p2pship.p2pship_libosso",
				   dbus_req_handler, osso_context);
	
	ASSERT_TRUE(result == OSSO_OK, err);
#endif
	ASSERT_TRUE(1, err);
	ret = 0;
 err:
	return ret;
}

void
dbus_close()
{
}

/* the dbus register */
static struct processor_module_s processor_module = 
{
	.init = dbus_init,
	.close = dbus_close,
	.name = "dbus",
	.depends = "ident",
};

/* register func */
void
dbus_register() 
{
	processor_register(&processor_module);
}
