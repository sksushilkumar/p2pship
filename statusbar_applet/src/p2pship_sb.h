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
#ifndef P2PSHIP_PLUGIN_H
#define P2PSHIP_PLUGIN_H

#include <glib-object.h>

/* For Status Bar plugins */
#include <libhildondesktop/statusbar-item.h>

G_BEGIN_DECLS

/* Common struct types declarations */
typedef struct _P2pshipPlugin P2pshipPlugin;
typedef struct _P2pshipPluginClass P2pshipPluginClass;
typedef struct _P2pshipPluginPrivate P2pshipPluginPrivate;

#define P2PSHIP_PLUGIN_GET_PRIVATE(obj) \
			(G_TYPE_INSTANCE_GET_PRIVATE ((obj), \
			P2PSHIP_PLUGIN, \
			P2pshipPluginPrivate));

/* Common macros */
#define MY_TYPE_STATUSBAR_PLUGIN            (p2pship_plugin_get_type ())
#define P2PSHIP_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), MY_TYPE_STATUSBAR_PLUGIN, P2pshipPlugin))
#define P2PSHIP_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  MY_TYPE_STATUSBAR_PLUGIN, P2pshipPluginClass))
#define P2PSHIP_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  MY_TYPE_STATUSBAR_PLUGIN, P2pshipPluginClass))

/* Instance struct */
struct _P2pshipPlugin
{
  StatusbarItem sbitem;

  P2pshipPluginPrivate *priv;
};

/* Class struct */
struct _P2pshipPluginClass
{
  StatusbarItemClass parent_class;
};

GType  p2pship_plugin_get_type  (void);

G_END_DECLS

/* debuggign */
//#define do_log(...)
#define do_log(fmt, args...) _do_log(fmt, ##args)
void _do_log(const char *template, ...);

/* paths */
#define SOCK_PATH "/tmp/p2pship.socket"
#define IMG_ROOT "/usr/share/p2pship_statusbar/sb"
#define ICON_ROOT "/usr/share/p2pship_statusbar/icons"
#define PATHLEN_CONF_KEY "ac_maxpath"
#define UAMODE_CONF_KEY "sipp_ua_mode"


#endif /* P2PSHIP_PLUGIN_H */
