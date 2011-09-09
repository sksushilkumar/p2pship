#
# 

AC_INIT([p2pship], [2.0], [bugs-p2pship@hiit.fi])
AC_PREREQ(2.59)
AC_CONFIG_SRCDIR([p2pship/main.c])
AM_INIT_AUTOMAKE([p2pship], [2.0])

# we are programming in c
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_CXX
AC_PROG_LIBTOOL

# outscope pkg-config
PKG_PROG_PKG_CONFIG


# check for hipl headers .. 
#AC_CHECK_HEADER(hidb.h, [], AC_MSG_ERROR[This application requires HIPL to be installed])

# some hipl-specific flags
AC_SUBST(hipl_common_include_paths, "-I ../opendht")

#
# the command-line flags
#

AC_ARG_ENABLE(gtk,
             AC_HELP_STRING([--enable-gtk],
                            [Enable GTK mainloop (default is NO)]),
             [ac_cv_use_gtk=$enableval], [ac_cv_use_gtk=no])

# media handling, gstreamer
AC_ARG_ENABLE(media,
             AC_HELP_STRING([--disable-media],
                            [Disable media handling extensions (default is NO)]),
             [ac_cv_use_media=$enableval], [ac_cv_use_media=yes])

# the python support
AC_ARG_ENABLE(python,
             AC_HELP_STRING([--disable-python],
                            [Disable Python extensions support (default is NO)]),
             [ac_cv_use_python=$enableval], [ac_cv_use_python=yes])

# op
AC_ARG_ENABLE(op,
             AC_HELP_STRING([--enable-op],
                            [Enable OP daemon support (default is NO)]),
             [ac_cv_use_op=$enableval], [ac_cv_use_op=no])

# hip
AC_ARG_ENABLE(hip,
             AC_HELP_STRING([--disable-hip],
                            [Disable HIP support (default is NO)]),
             [ac_cv_use_hip=$enableval], [ac_cv_use_hip=yes])

# blooms
AC_ARG_ENABLE(bloombuddies,
             AC_HELP_STRING([--disable-bloombuddies],
                            [Disable bloombuddies support (default is NO)]),
             [ac_cv_use_bloombuddies=$enableval], [ac_cv_use_bloombuddies=yes])

# opendht
AC_ARG_ENABLE(opendht,
             AC_HELP_STRING([--enable-opendht],
                            [Enable OpenDHT lookup support (default is NO)]),
             [ac_cv_use_opendht=$enableval], [ac_cv_use_opendht=no])

# proxy
AC_ARG_ENABLE(httpproxy,
             AC_HELP_STRING([--disable-httpproxy],
                            [Disable HTTP proxy for overlay requests (default is NO)]),
             [ac_cv_use_httpproxy=$enableval], [ac_cv_use_httpproxy=yes])

# broadcast
AC_ARG_ENABLE(broadcast,
             AC_HELP_STRING([--disable-broadcast],
                            [Disable broadcast lookup support (default is No)]),
             [ac_cv_use_broadcast=$enableval], [ac_cv_use_broadcast=yes])

# p2pship ext
AC_ARG_ENABLE(p2pext,
             AC_HELP_STRING([--disable-p2pext],
                            [Disable P2PSHIP EXT interface lookup (default is No)]),
             [ac_cv_use_p2pext=$enableval], [ac_cv_use_p2pext=yes])

# webconf
AC_ARG_ENABLE(webconf,
             AC_HELP_STRING([--disable-webconf],
                            [Disable Web configuration interface support (default is NO)]),
             [ac_cv_use_webconf=$enableval], [ac_cv_use_webconf=yes])

# extapi
AC_ARG_ENABLE(extapi,
             AC_HELP_STRING([--disable-extapi],
                            [Disable the external HTTP API (default is NO)]),
             [ac_cv_use_extapi=$enableval], [ac_cv_use_extapi=yes])
# webcache
AC_ARG_ENABLE(webcache,
             AC_HELP_STRING([--disable-webcache],
                            [Disable the webcache (default is NO)]),
             [ac_cv_use_webcache=$enableval], [ac_cv_use_webcache=yes])

# sip
AC_ARG_ENABLE(sip,
             AC_HELP_STRING([--disable-sip],
                            [Disable SIP UA proxy (default is NO)]),
             [ac_cv_use_sip=$enableval], [ac_cv_use_sip=yes])

# -dbus
AC_ARG_ENABLE(dbus,
             AC_HELP_STRING([--enable-dbus],
                            [Enable DBUS IPC support (default is NO)]),
             [ac_cv_use_dbus=$enableval], [ac_cv_use_dbus=no])
# gtk ui
AC_ARG_ENABLE(gtkui,
             AC_HELP_STRING([--enable-gtkui],
                            [Enable GTK-based UI (default is NO)]),
             [ac_cv_use_gtkui=$enableval], [ac_cv_use_gtkui=no])

# maemo ui
AC_ARG_ENABLE(maemoui,
             AC_HELP_STRING([--enable-maemoui],
                            [Enable Maemo-specific UI (default is NO)]),
             [ac_cv_use_maemoui=$enableval], [ac_cv_use_maemoui=no])

# libebook
AC_ARG_ENABLE(libebook,
             AC_HELP_STRING([--enable-libebook],
                            [Enable EDS contacts support (default is NO)]),
             [ac_cv_use_libebook=$enableval], [ac_cv_use_libebook=no])

# mc
AC_ARG_ENABLE(mc,
             AC_HELP_STRING([--enable-mc],
                            [Enable mission control account configuration support (default is NO)]),
             [ac_cv_use_mc=$enableval], [ac_cv_use_lmc=no])

# abs
AC_ARG_ENABLE(abs,
             AC_HELP_STRING([--enable-abs],
                            [Enable address-book based buddy subscribe simulation (default is NO)]),
             [ac_cv_use_abs=$enableval], [ac_cv_use_labs=no])

# maemo specifics
AC_ARG_ENABLE(maemoexts,
             AC_HELP_STRING([--enable-maemoexts],
                            [Enable misc. Maemo extensions (default is NO)]),
             [ac_cv_use_maemoexts=$enableval], [ac_cv_use_maemoexts=no])

# maemo, all
AC_ARG_ENABLE(maemo,
             AC_HELP_STRING([--enable-maemo],
                            [Enable all Maemo-related options (default is NO)]),
             [ac_cv_use_maemo=$enableval], [ac_cv_use_maemo=no])

# maemo, pre
AC_ARG_ENABLE(maemopre,
             AC_HELP_STRING([--enable-maemopre],
                            [Enable all Maemo-related options with PRE (default is NO)]),
             [ac_cv_use_maemopre=$enableval], [ac_cv_use_maemopre=no])


#
# macros
#

# maemo-pre almost the same as maemo
AC_CACHE_CHECK([whether to use maemo pre configuration],
               [ac_cv_use_maemopre], [ac_cv_use_maemopre=no])
if test x"$ac_cv_use_maemopre" = x"yes"; then
	      ac_cv_use_maemo="yes"
fi

AC_CACHE_CHECK([whether to use maemo configuration],
               [ac_cv_use_maemo], [ac_cv_use_maemo=no])
if test x"$ac_cv_use_maemo" = x"yes"; then
	      ac_cv_use_dbus="yes"
	      ac_cv_use_maemoui="yes"
	      ac_cv_use_libebook="yes"
	      ac_cv_use_mc="yes"
	      ac_cv_use_abs="yes"
	      ac_cv_use_maemoexts="yes"
	      ac_cv_use_media="no"
	      ac_cv_use_python="no"
fi

if test x"$ac_cv_use_maemopre" = x"yes"; then
	      ac_cv_use_media="yes"
	      ac_cv_use_python="yes"
fi

#
# handling of options
#

# media
AC_CACHE_CHECK([whether to enable media handling extensions],
               [ac_cv_use_media], [ac_cv_use_media=yes])
if test x"$ac_cv_use_media" = x"yes"; then
        AC_DEFINE(CONFIG_MEDIA_ENABLED, [1], [Use media handling extensions])
	PKG_CHECK_MODULES(MEDIA, gstreamer-0.10)

	AC_SUBST(MEDIA_CFLAGS)
	AC_SUBST(MEDIA_LIBS)
	CFLAGS="$CFLAGS $MEDIA_CFLAGS"
	LIBS="$LIBS $MEDIA_LIBS"
        ac_cv_use_gtk="yes"
fi
AM_CONDITIONAL(MEDIA_ENABLED, test x"$ac_cv_use_media" = x"yes")

# python
AC_CACHE_CHECK([whether to enable python extensions],
               [ac_cv_use_python], [ac_cv_use_python=yes])
if test x"$ac_cv_use_python" = x"yes"; then
        AC_DEFINE(CONFIG_PYTHON_ENABLED, [1], [Use Python extensions])
	AC_CHECK_LIB([python2.5],[Py_Initialize],,AC_MSG_ERROR([This application needs the python2.5 library]),[-lpython2.5])
	CFLAGS="$CFLAGS -I/usr/include/python2.5"
fi
AM_CONDITIONAL(PYTHON_ENABLED, test x"$ac_cv_use_python" = x"yes")

# op
AC_CACHE_CHECK([whether to use op],
               [ac_cv_use_op], [ac_cv_use_op=no])
if test x"$ac_cv_use_op" = x"yes"; then
   AC_CHECK_LIB([opconn],[opconn_init],,AC_MSG_ERROR([This application needs the opconn library]),[])
   AC_DEFINE(CONFIG_OP_ENABLED, [1], [Support OP personas])
fi
AM_CONDITIONAL(OP_ENABLED, test x"$ac_cv_use_op" = x"yes")

# hip
AC_CACHE_CHECK([whether to use hip],
               [ac_cv_use_hip], [ac_cv_use_hip=yes])
if test x"$ac_cv_use_hip" = x"yes"; then
        AC_DEFINE(CONFIG_HIP_ENABLED, [1], [Use HIP for connections])
        AC_CHECK_LIB([hipcore],[hip_do_hipconf],,AC_MSG_ERROR([This application needs the hipconf library]),[-lhipcore -lpthread -lssl -lcrypto])
#        AC_CHECK_LIB([hiptool],[main],,AC_MSG_ERROR([This application needs the hipconf library]),[])
fi
AM_CONDITIONAL(HIP_ENABLED, test x"$ac_cv_use_hip" = x"yes")

# bloom
AC_CACHE_CHECK([whether to use bloombuddies],
               [ac_cv_use_bloombuddies], [ac_cv_use_bloombuddies=yes])
if test x"$ac_cv_use_bloombuddies" = x"yes"; then
        AC_DEFINE(CONFIG_BLOOMBUDDIES_ENABLED, [1], [Use HIP for connections])
fi
AM_CONDITIONAL(BLOOMBUDDIES_ENABLED, test x"$ac_cv_use_hip" = x"yes")

# opendht
AC_CACHE_CHECK([whether to use opendht],
               [ac_cv_use_opendht], [ac_cv_use_opendht=no])
if test x"$ac_cv_use_opendht" = x"yes"; then
        AC_DEFINE(CONFIG_OPENDHT_ENABLED, [1], [Enable OpenDHT storage back-end])
fi
AM_CONDITIONAL(OPENDHT_ENABLED, test x"$ac_cv_use_opendht" = x"yes")

#
AC_CACHE_CHECK([whether to use httpproxy],
               [ac_cv_use_httpproxy], [ac_cv_use_httpproxy=yes])
if test x"$ac_cv_use_httpproxy" = x"yes"; then
        AC_DEFINE(CONFIG_HTTPPROXY_ENABLED, [1], [Enable HTTP proxy for overlay requests])
fi
AM_CONDITIONAL(HTTPPROXY_ENABLED, test x"$ac_cv_use_httpproxy" = x"yes")

#
AC_CACHE_CHECK([whether to use broadcast],
               [ac_cv_use_broadcast], [ac_cv_use_broadcast=yes])
if test x"$ac_cv_use_broadcast" = x"yes"; then
        AC_DEFINE(CONFIG_BROADCAST_ENABLED, [1], [Enable Broadcast storage back-end])
fi
AM_CONDITIONAL(BROADCAST_ENABLED, test x"$ac_cv_use_broadcast" = x"yes")

#
AC_CACHE_CHECK([whether to use p2pship ext lookup],
               [ac_cv_use_p2pext], [ac_cv_use_p2pext=yes])
if test x"$ac_cv_use_p2pext" = x"yes"; then
        AC_DEFINE(CONFIG_P2PEXT_ENABLED, [1], [Enable P2PSIP EXT lookup])
fi
AM_CONDITIONAL(P2PEXT_ENABLED, test x"$ac_cv_use_p2pext" = x"yes")

#
AC_CACHE_CHECK([whether to use webconf],
               [ac_cv_use_webconf], [ac_cv_use_webconf=yes])
if test x"$ac_cv_use_webconf" = x"yes"; then
        AC_DEFINE(CONFIG_WEBCONF_ENABLED, [1], [Enable webconf interface])
fi
AM_CONDITIONAL(WEBCONF_ENABLED, test x"$ac_cv_use_webconf" = x"yes")

#
AC_CACHE_CHECK([whether to enable the external HTTP API],
               [ac_cv_use_extapi], [ac_cv_use_extapi=yes])
if test x"$ac_cv_use_extapi" = x"yes"; then
        AC_DEFINE(CONFIG_EXTAPI_ENABLED, [1], [Enable extapi interface])
fi
AM_CONDITIONAL(EXTAPI_ENABLED, test x"$ac_cv_use_extapi" = x"yes")

#
AC_CACHE_CHECK([whether to enable the webcache],
               [ac_cv_use_webcache], [ac_cv_use_webcache=yes])
if test x"$ac_cv_use_webcache" = x"yes"; then
        AC_DEFINE(CONFIG_WEBCACHE_ENABLED, [1], [Enable webcache])
fi
AM_CONDITIONAL(WEBCACHE_ENABLED, test x"$ac_cv_use_webcache" = x"yes")

#
AC_CACHE_CHECK([whether to enable the SIP UA proxy],
               [ac_cv_use_sip], [ac_cv_use_sip=yes])
if test x"$ac_cv_use_sip" = x"yes"; then
        AC_DEFINE(CONFIG_SIP_ENABLED, [1], [Enable sip interface])
	#AC_CHECK_LIB([osip2],[main],,AC_MSG_ERROR([This application needs the osip2 (dev) library]),[-lpthread])
	PKG_CHECK_MODULES(OSIP, libosip2 >= 2.0)
	if pkg-config --atleast-version=3.0.0 libosip2; then
	   AC_DEFINE([HAVE_OSIP2_V3], [1], [You seem to have osip2 v3])
	fi

	AC_SUBST(OSIP_CFLAGS)
	AC_SUBST(OSIP_LIBS)
	CFLAGS="$CFLAGS $OSIP_CFLAGS"
	LIBS="$LIBS $OSIP_LIBS"
fi
AM_CONDITIONAL(SIP_ENABLED, test x"$ac_cv_use_sip" = x"yes")

# dus, again
AC_CACHE_CHECK([whether to use dbus],
               [ac_cv_use_dbus], [ac_cv_use_dbus=no])
if test x"$ac_cv_use_dbus" = x"yes"; then
        AC_DEFINE(CONFIG_DBUS_ENABLED, [1], [Enable dbus interface])
	PKG_CHECK_MODULES(OSSO, libosso >= 2.0)

	AC_SUBST(OSSO_CFLAGS)
	AC_SUBST(OSSO_LIBS)
	CFLAGS="$CFLAGS $OSSO_CFLAGS"
	LIBS="$LIBS $OSSO_LIBS"
        ac_cv_use_gtk="yes"
fi
AM_CONDITIONAL(DBUS_ENABLED, test x"$ac_cv_use_dbus" = x"yes")

# maemoui
AC_CACHE_CHECK([whether to use maemoui],
               [ac_cv_use_maemoui], [ac_cv_use_maemoui=no])
if test x"$ac_cv_use_maemoui" = x"yes"; then
        AC_DEFINE(CONFIG_MAEMOUI_ENABLED, [1], [Enable maemoui interface])
	PKG_CHECK_MODULES(MAEMOUI, hildon-desktop hildon-1)

	AC_SUBST(MAEMOUI_CFLAGS)
	AC_SUBST(MAEMOUI_LIBS)
	CFLAGS="$CFLAGS $MAEMOUI_CFLAGS"
	LIBS="$LIBS $MAEMOUI_LIBS"
        ac_cv_use_gtkui="yes"
fi
AM_CONDITIONAL(MAEMOUI_ENABLED, test x"$ac_cv_use_maemoui" = x"yes")

# gtkui
AC_CACHE_CHECK([whether to use gtkui],
               [ac_cv_use_gtkui], [ac_cv_use_gtkui=no])
if test x"$ac_cv_use_gtkui" = x"yes"; then
        AC_DEFINE(CONFIG_GTKUI_ENABLED, [1], [Enable GTK UI interface])
        ac_cv_use_gtk="yes"

	PKG_CHECK_MODULES([LIBNOTIFY],[libnotify >= 0.4.1],
 			  [HAVE_LIBNOTIFY="yes"],[HAVE_LIBNOTIFY="no"])
	if pkg-config --atleast-version=0.7.0 libnotify; then
	   AC_DEFINE([HAVE_LIBNOTIFY_NEW], [1], [You seem to have a newer version of libnotify.])
	fi
 	AC_SUBST([LIBNOTIFY_CFLAGS])
 	AC_SUBST([LIBNOTIFY_LIBS])
	CFLAGS="$CFLAGS $LIBNOTIFY_CFLAGS"
	LIBS="$LIBS $LIBNOTIFY_LIBS"
 	
 	if test "x$HAVE_LIBNOTIFY" = "xyes"; then
	 	AC_DEFINE([HAVE_LIBNOTIFY],[1],[libnotify is available on this machine])
 	fi
fi
AM_CONDITIONAL(GTKUI_ENABLED, test x"$ac_cv_use_gtkui" = x"yes")

# libebook
AC_CACHE_CHECK([whether to use libebook],
               [ac_cv_use_libebook], [ac_cv_use_libebook=no])
if test x"$ac_cv_use_libebook" = x"yes"; then
        AC_DEFINE(CONFIG_LIBEBOOK_ENABLED, [1], [Enable libebook interface])
	PKG_CHECK_MODULES(LIBEBOOK, libosso >= 2.0 libebook-1.2)

	AC_SUBST(LIBEBOOK_CFLAGS)
	AC_SUBST(LIBEBOOK_LIBS)
	CFLAGS="$CFLAGS $LIBEBOOK_CFLAGS"
	LIBS="$LIBS $LIBEBOOK_LIBS"
        ac_cv_use_gtk="yes"
fi
AM_CONDITIONAL(LIBEBOOK_ENABLED, test x"$ac_cv_use_libebook" = x"yes")

# mc
AC_CACHE_CHECK([whether to use mission control],
               [ac_cv_use_mc], [ac_cv_use_mc=no])
if test x"$ac_cv_use_mc" = x"yes"; then
        AC_DEFINE(CONFIG_MC_ENABLED, [1], [Enable mission control])
	PKG_CHECK_MODULES(MC, mission-control)

	AC_SUBST(MC_CFLAGS)
	AC_SUBST(MC_LIBS)
	CFLAGS="$CFLAGS $MC_CFLAGS"
	LIBS="$LIBS $MC_LIBS"
        ac_cv_use_gtk="yes"
fi
AM_CONDITIONAL(MC_ENABLED, test x"$ac_cv_use_mc" = x"yes")

# abs
AC_CACHE_CHECK([whether to do address-book based subscribes],
               [ac_cv_use_abs], [ac_cv_use_abs=no])
if test x"$ac_cv_use_abs" = x"yes"; then
        AC_DEFINE(CONFIG_ABS_ENABLED, [1], [Enable address-book subscribes])
fi

# maemoexts
AC_CACHE_CHECK([whether to use maemoexts],
               [ac_cv_use_maemoexts], [ac_cv_use_maemoexts=no])
if test x"$ac_cv_use_maemoexts" = x"yes"; then
        AC_DEFINE(CONFIG_MAEMOEXTS_ENABLED, [1], [Enable maemoexts interface])
	CFLAGS="$CFLAGS -fno-strict-aliasing"
fi

# the gtk mainloop. activated by default in certain other ones..
AC_CACHE_CHECK([whether to enable gtk mainloop],
               [ac_cv_use_gtk], [ac_cv_use_gtk=yes])
AS_IF([test x"$ac_cv_use_gtk" = "xyes"], [
        AC_DEFINE(CONFIG_START_GTK, [1], [Startup the GTK signal system])
	PKG_CHECK_MODULES(GTK, gtk+-2.0 >= 2.10.0)

	AC_SUBST(GTK_CFLAGS)
	AC_SUBST(GTL_LIBS)
	CFLAGS="$CFLAGS $GTK_CFLAGS"
	LIBS="$LIBS $GTK_LIBS"
])
AM_CONDITIONAL(GTK_ENABLED, test x"$ac_cv_use_gtk" = x"yes")



# headers

AC_CHECK_LIB([pthread],[main],,AC_MSG_ERROR([This application needs the pthread library]),[])

# check openssl version
if pkg-config --atleast-version=0.9.8 openssl; then
       AC_DEFINE([HAVE_OPENSSL_0_9_8], [1], [You seem to have OpenSSL >= 0.9.8])
fi

# pkg-based checks
PKG_CHECK_MODULES(DEPS, libxml-2.0 >= 1.0.0 openssl >= 0.9.6)
#PKG_CHECK_MODULES(DEPS, glib-2.0 >= 1.0.0 libxml-2.0 >= 1.0.0 openssl >= 0.9.6)

AC_SUBST(DEPS_CFLAGS)
AC_SUBST(DEPS_LIBS)

CFLAGS="$CFLAGS $DEPS_CFLAGS -Wall -Werror"
LIBS="$LIBS $DEPS_LIBS"


AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([
	Makefile
	p2pship/Makefile
	p2pship/ol_opendht/Makefile
	p2pship/ol_broadcast/Makefile
	p2pship/ol_p2pext/Makefile
])

# 
AC_OUTPUT