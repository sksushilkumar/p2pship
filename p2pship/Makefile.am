SUBDIRS = 

ol_libs =
ol_includes = 

if OPENDHT_ENABLED
SUBDIRS += ol_opendht
ol_libs += ol_opendht/.libs/libhipopendht.a
ol_includes += -I ol_opendht/
endif

if BROADCAST_ENABLED
SUBDIRS += ol_broadcast
ol_libs += ol_broadcast/.libs/libolbroadcast.a
ol_includes += -I ol_broadcast/
endif

if P2PEXT_ENABLED
SUBDIRS += ol_p2pext
ol_libs += ol_p2pext/.libs/libolp2pext.a
ol_includes += -I ol_p2pext/
endif

if HIP_ENABLED
#hip_libs = ../libinet6/.libs/libinet6.a ../libhiptool/.libs/libhiptool.a
#hip_includes = -I ../libinet6/ -I ../libhiptool
endif

extra_sources =
if MEDIA_ENABLED
extra_sources += media.c
endif

if DBUS_ENABLED
extra_sources += osso_dbus.c
endif

if MAEMOUI_ENABLED
extra_sources += ui_maemo.c
endif

if MC_ENABLED
extra_sources += mc.c
endif

if EXTAPI_ENABLED
extra_sources += ext_api.c
endif

if SIP_ENABLED
extra_sources += sipp.c sipp_mp.c access_control.c 
endif

if WEBCACHE_ENABLED
extra_sources += webcache.c
endif

if PYTHON_ENABLED
extra_sources += pymod.c
endif

#bin_PROGRAMS = p2pship addrparsetest identdatatest hiptest oltest
#bin_PROGRAMS = p2pship oltest
bin_PROGRAMS = p2pship #httptest
p2pship_SOURCES = main.c processor.c processor_config.c hipapi.c ident.c\
		  olclient.c conn.c netio.c ship_utils.c ship_crypto.c ship_debug.c\
		  ident_addr.c ident_data.c webconf.c netio_http.c netio_man.c\
		  sipp_buddy.c trustman.c netio_events.c ui.c ui_stdin.c $(extra_sources)\
		  addrbook.c resourceman.c

#httptest_SOURCES = httptest.c processor.c processor_config.c sipp.c hipapi.c ident.c\
#		  olclient.c conn.c netio.c ship_utils.c sipp_mp.c ship_debug.c\
#		  ident_addr.c ident_data.c access_control.c webconf.c netio_http.c netio_man.c\
#		  sipp_buddy.c trustman.c netio_events.c

#addrparsetest_SOURCES = addrparsetest.c ident_addr.c ship_utils.c ship_debug.c
#identdatatest_SOURCES = identdatatest.c ident_data.c ship_utils.c ship_debug.c ident_addr.c

#hiptest_SOURCES = hiptest.c ship_utils.c ident_addr.c ship_debug.c hipapi.c netio.c
#hiptest_LDADD = $(hip_libs)

#oltest_SOURCES = oltest.c ship_utils.c ident_addr.c ship_debug.c netio.c olclient.c processor_config.c\
#		 processor.c hipapi.c
#oltest_LDADD = $(ol_libs)

# this should probably be put inside some ifdef at some point
p2pship_LDADD = $(ol_libs) $(hip_libs) $(extra_libs)
#httptest_LDADD = $(ol_libs) $(hip_libs)

p2pship_LDFLAGS = -rdynamic

# if we want to link dynamically..
INCLUDES = $(ol_includes) $(hip_includes)


version:
	@echo "#define P2PSHIP_BUILD_VERSION \""`date +%y-%j.%H%M`"/"`svn info | grep Revision | sed 's/^.*[ ]//'`"\"" > p2pship_version.h

version-commit:
	@echo "#define P2PSHIP_BUILD_VERSION \""`date +%y-%j.%H%M`"/"`svn info | grep Revision | sed 's/^.*[ ]//'|while read nr; do echo $$(($$nr+1)); done`"\"" > p2pship_version.h
	svn commit -m "Version "`svn info | grep Revision | sed 's/^.*[ ]//'|while read nr; do echo $$(($$nr+1)); done`
