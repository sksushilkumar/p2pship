INCLUDES = -I ../

lib_LTLIBRARIES = libhipopendht.la
libhipopendht_la_SOURCES = ol_opendht.c libhipopendht.c libhipopendhtxml.c ../ship_utils.c

bin_PROGRAMS = opendht_test2
opendht_test2_SOURCES = opendht_test2.c
opendht_test2_LDADD = .libs/libhipopendht.a

#bin_PROGRAMS = opendhtteststub
#opendhtteststub_SOURCES = opendhtteststub.c
#opendhtteststub_LDADD = .libs/libhipopendht.a

