
###############################################################################
#                                 ECDH SCHEME
###############################################################################

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

# Convenience library
noinst_LTLIBRARIES       = libecdh.la

libecdh_la_SOURCES       = ecdh.c \
                           ecdh.h

# Add any link library dependencies
libecdh_la_LIBADD        = 
