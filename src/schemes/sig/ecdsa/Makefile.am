
###############################################################################
#                         ECDSA SIGNATURE SCHEME
###############################################################################

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

# Convenience library
noinst_LTLIBRARIES       = libecdsa.la

libecdsa_la_SOURCES      = ecdsa.c \
                           ecdsa.h

# Add any link library dependencies
libecdsa_la_LIBADD       = 
