
###############################################################################
#                         FALCON SIGNATURE SCHEME
###############################################################################

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

# Convenience library
noinst_LTLIBRARIES       = libfalcon.la

libfalcon_la_SOURCES     = falcon.c \
                           falcon.h \
                           falcon_params.c \
                           falcon_params.h \
                           split_and_merge.c \
                           split_and_merge.h

# Add any link library dependencies
libfalcon_la_LIBADD      = 
