
###############################################################################
#                         DILITHIUM SIGNATURE SCHEME
###############################################################################

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

# Convenience library
noinst_LTLIBRARIES       = libdilithium.la

libdilithium_la_SOURCES  = dilithium.c \
                           dilithium.h \
                           dilithium_params.c \
                           dilithium_params.h

# Add any link library dependencies
libdilithium_la_LIBADD   = 
