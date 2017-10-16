
###############################################################################
#                          BLISS-B SIGNATURE SCHEME
###############################################################################

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

# Convenience library
noinst_LTLIBRARIES       = libblissb.la
libblissb_la_SOURCES     = bliss_b.c \
                           bliss_b.h \
                           bliss_params.h \
                           bliss_params.c

# Add any link library dependencies
libblissb_la_LIBADD      = 