
###############################################################################
#                         RING-TESLA SIGNATURE SCHEME
###############################################################################

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include \
                           -I$(top_srcdir)/src \
                           -I$(top_srcdir)/src/utils/crypto

# Convenience library
noinst_LTLIBRARIES       = libringtesla.la
libringtesla_la_SOURCES  = ring_tesla.c \
                           ring_tesla.h \
                           random_oracle.c \
                           random_oracle.h \
                           ring_tesla_params.c \
                           ring_tesla_params.h

# Add any link library dependencies
libringtesla_la_LIBADD   = 
