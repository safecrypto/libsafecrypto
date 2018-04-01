
###############################################################################
#                          SAFEcrypto ECC TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir)/include -I$(top_srcdir)/src

# Convenience library
noinst_LTLIBRARIES        = libecc.la
libecc_la_SOURCES         = ecc.c \
                            ecc.h \
                            secret_bits.c \
                            secret_bits.h

# Add any link library dependencies
libecc_la_LIBADD          = 
