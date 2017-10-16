
###############################################################################
#                         KYBER ENCRYPTION SCHEME
###############################################################################

if WITH_KYBER_ENC

# C preprocessor flags
AM_CPPFLAGS             += -I$(top_srcdir)/include -I$(top_srcdir)/src

# Convenience library
noinst_LTLIBRARIES       = libkyberenc.la

SOURCEFILES              = kyber_enc.c \
                           kyber_enc.h \
                           kyber_enc_params.c \
                           kyber_enc_params.h

libkyberenc_la_SOURCES   = $(SOURCEFILES)

# Add any link library dependencies
libkyberenc_la_LIBADD    =

endif WITH_KYBER_ENC
