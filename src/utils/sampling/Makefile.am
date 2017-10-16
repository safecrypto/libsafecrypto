## Process this file with automake to produce Makefile.in

###############################################################################
#                      SAFEcrypto Cryptographic TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS += -I$(top_srcdir)/include -I$(top_srcdir)/src

# Convenience library
noinst_LTLIBRARIES            = libsampling.la
libsampling_la_SOURCES        = sampling.c \
                                sampling.h \
                                mw_bootstrap.c \
                                mw_bootstrap.h \
                                gaussian_bernoulli.c \
                                gaussian_bernoulli.h \
                                gaussian_cdf.c \
                                gaussian_cdf.h \
                                gaussian_bac.c \
                                gaussian_bac.h \
                                gaussian_huffman.c \
                                gaussian_huffman.h \
                                gaussian_knuth_yao.c \
                                gaussian_knuth_yao.h \
                                gaussian_knuth_yao_fast.c \
                                gaussian_knuth_yao_fast.h

# Add any link library dependencies
libsampling_la_LIBADD     = 
