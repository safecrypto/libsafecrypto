
###############################################################################
#                     SAFEcrypto Entropy Coding TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir)/include -I$(top_srcdir)/src

# Convenience library
noinst_LTLIBRARIES        = libentropy.la
libentropy_la_SOURCES     = packer.h \
                            packer.c \
                            bac.h \
                            bac.c \
                            exp_golomb.h \
                            exp_golomb.c \
                            huffman.h \
                            huffman.c \
                            entropy.h \
                            entropy.c

# Add any link library dependencies
libentropy_la_LIBADD      = 
