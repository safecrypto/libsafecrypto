
###############################################################################
#                       SAFEcrypto Threading TOOLBOX
###############################################################################

if WITH_MULTITHREADING

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir)/include -I$(top_srcdir)/src -pthread

# Convenience library
noinst_LTLIBRARIES        = libthreading.la
libthreading_la_SOURCES   = threading.c \
                            threading.h \
                            threadpool.c \
                            threadpool.h \
                            pipe.c \
                            pipe.h

# Add any link library dependencies
libthreading_la_LIBADD    = 

endif
