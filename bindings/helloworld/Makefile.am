noinst_PROGRAMS = helloworld_shared helloworld_static

# Common settings for the helloworld executable
HELLOWORLD_LIBS = -L$(top_builddir)/libs -lsafecrypto -lm
HELLOWORLD_SRC  = main.c
HELLOWORLD_INC  = -I$(top_srcdir)/include

# A build of the example program using the static SAFEcrypto library
helloworld_static_LDADD   = $(HELLOWORLD_LIBS)
helloworld_static_SOURCES = $(HELLOWORLD_SRC)
helloworld_static_CFLAGS  = $(HELLOWORLD_INC)
helloworld_static_LDFLAGS = -static

# A build of the example program using the shared SAFEcrypto library
helloworld_shared_LDADD   = $(HELLOWORLD_LIBS)
helloworld_shared_SOURCES = $(HELLOWORLD_SRC)
helloworld_shared_CFLAGS  = $(HELLOWORLD_INC)
helloworld_shared_LDFLAGS = -shared
