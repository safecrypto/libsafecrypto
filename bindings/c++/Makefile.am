noinst_PROGRAMS = SAFEcryptoTest_CPP_shared SAFEcryptoTest_CPP_static

# Common settings for the helloworld executable
SAFECRYPTO_LIBS = -L$(top_builddir)/libs -lsafecrypto -lm
SAFECRYPTO_SRCS = Test.cpp SAFEcrypto.cpp SAFEcrypto.hpp
SAFECRYPTO_INC  = -I$(top_srcdir)/include

# A build of the example program using the static SAFEcrypto library
SAFEcryptoTest_CPP_static_LDADD    = $(SAFECRYPTO_LIBS)
SAFEcryptoTest_CPP_static_SOURCES  = $(SAFECRYPTO_SRCS)
SAFEcryptoTest_CPP_static_CPPFLAGS = $(SAFECRYPTO_INC)
SAFEcryptoTest_CPP_static_LDFLAGS  = -static

# A build of the example program using the shared SAFEcrypto library
SAFEcryptoTest_CPP_shared_LDADD    = $(SAFECRYPTO_LIBS)
SAFEcryptoTest_CPP_shared_SOURCES  = $(SAFECRYPTO_SRCS)
SAFEcryptoTest_CPP_shared_CPPFLAGS = $(SAFECRYPTO_INC)
SAFEcryptoTest_CPP_shared_LDFLAGS  = -shared
