AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I/home/nsmyth/Projects/ECIT/libsafecrypto/include

AM_CFLAGS = \
	$(PLUGIN_CFLAGS) \
	@COVERAGE_CFLAGS@

noinst_LTLIBRARIES = libsafecrypto-params.la
libsafecrypto_params_la_SOURCES = \
	safecrypto_params.h safecrypto_params.c

# these files are also used by the tests, we can't directly refer to them
# because of the subdirectory, which would cause distclean to fail
noinst_LTLIBRARIES += libsafecrypto-plugin.la
libsafecrypto_plugin_la_SOURCES = \
	safecrypto_private_key.h safecrypto_private_key.c \
	safecrypto_public_key.h safecrypto_public_key.c
libsafecrypto_plugin_la_LIBADD = libsafecrypto-params.la

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-safecrypto.la
else
plugin_LTLIBRARIES = libstrongswan-safecrypto.la
endif

libstrongswan_safecrypto_la_SOURCES = \
	safecrypto_plugin.h safecrypto_plugin.c

libstrongswan_safecrypto_la_LDFLAGS = -module -avoid-version -lsafecrypto

libstrongswan_safecrypto_la_LIBADD = libsafecrypto-plugin.la

