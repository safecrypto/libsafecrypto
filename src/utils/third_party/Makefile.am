
###############################################################################
#                      Extract and build libtommath
###############################################################################

#EXTRA_DIST = libtommath-develop.zip
#ZIPFILES = libtommath-develop.zip
#LIBTOMMATH_STATIC_LIB = libtommath-develop/libtommath.a
#
#EXTRACT_TARGETS := $(addprefix .extract_,$(ZIPFILES))
#CLEAN_TARGETS := $(addprefix .clean_,$(ZIPFILES))
#
#$(LIBTOMMATH_STATIC_LIB): $(EXTRACT_TARGETS)
#	cd $(basename $(patsubst .extract_%,%,$<)) && CFLAGS="-fPIC" $(MAKE) $(AM_MAKEFLAGS)
#
#all-local: $(LIBTOMMATH_STATIC_LIB)
#clean-local: $(CLEAN_TARGETS)
#
#dist-hook:
#
#$(CLEAN_TARGETS): .clean_%: .extract_%
#	rm -rf $< $(basename $(patsubst .extract_%,%,$<))
#	rm -f $<
#
#$(EXTRACT_TARGETS): .extract_%: %
#	unzip -o $<
#	touch $@
#
#.PHONY: default clean $(CLEAN_TARGETS)
#
#AM_CPPFLAGS              += -I$(top_srcdir)/src/utils/third_party/libtommath-develop


###############################################################################
#                      SAFEcrypto Third Party TOOLBOX
###############################################################################

# C preprocessor flags
AM_CPPFLAGS              += -I$(top_srcdir)/include \
                            -I$(top_srcdir)/src

# Convenience libraries
noinst_LTLIBRARIES        = lib_3rd_party.la
lib_3rd_party_la_SOURCES  = 
lib_3rd_party_la_LIBADD   = 

