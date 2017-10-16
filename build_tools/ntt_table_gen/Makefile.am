
###############################################################################
#                          NTT TABLE GENERATOR
###############################################################################

noinst_PROGRAMS = ntt_table_gen

# Common settings for the ntt_table_gen executable
NTT_TABLE_GEN_LIBS = -lm
NTT_TABLE_GEN_SRC  = main.c \
                     ../../include/safecrypto.h \
                     ../../src/safecrypto_private.h \
                     roots_of_unity.c \
                     roots_of_unity.h \
                     limb.h \
                     limb.c \
                     limb_base.h \
                     limb_base.c \
                     sc_math.c \
                     sc_math.h
NTT_TABLE_GEN_INC  = -I$(top_srcdir)/include -I$(top_srcdir)/src

# A build of the example program using the static SAFEcrypto library
ntt_table_gen_LDADD   = $(NTT_TABLE_GEN_LIBS)
ntt_table_gen_SOURCES = $(NTT_TABLE_GEN_SRC)
ntt_table_gen_CFLAGS  = $(NTT_TABLE_GEN_INC)
ntt_table_gen_LDFLAGS = -static

