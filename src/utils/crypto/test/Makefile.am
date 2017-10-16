if HAVE_CHECK
TESTS                         = unit_aes \
                                unit_blake2 \
                                unit_ctr_drbg \
                                unit_hash \
                                unit_hash_drbg \
                                unit_isaac \
                                unit_prng \
                                unit_sha2 \
                                unit_sha3 \
                                unit_whirlpool \
                                unit_xof

noinst_PROGRAMS               = $(TESTS)

unit_aes_SOURCES              = unit_aes.c
unit_aes_CFLAGS               = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_aes_LDFLAGS              = -pthread
endif WITH_MULTITHREADING
unit_aes_LDADD                = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_blake2_SOURCES           = unit_blake2.c
unit_blake2_CFLAGS            = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_blake2_LDFLAGS           = -pthread
endif WITH_MULTITHREADING
unit_blake2_LDADD             = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_ctr_drbg_SOURCES         = unit_ctr_drbg.c
unit_ctr_drbg_CFLAGS          = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_ctr_drbg_LDFLAGS         = -pthread
endif WITH_MULTITHREADING
unit_ctr_drbg_LDADD           = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_hash_SOURCES             = unit_hash.c
unit_hash_CFLAGS              = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_hash_LDFLAGS             = -pthread
endif WITH_MULTITHREADING
unit_hash_LDADD               = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_hash_drbg_SOURCES        = unit_hash_drbg.c
unit_hash_drbg_CFLAGS         = -I$(srcdir)/../
if WITH_MULTITHREADING
unit_hash_drbg_LDFLAGS        = -pthread
endif WITH_MULTITHREADING
unit_hash_drbg_LDADD          = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_isaac_SOURCES            = unit_isaac.c
unit_isaac_CFLAGS             = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_isaac_LDFLAGS            = -pthread
endif WITH_MULTITHREADING
unit_isaac_LDADD              = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_prng_SOURCES             = unit_prng.c
unit_prng_CFLAGS              = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_prng_LDFLAGS             = -pthread
endif WITH_MULTITHREADING
unit_prng_LDADD               = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_sha2_SOURCES             = unit_sha2.c
unit_sha2_CFLAGS              = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_sha2_LDFLAGS             = -pthread
endif WITH_MULTITHREADING
unit_sha2_LDADD               = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_sha3_SOURCES             = unit_sha3.c
unit_sha3_CFLAGS              = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_sha3_LDFLAGS             = -pthread
endif WITH_MULTITHREADING
unit_sha3_LDADD               = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_whirlpool_SOURCES        = unit_whirlpool.c
unit_whirlpool_CFLAGS         = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_whirlpool_LDFLAGS        = -pthread
endif WITH_MULTITHREADING
unit_whirlpool_LDADD          = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

unit_xof_SOURCES              = unit_xof.c
unit_xof_CFLAGS               = -I$(srcdir)/../ @CHECK_CFLAGS@
if WITH_MULTITHREADING
unit_xof_LDFLAGS              = -pthread
endif WITH_MULTITHREADING
unit_xof_LDADD                = ../libcrypto.la @CHECK_LIBS@ -lm -lrt -lsubunit

else
TESTS =
endif
