
# List the subdirectories that are conditionally built
if WITH_ECDH_KEM
MAYBE_ECDH=ecdh
endif

# Define the subdirectories that must be built, including conditionally
SUBDIRS = $(MAYBE_ECDH)

# Explicitly define the subdirectories that must be distributed
DIST_SUBDIRS = $(MAYBE_ECDH)
