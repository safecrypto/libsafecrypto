
# List the subdirectories that are conditionally built
if WITH_ENS_KEM
MAYBE_ENS = ens
endif

if WITH_KYBER_KEM
MAYBE_KYBER = kyber
endif

# Define the subdirectories that must be built, including conditionally
SUBDIRS = $(MAYBE_ENS) $(MAYBE_KYBER)

# Explicitly define the subdirectories that must be distributed
DIST_SUBDIRS = $(MAYBE_ENS) $(MAYBE_KYBER)
