
# List the subdirectories that are conditionally built
if WITH_RLWE_ENC
MAYBE_RLWE_ENC = rlwe_enc
endif

if WITH_KYBER_ENC
MAYBE_KYBER = kyber
endif

# Define the subdirectories that must be built, including conditionally
SUBDIRS = $(MAYBE_RLWE_ENC) $(MAYBE_KYBER)

# Explicitly define the subdirectories that must be distributed
DIST_SUBDIRS = $(MAYBE_RLWE_ENC) $(MAYBE_KYBER)

