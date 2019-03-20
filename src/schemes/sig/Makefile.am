
# List the subdirectories that are conditionally built
if WITH_BLISS_B_SIG
MAYBE_BLISS_B=bliss_b
endif

if WITH_RING_TESLA_SIG
MAYBE_RING_TESLA=ring_tesla
endif

if BUILD_DILITHIUM
MAYBE_DILITHIUM=dilithium
endif

if BUILD_DLP_ENS_SIG
MAYBE_ENS_DLP=ens_dlp
endif

if WITH_FALCON_SIG
MAYBE_FALCON=falcon
endif

# Define the subdirectories that must be built, including conditionally
SUBDIRS = $(MAYBE_BLISS_B) $(MAYBE_RING_TESLA) $(MAYBE_DILITHIUM) $(MAYBE_ENS_DLP) $(MAYBE_FALCON)

# Explicitly define the subdirectories that must be distributed
DIST_SUBDIRS = $(MAYBE_BLISS_B) $(MAYBE_RING_TESLA) $(MAYBE_DILITHIUM) $(MAYBE_ENS_DLP) $(MAYBE_FALCON)
