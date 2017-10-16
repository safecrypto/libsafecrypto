##############################################################################
# Copyright (C) Queen's University Belfast, ECIT, 2016                       #
#                                                                            #
# This file is part of libsafecrypto.                                        #
#                                                                            #
# This file is subject to the terms and conditions defined in the file       #
# 'LICENSE', which is part of this source code package.                      #
##############################################################################

##############################################################################
# Git commit information:
#   Author: $SC_AUTHOR$
#   Date:   $SC_DATE$
#   Branch: $SC_BRANCH$
#   Id:     $SC_IDENT$
##############################################################################

from SAFEcrypto import *
from ctypes import *
import random


# Create a SAFEcrypto object
py_flags = [SC_FLAG_NONE]
flags = (c_uint * len(py_flags))(*py_flags)
SC = SAFEcrypto(sc_schemes.SC_SCHEME_SIG_BLISS, 4, flags)

# Display the version numbers
print("Version ", SC.get_version())
print("Version string ", SC.get_version_string())

# Generate a key pair
retcode = SC.keygen()
if retcode == 1:
	print("\nKey Generation: Success")
else:
    print("\nKey Generation: Failure")

debug_level = SC.get_debug_level()
print("Debug level: ", sc_debug_level(debug_level))

SC.set_key_coding(sc_entropy_type.SC_ENTROPY_NONE,
	sc_entropy_type.SC_ENTROPY_HUFFMAN_STATIC)
pub_coding = c_int(sc_entropy_type.SC_ENTROPY_NONE)
priv_coding = c_int(sc_entropy_type.SC_ENTROPY_NONE)
SC.get_key_coding(byref(pub_coding), byref(priv_coding))
print("Public key coding:  ", sc_entropy_type(pub_coding.value))
print("Private key coding: ", sc_entropy_type(priv_coding.value))

# Extract and print the public key
pubkey = POINTER(c_ubyte)()
pubkeylen = c_uint(0)
SC.public_key_encode(byref(pubkey), byref(pubkeylen))
print("Public Key [", pubkeylen.value, " bytes]:")
print(pubkeylen.value, pubkey[1:pubkeylen.value])

# Extract and print the private key
privkey = POINTER(c_ubyte)()
privkeylen = c_uint(0)
SC.private_key_encode(byref(privkey), byref(privkeylen))
print("Private Key [", privkeylen.value, " bytes]:")
print(privkeylen.value, privkey[1:privkeylen.value])

# Generate a random 64 byte value to act as a hash
arr = [random.randint(0,256) for _ in range(64)]
m = (c_ubyte * len(arr))(*arr)
print("Hash [64 bytes]\n", m[1:64])
mlen = c_uint(64)

# Sign the message
sig = POINTER(c_ubyte)()
siglen = c_uint(0)
retcode = SC.sign(m, mlen, byref(sig), byref(siglen))
if retcode == 1:
	print("\nSigning: Success")
else:
    print("\nSigning: Failure")
print("Signature [", siglen.value, " bytes]:")
print(sig[1:siglen.value])

# Verify the message
retcode = SC.verify(m, mlen, sig, siglen)
if retcode == 1:
	print("\nVerification: Success")
else:
    print("\nVerification: Failure")

print(SC.processing_stats())

# Destroy the SAFEcrypto object
SC.destroy()
