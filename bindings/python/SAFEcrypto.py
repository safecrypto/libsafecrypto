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

from ctypes import *
import ctypes as c
from enum import IntEnum

lib = cdll.LoadLibrary('libsafecrypto.so')

SC_FLAG_NONE                    = 0x00000000  # Disable all flags
SC_FLAG_ENTROPY_BAC             = 0x00000001  # BAC compression
SC_FLAG_ENTROPY_BAC_RLE         = 0x00000002  # BAC with RLE compression
SC_FLAG_ENTROPY_STRONGSWAN      = 0x00000004  # strongSwan compatible Huffman compression
SC_FLAG_ENTROPY_HUFFMAN_STATIC  = 0x00000008  # Huffman compression
SC_FLAG_SAMPLE_BLINDING         = 0x00000100  # Enable blinding countermeasures
SC_FLAG_SAMPLE_CDF              = 0x00000200  # CDF Gaussian sampler
SC_FLAG_SAMPLE_KNUTH_YAO        = 0x00000400  # Knuth Yao Gaussian sampler
SC_FLAG_SAMPLE_ZIGGURAT         = 0x00000800  # Ziggurat gaussian sampler
SC_FLAG_SAMPLE_BAC              = 0x00001000  # BAC Gaussian sampler
SC_FLAG_SAMPLE_HUFFMAN          = 0x00002000  # Huffman decoder Gaussian sampler
SC_FLAG_SAMPLE_BERNOULLI        = 0x00004000  # Bernoulli Gaussian sampler
SC_FLAG_HASH_LENGTH_MASK        = 0x00030000  # Mask used to isolate hash length selection
SC_FLAG_HASH_LENGTH_512         = 0x00000000  # Enable 512-bit hash
SC_FLAG_HASH_LENGTH_384         = 0x00010000  # Enable 384-bit hash
SC_FLAG_HASH_LENGTH_256         = 0x00020000  # Enable 256-bit hash
SC_FLAG_HASH_LENGTH_224         = 0x00030000  # Enable 224-bit hash
SC_FLAG_HASH_FUNCTION_MASK      = 0x001C0000  # Mask used to isloate hash algorithm
SC_FLAG_HASH_FUNCTION_DEFAULT   = 0x00000000  # Enable scheme default hash
SC_FLAG_HASH_BLAKE2             = 0x00040000  # Enable BLAKE2-B hash
SC_FLAG_HASH_SHA2               = 0x00080000  # Enable SHA-2 hash
SC_FLAG_HASH_SHA3               = 0x000C0000  # Enable SHA-3 hash
SC_FLAG_HASH_WHIRLPOOL          = 0x00100000  # Enable Whirlpool hash
SC_FLAG_REDUCTION_MASK          = 0x00E00000  # Mask used to isolate reduction selection
SC_FLAG_REDUCTION_REFERENCE     = 0x00200000  # Use reference arithmetic for reduction
SC_FLAG_REDUCTION_BARRETT       = 0x00400000  # Use Barrett reduction
SC_FLAG_REDUCTION_FP            = 0x00600000  # Use Floating Point reduction
SC_FLAG_THREADING_MASK          = 0x7C000000  # Mask used to identify the multithreading selection
SC_FLAG_THREADING_KEYGEN        = 0x04000000  # Enable multithreading support for key generation
SC_FLAG_THREADING_ENC_SIGN      = 0x08000000  # Enable multithreading support for encryption, signing, etc.
SC_FLAG_THREADING_DEC_VERIFY    = 0x10000000  # Enable multithreading support for decryption, verification, etc.

SC_FLAG_CSPRNG_AES              = 0x00000001  # Enable AES CTR-DRBG
SC_FLAG_CSPRNG_CHACHA           = 0x00000002  # Enable CHACHA20-CSPRNG
SC_FLAG_CSPRNG_SALSA            = 0x00000004  # Enable SALSA20-CSPRNG
SC_FLAG_CSPRNG_ISAAC            = 0x00000008  # Enable ISAAC CSPRNG
SC_FLAG_CSPRNG_KISS             = 0x00000010  # Enable Keep It Simple Stupid PRNG
SC_FLAG_CSPRNG_SHA3_512_DRBG    = 0x00000100  # Enable SHA3-512 HASH-DRBG
SC_FLAG_CSPRNG_SHA3_256_DRBG    = 0x00000400  # Enable SHA3-256 HASH-DRBG
SC_FLAG_CSPRNG_SHA2_512_DRBG    = 0x00001000  # Enable SHA2-512 HASH-DRBG
SC_FLAG_CSPRNG_SHA2_256_DRBG    = 0x00004000  # Enable SHA2-256 HASH-DRBG
SC_FLAG_CSPRNG_BLAKE2_512_DRBG  = 0x00010000  # Enable BLAKE2-512 HASH-DRBG
SC_FLAG_CSPRNG_BLAKE2_256_DRBG  = 0x00040000  # Enable BLAKE2-256 HASH-DRBG
SC_FLAG_CSPRNG_WHIRLPOOL_DRBG   = 0x00100000  # Enable Whirlpool-512 HASH-DRBG

class CtypesEnum(IntEnum):
    """A ctypes-compatible IntEnum superclass."""
    @classmethod
    def from_param(cls, obj):
        return int(obj)

class sc_schemes(CtypesEnum):
    SC_SCHEME_NONE = 0
    SC_SCHEME_SIG_HELLO_WORLD = 1
    SC_SCHEME_SIG_BLISS = 2
    SC_SCHEME_ENC_RLWE = 3

class sc_entropy_type(CtypesEnum):
    SC_ENTROPY_NONE = 0
    SC_ENTROPY_BAC = 1
    SC_ENTROPY_BAC_RLE = 2
    SC_ENTROPY_HUFFMAN_STATIC = 3
    SC_ENTROPY_STRONGSWAN = 4

class sc_debug_level(CtypesEnum):
    SC_LEVEL_NONE = 0
    SC_LEVEL_ERROR = 1
    SC_LEVEL_WARNING = 2
    SC_LEVEL_INFO = 3
    SC_LEVEL_DEBUG = 4

class SAFEcrypto(object):

    def __init__(self, scheme, param_set, flags):
        lib.safecrypto_create.argtypes = [sc_schemes, c_int, POINTER(c_uint)]
        lib.safecrypto_create.restype = c_void_p
        self.obj = lib.safecrypto_create(scheme, param_set, flags)

    def destroy(self):
        return lib.safecrypto_destroy(self.obj);

    def get_version(self):
        return lib.safecrypto_get_version();

    def get_version_string(self):
        lib.safecrypto_get_version_string.restype = c_char_p
        return lib.safecrypto_get_version_string()

    def set_debug_level(self, level):
        lib.safecrypto_set_debug_level.argtypes = [c_void_p, sc_debug_level]
        return lib.safecrypto_set_debug_level(self.obj, level)

    def get_debug_level(self):
        lib.safecrypto_get_debug_level.argtypes = [c_void_p]
        lib.safecrypto_get_version_string.restype = sc_debug_level
        return lib.safecrypto_get_debug_level(self.obj)

    def err_get_error(self):
        lib.safecrypto_get_version_string.restype = c_uint
        return safecrypto_err_get_error(self.obj)

    def err_peek_error(self):
        lib.safecrypto_get_version_string.restype = c_uint
        return safecrypto_err_peek_error(self.obj)

    def err_get_error_line(self):
        lib.safecrypto_err_get_error_line.argtypes = [c_void_p, POINTER(u_char_p), POINTER(c_int)]
        lib.safecrypto_err_get_error_line.restype = c_uint
        return safecrypto_err_get_error_line(self.obj)

    def err_peek_error_line(self):
        lib.safecrypto_err_peek_error_line.argtypes = [c_void_p, POINTER(u_char_p), POINTER(c_int)]
        lib.safecrypto_err_peek_error_line.restype = c_uint
        return safecrypto_err_peek_error_line(self.obj)

    def err_clear_error(self):
        lib.safecrypto_err_clear_error(self.obj)

    def keygen(self):
        lib.safecrypto_keygen.argtypes = [c_void_p]
        return lib.safecrypto_keygen(self.obj)

    def set_key_coding(self, pub, priv):
        lib.safecrypto_set_key_coding.argtypes = [c_void_p, sc_entropy_type, sc_entropy_type]
        return lib.safecrypto_set_key_coding(self.obj, pub, priv)

    def get_key_coding(self, pub, priv):
        lib.safecrypto_get_key_coding.argtypes = [c_void_p, POINTER(c_int), POINTER(c_int)]
        return lib.safecrypto_get_key_coding(self.obj, pub, priv)

    def public_key_encode(self, key, keylen):
        lib.safecrypto_public_key_encode.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), POINTER(c_uint)]
        return lib.safecrypto_public_key_encode(self.obj, key, keylen)

    def private_key_encode(self, key, keylen):
        lib.safecrypto_private_key_encode.argtypes = [c_void_p, POINTER(POINTER(c_ubyte)), POINTER(c_uint)]
        return lib.safecrypto_private_key_encode(self.obj, key, keylen)

    def public_key_load(self, key, keylen):
        lib.safecrypto_public_key_load.argtypes = [c_void_p, POINTER(c_ubyte), c_uint]
        return lib.safecrypto_public_key_load(self.obj, key, keylen)

    def private_key_load(self, key, keylen):
        lib.safecrypto_private_key_load.argtypes = [c_void_p, POINTER(c_ubyte), c_uint]
        return lib.safecrypto_private_key_load(self.obj, key, keylen)

    def public_encrypt(self, ilen, idata, olen, odata, padding):
        lib.safecrypto_public_encrypt.argtypes = [c_void_p, c_uint, POINTER(c_ubyte), POINTER(c_uint), POINTER(POINTER(c_ubyte)), c_int]
        return lib.safecrypto_public_encrypt(self.obj, flen, idata, olen, odata, padding)

    def private_decrypt(self, ilen, idata, olen, odata, padding):
        lib.safecrypto_public_decrypt.argtypes = [c_void_p, c_uint, POINTER(c_ubyte), POINTER(c_uint), POINTER(POINTER(c_ubyte)), c_int]
        return lib.safecrypto_private_decrypt(self.obj, flen, idata, olen, odata, padding)

    def sign(self, m, mlen, sig, siglen):
        lib.safecrypto_sign.argtypes = [c_void_p, POINTER(c_ubyte), c_uint, POINTER(POINTER(c_ubyte)), POINTER(c_uint)]
        return lib.safecrypto_sign(self.obj, m, mlen, sig, siglen)

    def verify(self, m, mlen, sig, siglen):
        lib.safecrypto_verify.argtypes = [c_void_p, POINTER(c_ubyte), c_uint, POINTER(c_ubyte), c_uint]
        return lib.safecrypto_verify(self.obj, m, mlen, sig, siglen)

    def processing_stats(self):
        lib.safecrypto_processing_stats.restype = c_char_p;
        return lib.safecrypto_processing_stats(self.obj)
