/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

using System;
using System.Text;
using System.Numerics;
using System.Linq;
using System.Runtime.InteropServices;

public class SAFEcrypto : IDisposable
{
	bool disposed = false;

    /// A flag bit used to indicate that a further 32-bit word of
    /// configuration flags will follow
    public const UInt32 SC_FLAG_MORE                    = 0x80000000;

    /// Disable all flags
    public const UInt32 SC_FLAG_NONE                    = 0x00000000;

    // Word 0
    public const UInt32 SC_FLAG_ENTROPY_BAC             = 0x00000001;  ///< BAC compression
    public const UInt32 SC_FLAG_ENTROPY_BAC_RLE         = 0x00000002;  ///< BAC with RLE compression
    public const UInt32 SC_FLAG_ENTROPY_STRONGSWAN      = 0x00000004;  ///< strongSwan compatible Huffman compression
    public const UInt32 SC_FLAG_ENTROPY_HUFFMAN_STATIC  = 0x00000008;  ///< Huffman compression
    public const UInt32 SC_FLAG_SAMPLE_BLINDING         = 0x00000100;  ///< Enable blinding countermeasures
    public const UInt32 SC_FLAG_SAMPLE_CDF              = 0x00000200;  ///< CDF Gaussian sampler
    public const UInt32 SC_FLAG_SAMPLE_KNUTH_YAO        = 0x00000400;  ///< Knuth Yao Gaussian sampler
    public const UInt32 SC_FLAG_SAMPLE_ZIGGURAT         = 0x00000800;  ///< Ziggurat gaussian sampler
    public const UInt32 SC_FLAG_SAMPLE_BAC              = 0x00001000;  ///< BAC Gaussian sampler
    public const UInt32 SC_FLAG_SAMPLE_HUFFMAN          = 0x00002000;  ///< Huffman decoder Gaussian sampler
    public const UInt32 SC_FLAG_SAMPLE_BERNOULLI        = 0x00004000;  ///< Bernoulli Gaussian sampler
    public const UInt32 SC_FLAG_HASH_LENGTH_MASK        = 0x00030000;  ///< Mask used to isolate hash length selection
    public const UInt32 SC_FLAG_HASH_LENGTH_512         = 0x00000000;  ///< Enable 512-bit hash
    public const UInt32 SC_FLAG_HASH_LENGTH_384         = 0x00010000;  ///< Enable 384-bit hash
    public const UInt32 SC_FLAG_HASH_LENGTH_256         = 0x00020000;  ///< Enable 256-bit hash
    public const UInt32 SC_FLAG_HASH_LENGTH_224         = 0x00030000;  ///< Enable 224-bit hash
    public const UInt32 SC_FLAG_HASH_FUNCTION_MASK      = 0x001C0000;  ///< Mask used to isloate hash algorithm
    public const UInt32 SC_FLAG_HASH_FUNCTION_DEFAULT   = 0x00000000;  ///< Enable scheme default hash
    public const UInt32 SC_FLAG_HASH_BLAKE2             = 0x00040000;  ///< Enable BLAKE2-B hash
    public const UInt32 SC_FLAG_HASH_SHA2               = 0x00080000;  ///< Enable SHA-2 hash
    public const UInt32 SC_FLAG_HASH_SHA3               = 0x000C0000;  ///< Enable SHA-3 hash
    public const UInt32 SC_FLAG_HASH_WHIRLPOOL          = 0x00100000;  ///< Enable Whirlpool hash
    public const UInt32 SC_FLAG_REDUCTION_MASK          = 0x00E00000;  ///< Mask used to isolate reduction selection
    public const UInt32 SC_FLAG_REDUCTION_REFERENCE     = 0x00200000;  ///< Use reference arithmetic for reduction
    public const UInt32 SC_FLAG_REDUCTION_BARRETT       = 0x00400000;  ///< Use Barrett reduction
    public const UInt32 SC_FLAG_REDUCTION_FP            = 0x00600000;  ///< Use Floating Point reduction
    public const UInt32 SC_FLAG_THREADING_MASK          = 0x7C000000;  ///< Mask used to identify the multithreading selection
    public const UInt32 SC_FLAG_THREADING_KEYGEN        = 0x04000000;  ///< Enable multithreading support for key generation
    public const UInt32 SC_FLAG_THREADING_ENC_SIGN      = 0x08000000;  ///< Enable multithreading support for encryption, signing, etc.
    public const UInt32 SC_FLAG_THREADING_DEC_VERIFY    = 0x10000000;  ///< Enable multithreading support for decryption, verification, etc.

    // Word 1
    public const UInt32 SC_FLAG_CSPRNG_AES              = 0x00000001;  ///< Enable AES CTR-DRBG
    public const UInt32 SC_FLAG_CSPRNG_CHACHA           = 0x00000002;  ///< Enable CHACHA20-CSPRNG
    public const UInt32 SC_FLAG_CSPRNG_SALSA            = 0x00000004;  ///< Enable SALSA20-CSPRNG
    public const UInt32 SC_FLAG_CSPRNG_ISAAC            = 0x00000008;  ///< Enable ISAAC CSPRNG
    public const UInt32 SC_FLAG_CSPRNG_KISS             = 0x00000010;  ///< Enable Keep It Simple Stupid PRNG
    public const UInt32 SC_FLAG_CSPRNG_SHA3_512_DRBG    = 0x00000100;  ///< Enable SHA3-512 HASH-DRBG
    public const UInt32 SC_FLAG_CSPRNG_SHA3_256_DRBG    = 0x00000400;  ///< Enable SHA3-256 HASH-DRBG
    public const UInt32 SC_FLAG_CSPRNG_SHA2_512_DRBG    = 0x00001000;  ///< Enable SHA2-512 HASH-DRBG
    public const UInt32 SC_FLAG_CSPRNG_SHA2_256_DRBG    = 0x00004000;  ///< Enable SHA2-256 HASH-DRBG
    public const UInt32 SC_FLAG_CSPRNG_BLAKE2_512_DRBG  = 0x00010000;  ///< Enable BLAKE2-512 HASH-DRBG
    public const UInt32 SC_FLAG_CSPRNG_BLAKE2_256_DRBG  = 0x00040000;  ///< Enable BLAKE2-256 HASH-DRBG
    public const UInt32 SC_FLAG_CSPRNG_WHIRLPOOL_DRBG   = 0x00100000;  ///< Enable Whirlpool-512 HASH-DRBG


    public enum sc_scheme_e {
        SC_SCHEME_NONE,
        SC_SCHEME_SIG_HELLO_WORLD,
        SC_SCHEME_SIG_BLISS,
        SC_SCHEME_ENC_RING_TESLA,
        SC_SCHEME_ENC_RLWE,
        SC_SCHEME_KEM_ENS,
        SC_SCHEME_SIG_ENS,
        SC_SCHEME_SIG_ENS_WITH_RECOVERY,
        SC_SCHEME_IBE_DLP,
        SC_SCHEME_SIG_DLP,
        SC_SCHEME_SIG_DLP_WITH_RECOVERY,
        SC_SCHEME_SIG_DILITHIUM,
        SC_SCHEME_SIG_DILITHIUM_G,
        SC_SCHEME_DH_ECDH
    };

    public enum sc_entropy_type_e {
        SC_ENTROPY_NONE,
        SC_ENTROPY_BAC,
        SC_ENTROPY_BAC_RLE,
        SC_ENTROPY_HUFFMAN_STATIC,
        SC_ENTROPY_STRONGSWAN,
    };

    public enum sc_debug_level_e {
        SC_LEVEL_NONE = 0,
        SC_LEVEL_ERROR,
        SC_LEVEL_WARNING,
        SC_LEVEL_INFO,
        SC_LEVEL_DEBUG
    };

	public enum sc_stat_component_e {
		SC_STAT_PUB_KEY = 0,
		SC_STAT_PRIV_KEY,
		SC_STAT_SIGNATURE,
		SC_STAT_EXTRACT,
		SC_STAT_ENCRYPT,
		SC_STAT_ENCAPSULATE,
	};

	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
	public struct sc_stat_coding
	{
		public UInt32 bits;
		public UInt32 bits_coded;

		[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
		public string  name;
	};

	[StructLayout(LayoutKind.Sequential)]
	public struct sc_stat_coding_5
	{
		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 5)]
		public sc_stat_coding[] stat;
	};

	[StructLayout(LayoutKind.Sequential)]
    public struct sc_statistics
    {
        public sc_scheme_e scheme;

		public UInt32 param_set;
		public UInt32 keygen_num;
		public UInt32 keygen_num_trials;
        public UInt32 pub_keys_encoded;
        public UInt32 pub_keys_loaded;
        public UInt32 priv_keys_encoded;
        public UInt32 priv_keys_loaded;
        public UInt32 sig_num;
        public UInt32 sig_num_trials;
		public UInt32 sig_num_verified;
		public UInt32 sig_num_unverified;
		public UInt32 encrypt_num;
		public UInt32 decrypt_num;
		public UInt32 encapsulate_num;
		public UInt32 decapsulate_num;
		public UInt32 extract_num;
		public UInt32 extract_keys_loaded;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
		public UInt32[] num_components;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
		public sc_stat_coding_5[] components;
    };



    [DllImport("libsafecrypto.so")]
    public static extern IntPtr safecrypto_create (sc_scheme_e scheme, Int32 set, UInt32[] flags);

    [DllImport("libsafecrypto.so")]
    public static extern Int32 safecrypto_destroy (IntPtr sc);



    [DllImport("libsafecrypto.so")]
    public static extern UInt32 safecrypto_get_version();

    [DllImport("libsafecrypto.so")]
    public static extern IntPtr safecrypto_get_version_string();



    [DllImport("libsafecrypto.so")]
    public static extern Int32 safecrypto_set_debug_level(IntPtr sc, sc_debug_level_e level);

    [DllImport("libsafecrypto.so")]
    public static extern sc_debug_level_e safecrypto_get_debug_level(IntPtr sc);



    [DllImport("libsafecrypto.so")]
    public static extern UInt32 safecrypto_err_get_error(IntPtr sc);

    [DllImport("libsafecrypto.so")]
    public static extern UInt32 safecrypto_err_peek_error(IntPtr sc);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern UInt32 safecrypto_err_get_error_line(IntPtr sc,
        ref string file, Int32 *line);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern UInt32 safecrypto_err_peek_error_line(IntPtr sc,
        ref string file, Int32 *line);

    [DllImport("libsafecrypto.so")]
    public static extern void safecrypto_err_clear_error(IntPtr sc);



    [DllImport("libsafecrypto.so")]
    public static extern Int32 safecrypto_keygen (IntPtr sc);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_public_key_load (IntPtr sc,
        byte *key, UInt32 keylen);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_private_key_load (IntPtr sc,
        byte *key, UInt32 keylen);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_public_key_encode (IntPtr sc,
        byte **key, UInt32 *keylen);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_private_key_encode (IntPtr sc,
        byte **key, UInt32 *keylen);

    [DllImport("libsafecrypto.so")]
    public static extern Int32 safecrypto_set_key_coding (IntPtr sc,
        sc_entropy_type_e pub, sc_entropy_type_e priv);


    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_public_encrypt(IntPtr sc,
        UInt32 flen, byte *from, UInt32 *tlen, byte **to);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_private_decrypt(IntPtr sc,
        UInt32 flen, byte *from, UInt32 *tlen, byte **to);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_sign(IntPtr sc, byte *m, UInt32 mlen,
        byte **sigret, UInt32 *siglen);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_verify(IntPtr sc, byte *m, UInt32 mlen,
        byte *sigbuf, UInt32 siglen);

    [DllImport("libsafecrypto.so")]
	public unsafe static extern IntPtr safecrypto_get_stats (IntPtr sc);

    [DllImport("libsafecrypto.so")]
    public unsafe static extern Int32 safecrypto_signature_transcode(IntPtr sc,
        sc_entropy_type_e from, sc_entropy_type_e to,
        byte *sigbuf, UInt32 siglen, byte **sigtrans, UInt32 *sigtranslen, UInt32 *length);



    private IntPtr SC;

    public SAFEcrypto (sc_scheme_e Scheme, Int32 Set, UInt32[] Flags)
    {
        SC = safecrypto_create (Scheme, Set, Flags);
        if (IntPtr.Zero == SC)
            throw new ArgumentNullException("SC");
    }

	public void Dispose()
	{
		Console.WriteLine ("Dispose()");
		Dispose (true);
		GC.SuppressFinalize(this);
	}

	protected virtual void Dispose(bool disposing)
	{
		if (disposed)
			return; 

		Console.WriteLine ("Disposing ...");

		if (disposing) {
			// Free any other managed objects here.
			//
			safecrypto_destroy (SC);
		}

		// Free any unmanaged objects here.
		//
		//safecrypto_destroy (SC);
		disposed = true;
	}

	~SAFEcrypto()
	{
		Dispose(false);
	}

    public static string ByteArrayToString(byte[] ba)
    {
        if (1 == (ba.Length & 1)) {
        byte[] newArray = new byte[ba.Length + 1];
            ba.CopyTo(newArray, 0);
            newArray[ba.Length] = 0;
            ba = newArray;
        }
        String s = String.Empty;
        for(int index = 0; index < ba.Length; index++)
            s += String.Format("{0,2:X2}", ba[index]);
        return s;
    }

    public static byte[] StringToByteArray(String hex)
    {
        return Enumerable.Range(0, hex.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
            .ToArray();
    }

    public UInt32 GetVersion()
    {
        return safecrypto_get_version ();
    }

    public string GetVersionString()
    {
        return Marshal.PtrToStringAnsi(safecrypto_get_version_string ());
    }

    public Int32 SetDebugLevel(sc_debug_level_e level)
    {
        return safecrypto_set_debug_level (SC, level);
    }

    public sc_debug_level_e GetDebugLevel()
    {
        return safecrypto_get_debug_level(SC);
    }

    public void KeyGen()
    {
        safecrypto_keygen (SC);
    }

    unsafe public string GetPublicKey(sc_entropy_type_e type)
    {
        byte* key;
        UInt32 keylen = 0;

        safecrypto_set_key_coding (SC, type, type);

        safecrypto_public_key_encode (SC, &key, &keylen);
        byte[] pubkey = new byte[keylen];
        Marshal.Copy((IntPtr)key, pubkey, 0, (int)keylen);

        return ByteArrayToString(pubkey);
    }

    unsafe public string GetPrivateKey(sc_entropy_type_e type)
    {
        byte* key;
        UInt32 keylen = 0;

        safecrypto_set_key_coding (SC, type, type);

        int RetVal = safecrypto_private_key_encode (SC, &key, &keylen);
		if (RetVal == 0) {
			UInt32 Code = safecrypto_err_get_error (SC);
			Console.WriteLine ("Code: {0}", Code);
			return Code.ToString();
		} else {
			byte[] privkey = new byte[keylen];
			Marshal.Copy ((IntPtr)key, privkey, 0, (int)keylen);
			return ByteArrayToString(privkey);
		}
    }

    unsafe public Int32 SetPublicKey(sc_entropy_type_e type, string pubkey)
    {
        byte[] arr = StringToByteArray(pubkey);
        fixed(byte* key = arr) {
            UInt32 keylen = (UInt32)arr.Length;

            safecrypto_set_key_coding (SC, type, type);

            return safecrypto_public_key_load (SC, key, keylen);
        }
    }

    unsafe public Int32 SetPrivateKey(sc_entropy_type_e type,  string privkey)
    {
        byte[] arr = StringToByteArray(privkey);
        fixed(byte* key = arr) {
            UInt32 keylen = (UInt32)arr.Length;

            safecrypto_set_key_coding (SC, type, type);

            return safecrypto_private_key_load (SC, key, keylen);
        }
    }

    unsafe public byte[] PublicEncrypt(byte[] Input)
    {
        byte* Output;
        UInt32 OutputLen = 0;

        fixed(byte* InputPtr = Input) {
            Int32 RetCode = safecrypto_public_encrypt(SC, (UInt32)Input.Length, InputPtr,
                &OutputLen, &Output);
            if (0 == RetCode)
                return null;
            byte[] Ciphertext = new byte[OutputLen];
            Marshal.Copy ((IntPtr)Output, Ciphertext, 0, (int)OutputLen);
            return Ciphertext;
        }
    }

    unsafe public byte[] PrivateDecrypt(byte[] Input)
    {
        byte* Output;
        UInt32 OutputLen = 0;

        fixed(byte* InputPtr = Input) {
            Int32 RetCode = safecrypto_private_decrypt(SC, (UInt32)Input.Length, InputPtr,
                &OutputLen, &Output);
            if (0 == RetCode)
                return null;
            byte[] Plaintext = new byte[OutputLen];
            Marshal.Copy ((IntPtr)Output, Plaintext, 0, (int)OutputLen);
            return Plaintext;
        }
    }

    unsafe public byte[] GetSignature(byte[] Message)
    {
        byte* Sig;
        UInt32 SigLen = 0;

        fixed(byte* MsgPtr = Message) {
            Int32 RetCode = safecrypto_sign (SC, MsgPtr, (UInt32)Message.Length, &Sig, &SigLen);
            if (0 == RetCode) {
                throw new ArgumentException ("Return code failure");
            }
            byte[] Signature = new byte[SigLen];
            Marshal.Copy ((IntPtr)Sig, Signature, 0, (int)SigLen);
            return Signature;
        }
    }

    unsafe public Boolean VerifySignature(byte[] Message, byte[] Signature)
    {
        fixed(byte* MsgPtr = Message) {
            fixed(byte* SigPtr = Signature) {
 	                Int32 Validated = safecrypto_verify (SC, MsgPtr, (UInt32)Message.Length,
                        SigPtr, (UInt32)Signature.Length);
                return Validated == 1;
            }
        }
    }

    unsafe public Int32 GetAveEncryptionCompression()
    {
		IntPtr StatsPtr = safecrypto_get_stats(SC);
		sc_statistics Stats = (sc_statistics) Marshal.PtrToStructure(StatsPtr, typeof(sc_statistics));
		Console.WriteLine ("Scheme = {0}", Stats.scheme);
		Console.WriteLine ("Set = {0}", Stats.param_set);
		int NumComponents;
		NumComponents = (int)Stats.num_components [(int)sc_stat_component_e.SC_STAT_PUB_KEY];
		Console.WriteLine ("Pub Key Num components = {0}", NumComponents);
		NumComponents = (int)Stats.num_components [(int)sc_stat_component_e.SC_STAT_PRIV_KEY];
		Console.WriteLine ("Priv Key Num components = {0}", NumComponents);
		NumComponents = (int)Stats.num_components [(int)sc_stat_component_e.SC_STAT_SIGNATURE];
		Console.WriteLine ("Signature Num components = {0}", NumComponents);
		NumComponents = (int)Stats.num_components [(int)sc_stat_component_e.SC_STAT_EXTRACT];
		Console.WriteLine ("Extract Num components = {0}", NumComponents);
		NumComponents = (int)Stats.num_components [(int)sc_stat_component_e.SC_STAT_ENCAPSULATE];
		Console.WriteLine ("Encapsulate Num components = {0}", NumComponents);
		NumComponents = (int)Stats.num_components [(int)sc_stat_component_e.SC_STAT_ENCRYPT];
		Console.WriteLine ("Encrypt Num components = {0}", NumComponents);
		sc_stat_coding Coding = Stats.components [(int)sc_stat_component_e.SC_STAT_ENCRYPT].stat [NumComponents];
		return (int)Coding.bits_coded / (int)Coding.bits;
    }

    unsafe public byte[] SignatureTranscode(sc_entropy_type_e From, sc_entropy_type_e To,
        byte[] Signature, out UInt32 Length)
    {
        byte* Sig;
        UInt32 SigLen;
        UInt32 VectorLen;

        fixed(byte* SigPtr = Signature) {

            Int32 RetCode = safecrypto_signature_transcode (SC,
                                         From, To, SigPtr, (UInt32)Signature.Length, &Sig, &SigLen, &VectorLen);
            if (0 == RetCode) {
                throw new ArgumentException ("Return code failure");
            }
            byte[] SigBuf = new byte[SigLen];
            Marshal.Copy ((IntPtr)Sig, SigBuf, 0, (int)SigLen);
            Length = VectorLen;
            return SigBuf;
        }
    }
}

