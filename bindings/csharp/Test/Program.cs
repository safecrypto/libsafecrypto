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

namespace Test
{
	class MainClass
	{
		public static void Main (string[] args)
		{
			Console.WriteLine ("SAFEcrypto C# Binding Example");

			Console.WriteLine ("Example 1: BLISS-B");

			string MessageString = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F";

			SAFEcrypto SC = null;

			UInt32[] Flags = {SAFEcrypto.SC_FLAG_NONE};
			using (SC = new SAFEcrypto (SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS, 4, Flags)) {
				Console.WriteLine ("Version {0}", SC.GetVersion ());
				Console.WriteLine ("Debug Level {0}", SC.GetDebugLevel ());

				SC.KeyGen ();
				string PublicKey = SC.GetPublicKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);
				string PrivateKey = SC.GetPrivateKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);

				Console.WriteLine ("\nPublic Key:");
				Console.WriteLine (PublicKey);
				Console.WriteLine ("\nPrivate Key:");
				Console.WriteLine (PrivateKey);

				byte[] Message = SAFEcrypto.StringToByteArray (MessageString);
				byte[] Signature = SC.GetSignature (Message);

				Console.WriteLine ("\nMessage:");
				Console.WriteLine (MessageString);
				Console.WriteLine ("\nSignature:");
				Console.WriteLine (SAFEcrypto.ByteArrayToString (Signature));

				Boolean Verified = SC.VerifySignature (Message, Signature);
				if (Verified)
					Console.WriteLine ("\nVerification: SUCCESS");
				else
					Console.WriteLine ("\nVerification: FAILURE");
		

				Console.WriteLine ("\n\nExample 2: BLISS-B with a BLAKE2B random oracle and Huffman compression");
			}

			UInt32[] Flags2 = {SAFEcrypto.SC_FLAG_HASH_LENGTH_512 | SAFEcrypto.SC_FLAG_HASH_BLAKE2 | SAFEcrypto.SC_FLAG_ENTROPY_HUFFMAN_STATIC};
			using (SC = new SAFEcrypto (SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS, 4, Flags2)) {

				SC.KeyGen ();
				string PublicKey = SC.GetPublicKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);
				string PrivateKey = SC.GetPrivateKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_HUFFMAN_STATIC);

				Console.WriteLine ("\nPublic Key:");
				Console.WriteLine (PublicKey);
				Console.WriteLine ("\nPrivate Key:");
				Console.WriteLine (PrivateKey);

				byte[] Message = SAFEcrypto.StringToByteArray (MessageString);
				byte[] Signature = SC.GetSignature (Message);

				Console.WriteLine ("\nMessage:");
				Console.WriteLine (MessageString);
				Console.WriteLine ("\nSignature:");
				Console.WriteLine (SAFEcrypto.ByteArrayToString (Signature));

				Boolean Verified = SC.VerifySignature (Message, Signature);
				if (Verified)
					Console.WriteLine ("\nVerification: SUCCESS");
				else
					Console.WriteLine ("\nVerification: FAILURE");

				Console.WriteLine ("\n\nExample 3: RLWE Encryption");
			}

			UInt32[] Flags3 = {SAFEcrypto.SC_FLAG_NONE};
			using (SC = new SAFEcrypto (SAFEcrypto.sc_scheme_e.SC_SCHEME_ENC_RLWE, 1, Flags3)) {
				
				SC.KeyGen ();
				string PublicKey = SC.GetPublicKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);
				string PrivateKey = SC.GetPrivateKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);

				Console.WriteLine ("\nPublic Key:");
				Console.WriteLine (PublicKey);
				Console.WriteLine ("\nPrivate Key:");
				Console.WriteLine (PrivateKey);

				byte[] Message = SAFEcrypto.StringToByteArray (MessageString);
				byte[] Ciphertext = SC.PublicEncrypt (Message);

				Console.WriteLine ("\nMessage:");
				Console.WriteLine (MessageString);
				Console.WriteLine ("\nCiphertext:");
				Console.WriteLine (SAFEcrypto.ByteArrayToString (Ciphertext));

				byte[] Plaintext = SC.PrivateDecrypt (Ciphertext);
				Console.WriteLine ("\nPlaintext:");
				Console.WriteLine (SAFEcrypto.ByteArrayToString (Plaintext));

				if (MessageString != SAFEcrypto.ByteArrayToString (Plaintext)) {
					Console.WriteLine ("\nERROR! Mismatch detected");
					return;
				} else {
					Console.WriteLine ("\nSUCCESS!");
				}

				/*int Compression = SC.GetAveEncryptionCompression ();
				Console.WriteLine ("Compression = {0}", Compression);*/
			}

		}
	}
}
