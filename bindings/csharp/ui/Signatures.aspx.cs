/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using System;
using System.Web;
using System.Web.UI;
using System.Data;
using System.Windows.Forms;

namespace webapp
{
	public partial class Signatures : System.Web.UI.Page
	{
		private void Page_Load()
		{
			if (!IsPostBack)
			{
			}
		}

		public void SchemeList_Change (object sender, EventArgs args)
		{
			PubKeyText.Text = string.Empty;
			PrivKeyText.Text = string.Empty;
			UpdatePanel_Keys.Update ();

			SigBtn.CssClass = "btn btn-primary disabled";
			SigFileBtn.CssClass = "btn btn-primary disabled";
			SigBtn.Enabled = false;
			SigFileBtn.Enabled = false;
			InputText.Text = string.Empty;
			SignatureText.Text = string.Empty;
			VerBtn.Text = string.Empty;
			VerBtn.BackColor = System.Drawing.Color.White;
			UpdatePanel_Sigs.Update ();
		}

		protected void Configure()
		{
			string SchemeString = SchemeList.SelectedValue;
			SAFEcrypto.sc_scheme_e Scheme = SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS;
			Int32 Set = 0;
			switch (SchemeString) {
			case "BLISS-B-IV":
				Scheme = SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS;
				Set = 4;
				break;
			case "BLISS-B-III":
				Scheme = SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS;
				Set = 3;
				break;
			case "BLISS-B-II":
				Scheme = SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS;
				Set = 2;
				break;
			case "BLISS-B-I":
				Scheme = SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS;
				Set = 1;
				break;
			case "BLISS-B-0":
				Scheme = SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS;
				Set = 0;
				break;
			}

			UInt32[] Entropy = {0};

			switch (SigEntropyList.SelectedIndex) {
			case 1:
				Entropy[0] |= SAFEcrypto.SC_FLAG_ENTROPY_BAC;
				break;
			case 2:
				Entropy[0] |= SAFEcrypto.SC_FLAG_ENTROPY_BAC_RLE;
				break;
			case 3:
				Entropy[0] |= SAFEcrypto.SC_FLAG_ENTROPY_HUFFMAN_STATIC;
				break;
			case 4:
				Entropy[0] |= SAFEcrypto.SC_FLAG_ENTROPY_STRONGSWAN;
				break;
			default:
				break;
			}

			switch (SigCsprngList.SelectedIndex) {
			case 1:
				Entropy[0] |= SAFEcrypto.SC_FLAG_MORE;
				Entropy[1] |= SAFEcrypto.SC_FLAG_CSPRNG_ISAAC;
				break;
			case 2:
			    Entropy[0] |= SAFEcrypto.SC_FLAG_MORE;
				Entropy[1] |= SAFEcrypto.SC_FLAG_CSPRNG_AES;
				break;
			case 3:
			    Entropy[0] |= SAFEcrypto.SC_FLAG_MORE;
				Entropy[1] |= SAFEcrypto.SC_FLAG_CSPRNG_CHACHA;
				break;
			default:
				break;
			}

			switch (SigHashList.SelectedIndex) {
			case 1:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA3;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_512;
				break;
			case 2:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA3;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_384;
				break;
			case 3:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA3;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_256;
				break;
			case 4:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA3;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_224;
				break;
			case 5:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_512;
				break;
			case 6:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_384;
				break;
			case 7:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_256;
				break;
			case 8:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_SHA2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_224;
				break;
			case 9:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_BLAKE2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_512;
				break;
			case 10:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_BLAKE2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_384;
				break;
			case 11:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_BLAKE2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_256;
				break;
			case 12:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_BLAKE2;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_224;
				break;
			case 13:
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_WHIRLPOOL;
				Entropy[0] |= SAFEcrypto.SC_FLAG_HASH_LENGTH_512;
				break;
			}

			SAFEcrypto SC = (SAFEcrypto) Session ["SC"];
			SC.Dispose ();
			GC.Collect ();
			SC = null;
			SC = new SAFEcrypto (Scheme, Set, Entropy);
			SC.SetPublicKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE, PubKeyText.Text.Trim ());
			SC.SetPrivateKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE, PrivKeyText.Text.Trim ());
			Session ["SC"] = SC;
		}

		protected void KeyGenBtn_Click(object sender, EventArgs args)
		{
			Configure ();

			SAFEcrypto SC = (SAFEcrypto) Session ["SC"];

			try {
				SC.KeyGen ();
				string PublicKey = SC.GetPublicKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);
				PubKeyText.Text = string.Empty;
				PubKeyText.Text = PublicKey;

				string PrivateKey = SC.GetPrivateKey (SAFEcrypto.sc_entropy_type_e.SC_ENTROPY_NONE);
				PrivKeyText.Text = PrivateKey;
				UpdatePanel_Keys.Update ();

				SigBtn.CssClass = "btn btn-primary";
				SigFileBtn.CssClass = "btn btn-primary disabled";
				SigBtn.Enabled = true;
				SigFileBtn.Enabled = false;
				InputText.Text = string.Empty;
				SignatureText.Text = string.Empty;
				VerBtn.Text = string.Empty;
				VerBtn.BackColor = System.Drawing.Color.White;
				UpdatePanel_Sigs.Update ();

				Session ["SC"] = SC;
			}
			catch (ArgumentException error) {
				SignatureText.Text = error.Message + ", " + error.Source;
				return;
			}
		}

		protected void SignatureUpdate(string Message)
		{
			SAFEcrypto SC = (SAFEcrypto) Session ["SC"];

			byte[] Msg = SAFEcrypto.StringToByteArray (Message);
			try {
				byte[] Signature = SC.GetSignature (Msg);
				Boolean Verified = SC.VerifySignature (Msg, Signature);
				InputText.Text = Message;
				SignatureText.Text = SAFEcrypto.ByteArrayToString(Signature);
				if (Verified) {
					VerBtn.Text = "<span class=\"glyphicon glyphicon-ok\"></span>";
					VerBtn.BackColor = System.Drawing.Color.Green;
					VerBtn.ForeColor = System.Drawing.Color.White;
				} else {
					VerBtn.Text = "<span class=\"glyphicon glyphicon-remove\"></span>";
					VerBtn.BackColor = System.Drawing.Color.Red;
					VerBtn.ForeColor = System.Drawing.Color.White;
				}
				//RatioTest.Text = SC.GetAveEncryptionCompression().ToString();
				UpdatePanel_Sigs.Update ();

				Session ["SC"] = SC;
			}
			catch (ArgumentException error) {
				SignatureText.Text = error.Message;
				return;
			}
		}

		protected void SigBtn_Click(object sender, EventArgs args)
		{
			Random rnd = new Random();
			byte[] Message = new byte[64];
			rnd.NextBytes(Message);
			string MessageString = SAFEcrypto.ByteArrayToString (Message);
			SignatureUpdate (MessageString);
		}

		protected void CfgApplyBtn_Click(object sender, EventArgs args)
		{
			Configure ();
		}
	}
}

