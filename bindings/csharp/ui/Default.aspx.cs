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

namespace webapp
{
	
	public partial class Default : System.Web.UI.Page
	{
		public void encBtnClicked (object sender, EventArgs args)
		{
			Response.Redirect ("Encryption.aspx");
		}

		public void sigBtnClicked (object sender, EventArgs args)
		{
			Response.Redirect ("Signatures.aspx");
		}

		public void ibeBtnClicked (object sender, EventArgs args)
		{
			Response.Redirect ("IBE.aspx");
		}
	}
}

