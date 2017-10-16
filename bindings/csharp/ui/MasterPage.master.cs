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
	public partial class MasterPage : System.Web.UI.MasterPage
	{
		protected void Page_Load(object sender, EventArgs e)
		{
			SAFEcrypto SC = (SAFEcrypto) Session ["SC"];
			string Version = SC.GetVersionString ();
			LibVersionFooter.Text = "libsafecrypto " + Version;
			FooterUpdatePanel.Update ();
		}	
	}
}

