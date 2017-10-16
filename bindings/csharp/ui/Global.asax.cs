/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

using System;
using System.Collections;
using System.ComponentModel;
using System.Web;
using System.Web.SessionState;
using System.Runtime.InteropServices;

namespace webapp
{
	public class Global : System.Web.HttpApplication
	{
		protected void Application_Start (Object sender, EventArgs e)
		{

		}

		unsafe protected void Session_Start (Object sender, EventArgs e)
		{
			UInt32[] Flags = {SAFEcrypto.SC_FLAG_NONE};
			SAFEcrypto SC = new SAFEcrypto (SAFEcrypto.sc_scheme_e.SC_SCHEME_SIG_BLISS, 4, Flags);
			Session ["SC"] = SC;
		}

		protected void Application_BeginRequest (Object sender, EventArgs e)
		{

		}

		protected void Application_EndRequest (Object sender, EventArgs e)
		{

		}

		protected void Application_AuthenticateRequest (Object sender, EventArgs e)
		{

		}

		protected void Application_Error (Object sender, EventArgs e)
		{

		}

		protected void Session_End (Object sender, EventArgs e)
		{
			SAFEcrypto SC = (SAFEcrypto) Session ["SC"];
			SC = null;
		}

		protected void Application_End (Object sender, EventArgs e)
		{

		}
	}
}
