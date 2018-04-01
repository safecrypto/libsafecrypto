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

#include "sha2_safecrypto.h"


SINT32 sc_sha2_make_copy(void *c, void *c_copy)
{
	sha2_ctx *S      = (sha2_ctx *) c;
	sha2_ctx *S_copy = (sha2_ctx *) c_copy;
	*S_copy = *S;
	return SC_FUNC_SUCCESS;
}

SINT32 sc_sha2_init(void *c, SINT32 outlen)
{
	sha2_ctx *S = (sha2_ctx *) c;
	SINT32 retcode = sha2_begin(outlen, S);
	return (EXIT_SUCCESS == retcode)? SC_FUNC_SUCCESS : SC_FUNC_FAILURE;
}

SINT32 sc_sha2_update(void *c, const void *data, size_t inlen)
{
	sha2_ctx *S = (sha2_ctx *) c;
	const unsigned char *d = (const unsigned char*) data;
	sha2_hash(d, inlen, S);
	return SC_FUNC_SUCCESS;
}

SINT32 sc_sha2_final(void *c, void *out)
{
	sha2_ctx *S = (sha2_ctx *) c;
	unsigned char *md = (unsigned char*) out;
	sha2_end(md, S);
	return SC_FUNC_SUCCESS;
}

