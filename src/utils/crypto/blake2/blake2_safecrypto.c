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

#include "blake2_safecrypto.h"

SINT32 sc_blake2b_make_copy(void *ctx, void *ctx_copy)
{
	blake2b_state *S      = (blake2b_state *) ctx;
	blake2b_state *S_copy = (blake2b_state *) ctx_copy;
	*S_copy = *S;
	return SC_FUNC_SUCCESS;
}

SINT32 sc_blake2b_init(void *c, SINT32 outlen)
{
	blake2b_state *S = (blake2b_state *) c;
	return blake2b_init(S, outlen)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

SINT32 sc_blake2b_update(void *c, const void *data, size_t inlen)
{
	blake2b_state *S = (blake2b_state *) c;
	const UINT8 *d = (const UINT8*) data;
	return blake2b_update(S, d, inlen)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

SINT32 sc_blake2b_final(void *c, void *out)
{
	blake2b_state *S = (blake2b_state *) c;
	UINT8 *md = (UINT8*) out;
	return blake2b_final(S, md, 64)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

SINT32 sc_blake2xb_make_copy(void *ctx, void *ctx_copy)
{
	blake2xb_state *S      = (blake2xb_state *) ctx;
	blake2xb_state *S_copy = (blake2xb_state *) ctx_copy;
	*S_copy = *S;
	return SC_FUNC_SUCCESS;
}

SINT32 sc_blake2xb_init(void *c, SINT32 outlen)
{
	blake2xb_state *S = (blake2xb_state *) c;
	return blake2xb_init(S, outlen)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

SINT32 sc_blake2xb_update(void *c, const void *data, size_t inlen)
{
	blake2xb_state *S = (blake2xb_state *) c;
	const UINT8 *d = (const UINT8*) data;
	return blake2xb_update(S, d, inlen)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}

SINT32 sc_blake2xb_xof(void *c, void *out, size_t len)
{
	blake2xb_state *S = (blake2xb_state *) c;
	return blake2xb_final(S, out, len)? SC_FUNC_FAILURE : SC_FUNC_SUCCESS;
}
