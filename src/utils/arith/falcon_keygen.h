/*
 * Public API for Falcon.
 *
 * NOTE: Modified for use within SAFEcrypto for the purposes of key generation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2017  Falcon Project
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@nccgroup.trust>
 */

#ifndef FALCON_H__
#define FALCON_H__

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SAFEcrypto context
 */
typedef struct _safecrypto safecrypto_t;

/*
 * SAFEcrypto NTT context
 */
typedef struct ntt_params_t ntt_params_t;

/*
 * Key generation context.
 */
typedef struct falcon_keygen_ falcon_keygen;

/*
 * Create a new falcon key generation context.
 *
 * In the binary case (ternary = 0), the 'logn' parameter is the base-2
 * logarithm of the degree; it must be between 1 and 10 (normal Falcon
 * parameters use logn = 9 or 10; lower values are for reduced test-only
 * versions).
 *
 * In the ternary case (ternary = 1), the 'logn' parameter is the base-2
 * logarithm of 2/3rd of the degree (e.g. logn is 9 for degree 768). In
 * that case, 'logn' must lie between 2 and 9 (normal value is 9, lower
 * values are for reduced test-only versions).
 *
 * Returned value is the new context, or NULL on error. Errors include
 * out-of-range parameters, and memory allocation errors.
 */
falcon_keygen *falcon_keygen_new(safecrypto_t *sc, ntt_params_t *ntt_params,
	const int16_t *ntt_w, const int16_t *ntt_r, unsigned logn);

/*
 * Release a previously allocated key generation context, and all
 * corresponding resources. If 'fk' is NULL then this function does
 * nothing.
 */
void falcon_keygen_free(falcon_keygen *fk);

/*
 * Get the maximum encoded size (in bytes) of a private key that can be
 * generated with the provided context. When using no compression
 * (FALCON_COMP_NONE), this is the exact size; with compression,
 * private key will be shorter.
 */
size_t falcon_keygen_max_privkey_size(falcon_keygen *fk);

/*
 * Get the maximum encoded size (in bytes) of a public key that can be
 * generated with the provided context. Since public keys are uncompressed,
 * the returned size is always exact.
 */
size_t falcon_keygen_max_pubkey_size(falcon_keygen *fk);


int solve_NTRU(falcon_keygen *fk, int32_t *F, int32_t *G,
	const int32_t *f, const int32_t *g, int32_t optimise_depth);



inline size_t
skoff_b00(unsigned logn, unsigned ter)
{
	(void)logn;
	(void)ter;
	return 0;
}

inline size_t
skoff_b01(unsigned logn, unsigned ter)
{
	return (1 + ((ter) << 1)) << ((logn) - (ter));
}

inline size_t
skoff_b10(unsigned logn, unsigned ter)
{
	return 2 * (1 + ((ter) << 1)) << ((logn) - (ter));
}

inline size_t
skoff_b11(unsigned logn, unsigned ter)
{
	return 3 * (1 + ((ter) << 1)) << ((logn) - (ter));
}

inline size_t
skoff_tree(unsigned logn, unsigned ter)
{
	return 4 * (1 + ((ter) << 1)) << ((logn) - (ter));
}

void smallints_to_double(DOUBLE *r, const SINT32 *t, unsigned logn, unsigned ter);

void load_skey(DOUBLE *restrict sk, unsigned q,
	const SINT32 *f_src, const SINT32 *g_src,
	const SINT32 *F_src, const SINT32 *G_src,
	unsigned logn, unsigned ter, DOUBLE *restrict tmp);

#ifdef __cplusplus
}
#endif

#endif
