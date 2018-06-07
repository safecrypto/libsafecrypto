/*
 * Falcon signature generation.
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

#include "safecrypto_types.h"


void LDL_fft(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g01,
	const DOUBLE *restrict g11, unsigned logn, DOUBLE *restrict tmp);

/*
 * Special case of LDL when G is quasicyclic, i.e. g11 == g00.
 */
inline void
LDLqc_fft(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g01, unsigned logn,
	DOUBLE *restrict tmp)
{
	LDL_fft(d11, l10, g00, g01, g00, logn, tmp);
}

/*
 * Get the size of the LDL tree for an input with polynomials of size
 * 2^logn. The size is expressed in the number of elements.
 */
inline unsigned ffLDL_treesize(unsigned logn)
{
	/*
	 * For logn = 0 (polynomials are constant), the "tree" is a
	 * single element. Otherwise, the tree node has size 2^logn, and
	 * has two child trees for size logn-1 each. Thus, treesize s()
	 * must fulfill these two relations:
	 *
	 *   s(0) = 1
	 *   s(logn) = (2^logn) + 2*s(logn-1)
	 */
	return (logn + 1) << logn;
}

/*
 * Inner function for ffLDL_fft(). It expects the matrix to be both
 * auto-adjoint and quasicyclic; also, it uses the source operands
 * as modifiable temporaries.
 *
 * tmp[] must have room for at least two polynomials.
 */
void
ffLDL_fft_inner(DOUBLE *restrict tree,
	DOUBLE *restrict g0, DOUBLE *restrict g1, unsigned logn, DOUBLE *restrict tmp);

/*
 * Compute the ffLDL tree of an auto-adjoint matrix G. The matrix
 * is provided as three polynomials (FFT representation).
 *
 * The "tree" array is filled with the computed tree, of size
 * (logn+1)*(2^logn) elements (see ffLDL_treesize()).
 *
 * Input arrays MUST NOT overlap, except possibly the three unmodified
 * arrays g00, g01 and g11. tmp[] should have room for at least four
 * polynomials of 2^logn elements each.
 */
void ffLDL_fft(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g01, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp);

/// Normalize an ffLDL tree: each leaf of value x is replaced with sigma / sqrt(x).
void ffLDL_binary_normalize(DOUBLE *tree, DOUBLE sigma, unsigned logn);

/*
 * Perform LDL decomposition of a 2x2 Gram matrix.
 *
 * Input: matrix G = [[g00, g01], [g10, g11]] such that G* = G
 * (hence: adj(g00) = g00, adj(g11) = g11, adj(g01) = g10).
 *
 * Output: L = [[1, 0], [l10, 1]] and D = [[d00, 0], [0, d11]] such
 * that G = L·D·L*.
 *
 * We have d00 = g00, thus that value is omitted from the outputs.
 *
 * All inputs and outputs are in FFT3 representation.
 * Overlap allowed only between the constant inputs (g00, g10, g11).
 */
void LDL_dim2_fft3(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g10,
	const DOUBLE *restrict g11, unsigned logn, unsigned full);

/*
 * Perform LDL decomposition of a Gram 3x3 matrix.
 *
 * Input: matrix G = [[g00, g01, g02], [g10, g11, g12], [g20, g21, g22]]
 * such that G* = G.
 *
 * Output: L = [[1, 0, 0], [l10, 1, 0], [l20, l21, 1]], and
 * D = [[d00, 0, 0], [0, d11, 0], [0, 0, d22]] such that G = L·D·L*.
 *
 * We have d00 = g00, thus that value is omitted from the outputs.
 *
 * All inputs and outputs are in FFT3 representation.
 * Overlap allowed only between the constant inputs (g00, g10, g11).
 * tmp[] must have room for one polynomial.
 */
void LDL_dim3_fft3(DOUBLE *restrict d11, DOUBLE *restrict d22,
	DOUBLE *restrict l10, DOUBLE *restrict l20, DOUBLE *restrict l21,
	const DOUBLE *restrict g00, const DOUBLE *restrict g10,
	const DOUBLE *restrict g11, const DOUBLE *restrict g20,
	const DOUBLE *restrict g21, const DOUBLE *restrict g22,
	unsigned logn, unsigned full, DOUBLE *restrict tmp);

size_t ffLDL_inner_fft3(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g10, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp);

size_t ffLDL_depth1_fft3(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g10, const DOUBLE *restrict g11,
	const DOUBLE *restrict g20, const DOUBLE *restrict g21,
	const DOUBLE *restrict g22, unsigned logn, DOUBLE *restrict tmp);

size_t ffLDL_fft3(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g10, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp);

/*
 * Get the size of the LDL tree for an input with polynomials of size
 * 2^logn. The size is expressed in the number of elements.
 */
inline unsigned ffLDL_ternary_treesize(unsigned logn)
{
	return 3 * ((logn + 2) << (logn - 1));
}

size_t ffLDL_ternary_normalize_inner(DOUBLE *tree, DOUBLE sigma, unsigned logn);

size_t ffLDL_ternary_normalize_depth1(DOUBLE *tree, DOUBLE sigma, unsigned logn);

size_t ffLDL_ternary_normalize(DOUBLE *tree, DOUBLE sigma, unsigned logn);
