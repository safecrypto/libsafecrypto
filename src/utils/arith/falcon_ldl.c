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

#include <string.h>
#include "utils/arith/falcon_ldl.h"
#include "utils/arith/falcon_fft.h"

/* =================================================================== */

/*
 * Compute degree N from logarithm 'logn', and ternary flag 'ter'.
 * 'ter' MUST be 0 or 1.
 */
#ifndef MKN
#define MKN(logn, ter)   ((size_t)(1 + ((ter) << 1)) << ((logn) - (ter)))
#endif

/* =================================================================== */
/*
 * Binary case:
 *   N = 2^logn
 *   phi = X^N+1
 */

/*
 * Compute LDL decomposition on an auto-adjoint 2x2 matrix G. Matrix
 * elements are real polynomials modulo X^n+1:
 *   g00   top-left element
 *   g01   top-right element
 *   g10   bottom-left element
 *   g11   bottom-right element
 *
 * The matrix being auto-adjoint means that G = G*. Thus, adj(g00) == g00,
 * adj(g11) == g11, adj(g10) == g01, and adj(g01) == g10.
 * Since g10 and g01 are redundant, g10 is not provided as parameter.
 *
 * LDL decomposition is:
 *   G = L·D·L*
 * where L is lower-triangular with 1 on the diagonal, and D is diagonal.
 * The top-left element of D is equal to g00, so it is not returned;
 * outputs are thus d11 (lower-right element of D) and l10 (lower-left
 * element of L).
 *
 * The tmp[] buffer must be able to hold at least one polynomial.
 *
 * All operands are in FFT representation. No overlap allowed, except
 * between the constant inputs (g00, g01 and g11).
 */
void
LDL_fft(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g01,
	const DOUBLE *restrict g11, unsigned logn, DOUBLE *restrict tmp)
{
	size_t n;
	n = (1 + ((0) << 1)) << (logn) - (0);
	/* Let tmp = mu = G[0,1] / G[0,0]. */
	memcpy(tmp, g01, n * sizeof *g01);
	falcon_poly_div_fft(tmp, g00, logn);

	/* Let L[1,0] = adj(mu) and tmp = aux = mu * adj(mu). */
	memcpy(l10, tmp, n * sizeof *tmp);
	falcon_poly_adj_fft(l10, logn);
	falcon_poly_mul_fft(tmp, l10, logn);

	/* D[1,1] = G[1,1] - aux * G[0][0]. */
	falcon_poly_mul_fft(tmp, g00, logn);
	memcpy(d11, g11, n * sizeof *g11);
	falcon_poly_sub_fft(d11, tmp, logn);
}

/*
 * Special case of LDL when G is quasicyclic, i.e. g11 == g00.
 */
inline void
LDLqc_fft(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g01, unsigned logn,
	DOUBLE *restrict tmp);

/*
 * Get the size of the LDL tree for an input with polynomials of size
 * 2^logn. The size is expressed in the number of elements.
 */
inline unsigned ffLDL_treesize(unsigned logn);

/*
 * Inner function for ffLDL_fft(). It expects the matrix to be both
 * auto-adjoint and quasicyclic; also, it uses the source operands
 * as modifiable temporaries.
 *
 * tmp[] must have room for at least two polynomials.
 */
void
ffLDL_fft_inner(DOUBLE *restrict tree,
	DOUBLE *restrict g0, DOUBLE *restrict g1, unsigned logn, DOUBLE *restrict tmp)
{
	size_t n, hn;

	n = (1 + ((0) << 1)) << ((logn) - (0));
	if (n == 1) {
		tree[0] = g0[0];
		return;
	}
	hn = n >> 1;

	/*
	 * The LDL decomposition yields L (which is written in the tree)
	 * and the diagonal of D. Since d00 = g0, we just write d11
	 * into tmp.
	 */
	LDLqc_fft(tmp, tree, g0, g1, logn, tmp + n);

	/*
	 * Split d00 (currently in g0) and d11 (currently in tmp). We
	 * reuse g0 and g1 as temporary storage spaces:
	 *   d00 splits into g1, g1+hn
	 *   d11 splits into g0, g0+hn
	 */
	falcon_poly_split_fft(g1, g1 + hn, g0, logn);
	falcon_poly_split_fft(g0, g0 + hn, tmp, logn);

	/*
	 * Each split result is the first row of a new auto-adjoint
	 * quasicyclic matrix for the next recursive step.
	 */
	ffLDL_fft_inner(tree + n,
		g1, g1 + hn, logn - 1, tmp);
	ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
		g0, g0 + hn, logn - 1, tmp);
}

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
void
ffLDL_fft(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g01, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp)
{
	size_t n, hn;
	DOUBLE *d00, *d11;
	n = (1 + ((0) << 1)) << ((logn) - (0));
	if (n == 1) {
		tree[0] = g00[0];
		return;
	}
	hn = n >> 1;
	d00 = tmp;
	d11 = tmp + n;
	tmp += n << 1;

	memcpy(d00, g00, n * sizeof *g00);
	LDL_fft(d11, tree, g00, g01, g11, logn, tmp);

	falcon_poly_split_fft(tmp, tmp + hn, d00, logn);
	falcon_poly_split_fft(d00, d00 + hn, d11, logn);
	memcpy(d11, tmp, n * sizeof *tmp);
	ffLDL_fft_inner(tree + n,
		d11, d11 + hn, logn - 1, tmp);
	ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
		d00, d00 + hn, logn - 1, tmp);
}

/*
 * Normalize an ffLDL tree: each leaf of value x is replaced with
 * sigma / sqrt(x).
 */
void
ffLDL_binary_normalize(DOUBLE *tree, DOUBLE sigma, unsigned logn)
{
	/*
	 * TODO: make an iterative version.
	 */
	size_t n;

	n = (1 + ((0) << 1)) << ((logn) - (0));
	if (n == 1) {
		tree[0] = (sigma / sqrt(tree[0]));
	} else {
		ffLDL_binary_normalize(tree + n,
			sigma, logn - 1);
		ffLDL_binary_normalize(tree + n + ffLDL_treesize(logn - 1),
			sigma, logn - 1);
	}
}
/* =================================================================== */
/*
 * Ternary case:
 *   N = 1.5*2^logn
 *   phi = X^N-X^(N/2)+1
 *
 * When doing operations along the splitting tree, the "top" operation
 * divides the degree by 3, while "deep" operations halve the degree.
 *
 * At the top-level, we perform a trisection:
 *
 *  - Input 2x2 Gram matrix is decomposed into its LDL representation:
 *    G = L·D·L*, where D is diagonal and L is low-triangular with
 *    only ones on its diagonal. Thus, there is one non-trivial element
 *    in L, and two non-trivial elements in D.
 *
 *  - Elements of D are each split into three elements of degree N/3.
 *
 *  - Two recursive invocations on 3x3 Gram matrices are performed.
 *
 * At the level immediately below:
 *
 *  - Input 3x3 Gram matrix is decomposed into LDL. We get three non-trivial
 *    elements in D (the diagonal), and three others in L (the lower
 *    triangle, excluding the diagonal). From these, we performs splits
 *    (that halve the degree) and build three 2x2 matrices for the recursive
 *    invocation.
 *
 * Lower levels receive a 2x2 Gram matrix, and perform 2-way splits.
 *
 * At the lowest level, polynomials are modulo X^2-X+1.
 */

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
void
LDL_dim2_fft3(DOUBLE *restrict d11, DOUBLE *restrict l10,
	const DOUBLE *restrict g00, const DOUBLE *restrict g10,
	const DOUBLE *restrict g11, unsigned logn, unsigned full)
{
	size_t n;

	n = MKN(logn, full);

	/*
	 * Set l10 = g10/g00.
	 * Since g00 = adj(g00), FFT representation of g00 contains only
	 * real numbers.
	 */
	memcpy(l10, g10, n * sizeof *g10);
	falcon_poly_div_autoadj_fft3(l10, g00, logn, full);

	/*
	 * Set d11 = g11 - g10*adj(g10/g00).
	 * TODO: g11 = adj(g11), so it should be half-sized (only real
	 * numbers in FFT representation).
	 */
	memcpy(d11, g10, n * sizeof *g10);
	falcon_poly_muladj_fft3(d11, l10, logn, full);
	falcon_poly_neg_fft3(d11, logn, full);
	falcon_poly_add_fft3(d11, g11, logn, full);
}

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
void
LDL_dim3_fft3(DOUBLE *restrict d11, DOUBLE *restrict d22,
	DOUBLE *restrict l10, DOUBLE *restrict l20, DOUBLE *restrict l21,
	const DOUBLE *restrict g00, const DOUBLE *restrict g10,
	const DOUBLE *restrict g11, const DOUBLE *restrict g20,
	const DOUBLE *restrict g21, const DOUBLE *restrict g22,
	unsigned logn, unsigned full, DOUBLE *restrict tmp)
{
	size_t n;

	n = MKN(logn, full);

	/*
	 * l10 = g10/g00
	 * d11 = g11 - g10*adj(g10/g00)
	 * These are the same formulas as the LDL decomposition of a 2x2
	 * matrix.
	 */
	LDL_dim2_fft3(d11, l10, g00, g10, g11, logn, full);

	/*
	 * l20 = g20/g00
	 */
	memcpy(l20, g20, n * sizeof *g20);
	falcon_poly_div_autoadj_fft3(l20, g00, logn, full);

	/*
	 * l21 = (g21 - g20*adj(g10)/g00) / d11
	 * Note that d11 = adj(d11)
	 */
	memcpy(l21, g20, n * sizeof *g20);
	falcon_poly_muladj_fft3(l21, g10, logn, full);
	falcon_poly_div_autoadj_fft3(l21, g00, logn, full);
	falcon_poly_neg_fft3(l21, logn, full);
	falcon_poly_add_fft3(l21, g21, logn, full);
	falcon_poly_div_autoadj_fft3(l21, d11, logn, full);

	/*
	 * d22 = g22 - l20*adj(g20) - l21*adj(l21) / d11
	 */
	memcpy(d22, l20, n * sizeof *l20);
	falcon_poly_muladj_fft3(d22, g20, logn, full);
	falcon_poly_neg_fft3(d22, logn, full);
	falcon_poly_add_fft3(d22, g22, logn, full);
	memcpy(tmp, l21, n * sizeof *l21);
	falcon_poly_mulselfadj_fft3(tmp, logn, full);
	falcon_poly_mul_autoadj_fft3(tmp, d11, logn, full);
	falcon_poly_sub_fft3(d22, tmp, logn, full);
}

size_t
ffLDL_inner_fft3(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g10, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp)
{
	size_t n, hn, s;
	DOUBLE *t0, *t1, *t2;

	n = (size_t)1 << logn;
	hn = n >> 1;

	if (logn == 1) {
		/*
		 * When N = 2, diagonal elements (of D in the LDL
		 * decomposition) are real numbers (since they are
		 * auto-adjoint), and there is no need for further
		 * recursion.
		 *
		 * LDL_dim2_fft3() returns d11 (in tmp) and l10
		 * (two slots, in tree). It will be followed by two
		 * leaves, corresponding to d00 (which is g00) and d11.
		 * The two leaves are real numbers (one slot each).
		 */
		LDL_dim2_fft3(tmp, tree, g00, g10, g11, logn, 0);

		tree[2] = g00[0];
		tree[3] = tmp[0];
		return 4;
	}

	/*
	 * Do the LDL, split diagonal elements, and recurse.
	 * Since d00 = g00, we can do the first recursion
	 * before the LDL.
	 */
	s = n;
	t0 = tmp;
	t1 = tmp + hn;
	t2 = t1 + hn;

	falcon_poly_split_deep_fft3(t0, t1, g00, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	s += ffLDL_inner_fft3(tree + s, t0, t1, t0, logn - 1, t2);

	LDL_dim2_fft3(t2, tree, g00, g10, g11, logn, 0);

	falcon_poly_split_deep_fft3(t0, t1, t2, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	s += ffLDL_inner_fft3(tree + s, t0, t1, t0, logn - 1, t2);

	return s;
}

size_t
ffLDL_depth1_fft3(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g10, const DOUBLE *restrict g11,
	const DOUBLE *restrict g20, const DOUBLE *restrict g21,
	const DOUBLE *restrict g22, unsigned logn, DOUBLE *restrict tmp)
{
	/*
	 * At depth 1, we perform a bisection on the elements of the
	 * input 3x3 matrix.
	 */

	size_t n, hn, s;
	DOUBLE *l10, *l20, *l21, *d11, *d22;
	DOUBLE *t0, *t1, *t2;

	n = (size_t)1 << logn;
	hn = n >> 1;
	l10 = tree;
	l20 = l10 + n;
	l21 = l20 + n;
	d11 = tmp;
	d22 = d11 + n;
	t0 = d22 + n;
	t1 = t0 + hn;
	t2 = t1 + hn;
	s = 3 * n;

	/*
	 * LDL decomposition.
	 */
	LDL_dim3_fft3(d11, d22, l10, l20, l21,
		g00, g10, g11, g20, g21, g22, logn, 0, t2);

	/*
	 * Splits and recursive invocations.
	 *
	 * TODO: for N = 6, this would need special code. Right now,
	 * we simply refuse to handle it, because N = 6 is way too weak
	 * to have any value anyway.
	 */
	falcon_poly_split_deep_fft3(t0, t1, g00, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	s += ffLDL_inner_fft3(tree + s, t0, t1, t0, logn - 1, t2);

	falcon_poly_split_deep_fft3(t0, t1, d11, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	s += ffLDL_inner_fft3(tree + s, t0, t1, t0, logn - 1, t2);

	falcon_poly_split_deep_fft3(t0, t1, d22, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	s += ffLDL_inner_fft3(tree + s, t0, t1, t0, logn - 1, t2);

	return s;
}

size_t
ffLDL_fft3(DOUBLE *restrict tree, const DOUBLE *restrict g00,
	const DOUBLE *restrict g10, const DOUBLE *restrict g11,
	unsigned logn, DOUBLE *restrict tmp)
{
	size_t n, tn, s;
	DOUBLE *l10, *d11, *t0, *t1, *t2, *t3;

	n = (size_t)3 << (logn - 1);
	tn = (size_t)1 << (logn - 1);
	l10 = tree;
	s = n;
	t0 = tmp;
	t1 = t0 + tn;
	t2 = t1 + tn;
	t3 = t2 + tn;

	/*
	 * Formally, we perform the LDL decomposition, _then_ do
	 * the recursion on split versions of the diagonal elements.
	 * However, d00 = g00, so we can perform the first recursion
	 * _before_ computing the LDL; this saves RAM.
	 */

	/*
	 * Trisection of d00 for first recursion.
	 */
	falcon_poly_split_top_fft3(t0, t1, t2, g00, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	falcon_poly_adj_fft3(t2, logn - 1, 0);
	s += ffLDL_depth1_fft3(tree + s, t0, t1, t0, t2, t1, t0, logn - 1, t3);

	/*
	 * Compute LDL decomposition of the top matrix.
	 */
	d11 = t3;
	LDL_dim2_fft3(d11, l10, g00, g10, g11, logn, 1);

	/*
	 * Trisection of d11 for second recursion.
	 */
	falcon_poly_split_top_fft3(t0, t1, t2, d11, logn);
	falcon_poly_adj_fft3(t1, logn - 1, 0);
	falcon_poly_adj_fft3(t2, logn - 1, 0);
	s += ffLDL_depth1_fft3(tree + s, t0, t1, t0, t2, t1, t0, logn - 1, t3);

	return s;
}

/*
 * Get the size of the LDL tree for an input with polynomials of size
 * 2^logn. The size is expressed in the number of elements.
 */
inline unsigned ffLDL_ternary_treesize(unsigned logn);

size_t
ffLDL_ternary_normalize_inner(DOUBLE *tree, DOUBLE sigma, unsigned logn)
{
	size_t s;

	if (logn == 1) {
		/*
		 * At logn = 1, tree consists in three polynomials,
		 * one parent node and two leaves. We normalize the
		 * leaves.
		 */
		tree[2] = fpr_div(sigma, fpr_sqrt(tree[2]));
		tree[3] = fpr_div(sigma, fpr_sqrt(tree[3]));
		return 4;
	}

	s = (size_t)1 << logn;
	s += ffLDL_ternary_normalize_inner(tree + s, sigma, logn - 1);
	s += ffLDL_ternary_normalize_inner(tree + s, sigma, logn - 1);
	return s;
}

size_t
ffLDL_ternary_normalize_depth1(DOUBLE *tree, DOUBLE sigma, unsigned logn)
{
	size_t s;

	s = (size_t)3 << logn;
	s += ffLDL_ternary_normalize_inner(tree + s, sigma, logn - 1);
	s += ffLDL_ternary_normalize_inner(tree + s, sigma, logn - 1);
	s += ffLDL_ternary_normalize_inner(tree + s, sigma, logn - 1);
	return s;
}

size_t
ffLDL_ternary_normalize(DOUBLE *tree, DOUBLE sigma, unsigned logn)
{
	size_t s;

	s = (size_t)3 << (logn - 1);
	s += ffLDL_ternary_normalize_depth1(tree + s, sigma, logn - 1);
	s += ffLDL_ternary_normalize_depth1(tree + s, sigma, logn - 1);
	return s;
}


#undef MKN

