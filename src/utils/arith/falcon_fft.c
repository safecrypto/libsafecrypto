/*
 * FFT code.
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

#include <stdio.h>
#include <math.h>

#include "safecrypto_types.h"

/*
 * Load the table of constants for FFT.
 */
#define FPC(re, im)   re, im
#include "falcon_fft.h"
#undef FPC



static const DOUBLE fpr_log2 = { 0.69314718055994530941723212146 };
static const DOUBLE fpr_p55 = { 36028797018963968.0 };
static const DOUBLE fpr_p63 = { 9223372036854775808.0 };
static const DOUBLE fpr_p64 = { 18446744073709551616.0 };

/*
 * For w = exp(i*pi/3), real and imaginary parts of w^1, w^2, w^4 and w^5.
 *
 *   w^2 and w^4 are the two primitive cubic roots of 1.
 *
 *   w^1 and w^5 are the two roots of X^2-X+1.
 */
static const DOUBLE fpr_W1R = {  0.500000000000000000000000000 };
static const DOUBLE fpr_W1I = {  0.866025403784438646763723171 };
static const DOUBLE fpr_W2R = { -0.500000000000000000000000000 };
static const DOUBLE fpr_W2I = {  0.866025403784438646763723171 };
static const DOUBLE fpr_W4R = { -0.500000000000000000000000000 };
static const DOUBLE fpr_W4I = { -0.866025403784438646763723171 };
static const DOUBLE fpr_W5R = {  0.500000000000000000000000000 };
static const DOUBLE fpr_W5I = { -0.866025403784438646763723171 };


/*
 * For w = exp(i*pi/3), the coefficient c = Re(w)/Im(w).
 */
static const DOUBLE fpr_IW1I = {  1.154700538379251529018297561 };



/*
 * Rules for complex number macros:
 * --------------------------------
 *
 * Operand order is: destination, source1, source2...
 *
 * Each operand is a real and an imaginary part.
 *
 * All overlaps are allowed.
 */

/*
 * Addition of two complex numbers (d = a + b).
 */
#define FPC_ADD(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
		DOUBLE fpct_re, fpct_im; \
		fpct_re = a_re + b_re; \
		fpct_im = a_im + b_im; \
		(d_re) = fpct_re; \
		(d_im) = fpct_im; \
	} while (0)

/*
 * Subtraction of two complex numbers (d = a - b).
 */
#define FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
		DOUBLE fpct_re, fpct_im; \
		fpct_re = a_re - b_re; \
		fpct_im = a_im - b_im; \
		(d_re) = fpct_re; \
		(d_im) = fpct_im; \
	} while (0)

/*
 * Multplication of two complex numbers (d = a * b).
 */
#define FPC_MUL(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
		DOUBLE fpct_a_re, fpct_a_im; \
		DOUBLE fpct_b_re, fpct_b_im; \
		DOUBLE fpct_d_re, fpct_d_im; \
		fpct_a_re = (a_re); \
		fpct_a_im = (a_im); \
		fpct_b_re = (b_re); \
		fpct_b_im = (b_im); \
		fpct_d_re = \
			(fpct_a_re * fpct_b_re) \
			- (fpct_a_im * fpct_b_im); \
		fpct_d_im =  \
			(fpct_a_re * fpct_b_im) \
			+(fpct_a_im * fpct_b_re); \
		(d_re) = fpct_d_re; \
		(d_im) = fpct_d_im; \
	} while (0)

/*
 * Squaring of a complex number (d = a * a).
 */
#define FPC_SQR(d_re, d_im, a_re, a_im)   do { \
		DOUBLE fpct_a_re, fpct_a_im; \
		DOUBLE fpct_d_re, fpct_d_im; \
		fpct_a_re = (a_re); \
		fpct_a_im = (a_im); \
		fpct_d_re = (fpct_a_re * fpct_a_re)-(fpct_a_im * fpct_a_im); \
		fpct_d_im = (fpct_a_re * fpct_a_im) + (fpct_a_re * fpct_a_im); \
		(d_re) = fpct_d_re; \
		(d_im) = fpct_d_im; \
	} while (0)

/*
 * Inversion of a complex number (d = 1 / a).
 */
#define FPC_INV(d_re, d_im, a_re, a_im)   do { \
		DOUBLE fpct_a_re, fpct_a_im; \
		DOUBLE fpct_d_re, fpct_d_im; \
		DOUBLE fpct_m; \
		fpct_a_re = (a_re); \
		fpct_a_im = (a_im); \
		fpct_m = (fpct_a_re * fpct_a_re) + (fpct_a_im* fpct_a_im); \
		fpct_d_re = fpct_a_re / fpct_m; \
		fpct_d_im = -(fpct_a_im)/ fpct_m; \
		(d_re) = fpct_d_re; \
		(d_im) = fpct_d_im; \
	} while (0)

/*
 * Division of complex numbers (d = a / b).
 */
#define FPC_DIV(d_re, d_im, a_re, a_im, b_re, b_im)   do { \
		DOUBLE fpct_a_re, fpct_a_im; \
		DOUBLE fpct_b_re, fpct_b_im; \
		DOUBLE fpct_d_re, fpct_d_im; \
		DOUBLE fpct_m; \
		fpct_a_re = (a_re); \
		fpct_a_im = (a_im); \
		fpct_b_re = (b_re); \
		fpct_b_im = (b_im); \
		fpct_m = fpct_b_re*fpct_b_re + fpct_b_im * fpct_b_im; \
		fpct_b_re = fpct_b_re / fpct_m; \
		fpct_b_im = -(fpct_b_im) / fpct_m; \
		fpct_d_re =  \
			fpct_a_re * fpct_b_re - \
			(fpct_a_im * fpct_b_im); \
		fpct_d_im =  \
			(fpct_a_re * fpct_b_im) + \
			(fpct_a_im * fpct_b_re); \
		(d_re) = fpct_d_re; \
		(d_im) = fpct_d_im; \
	} while (0)

/*
 * Let w = exp(i*pi/N); w is a primitive 2N-th root of 1. We define the
 * values w_j = w^(2j+1) for all j from 0 to N-1: these are the roots
 * of X^N+1 in the field of complex numbers. A crucial property is that
 * w_{N-1-j} = conj(w_j) = 1/w_j for all j.
 *
 * FFT representation of a polynomial f (taken modulo X^N+1) is the
 * set of values f(w_j). Since f is real, conj(f(w_j)) = f(conj(w_j)),
 * thus f(w_{N-1-j}) = conj(f(w_j)). We thus store only half the values,
 * for j = 0 to N/2-1; the other half can be recomputed easily when (if)
 * needed. A consequence is that FFT representation has the same size
 * as normal representation: N/2 complex numbers use N real numbers (each
 * complex number is the combination of a real and an imaginary part).
 *
 * We use a specific ordering which makes computations easier. Let rev()
 * be the bit-reversal function over log(N) bits. For j in 0..N/2-1, we
 * store the real and imaginary parts of f(w_j) in slots:
 *
 *    Re(f(w_j)) -> slot rev(j)/2
 *    Im(f(w_j)) -> slot rev(j)/2+N/2
 *
 * (Note that rev(j) is even for j < N/2.)
 */

/* see internal.h */
void
falcon_FFT(DOUBLE *f, unsigned logn)
{
	/*
	 * FFT algorithm in bit-reversal order uses the following
	 * iterative algorithm:
	 *
	 *   t = N
	 *   for m = 1; m < N; m *= 2:
	 *       ht = t/2
	 *       for i1 = 0; i1 < m; i1 ++:
	 *           j1 = i1 * t
	 *           s = GM[m + i1]
	 *           for j = j1; j < (j1 + ht); j ++:
	 *               x = f[j]
	 *               y = s * f[j + ht]
	 *               f[j] = x + y
	 *               f[j + ht] = x - y
	 *       t = ht
	 *
	 * GM[k] contains w^rev(k) for primitive root w = exp(i*pi/N).
	 *
	 * In the description above, f[] is supposed to contain complex
	 * numbers. In our in-memory representation, the real and
	 * imaginary parts of f[k] are in array slots k and k+N/2.
	 *
	 * We only keep the first half of the complex numbers. We can
	 * see that after the first iteration, the first and second halves
	 * of the array of complex numbers have separate lives, so we
	 * simply ignore the second part.
	 */

	unsigned u;
	size_t t, n, hn, m;

	/*
	 * First iteration: compute f[j] + i * f[j+N/2] for all j < N/2
	 * (because GM[1] = w^rev(1) = w^(N/2) = i).
	 * In our chosen representation, this is a no-op: everything is
	 * already where it should be.
	 */

	/*
	 * Subsequent iterations are truncated to use only the first
	 * half of values.
	 */
	n = (size_t)1 << logn;
	hn = n >> 1;
	t = hn;
	for (u = 1, m = 2; u < logn; u ++, m <<= 1) {
		size_t ht, hm, i1, j1;

		ht = t >> 1;
		hm = m >> 1;
		for (i1 = 0, j1 = 0; i1 < hm; i1 ++, j1 += t) {
			unsigned j, j2;
			DOUBLE s_re, s_im;

			s_re = fpr_gm_tab[((m + i1) << 1) + 0];
			s_im = fpr_gm_tab[((m + i1) << 1) + 1];
			j2 = j1 + ht;
//FILE * pFile;
//pFile=fopen("SAFEcrypto_fft_POINT1.txt", "w");
			for (j = j1; j < j2; j ++) {
				DOUBLE x_re, x_im, y_re, y_im;

				x_re = f[j];
				x_im = f[j + hn];
				y_re = f[j + ht];
				y_im = f[j + ht + hn];
//fprintf(pFile, "  %3.3g \t  %3.3g \t  %3.3g \t %3.3g \n", x_re, x_im, y_re, y_im);

				FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
//fprintf(pFile, " FPC_MUL %3.3g \t  %3.3g \n", y_re, y_im);

				FPC_ADD(f[j], f[j + hn],
					x_re, x_im, y_re, y_im);
//fprintf(pFile, " FPC_ADD %3.3g \t  %3.3g \n", f[j], f[j + hn]);

				FPC_SUB(f[j + ht], f[j + ht + hn],
					x_re, x_im, y_re, y_im);
//fprintf(pFile, " FPC_SUB %3.3g \t  %3.3g \n", f[j + ht], f[j + ht + hn]);

			}
//fclose(pFile);
		}
		t = ht;
	}
}

/* see internal.h */
void
falcon_iFFT(DOUBLE *f, unsigned logn)
{
	/*
	 * Inverse FFT algorithm in bit-reversal order uses the following
	 * iterative algorithm:
	 *
	 *   t = 1
	 *   for m = N; m > 1; m /= 2:
	 *       hm = m/2
	 *       dt = t*2
	 *       for i1 = 0; i1 < hm; i1 ++:
	 *           j1 = i1 * dt
	 *           s = iGM[hm + i1]
	 *           for j = j1; j < (j1 + t); j ++:
	 *               x = f[j]
	 *               y = f[j + t]
	 *               f[j] = x + y
	 *               f[j + t] = s * (x - y)
	 *       t = dt
	 *   for i1 = 0; i1 < N; i1 ++:
	 *       f[i1] = f[i1] / N
	 *
	 * iGM[k] contains (1/w)^rev(k) for primitive root w = exp(i*pi/N)
	 * (actually, iGM[k] = 1/GM[k] = conj(GM[k])).
	 *
	 * In the main loop (not counting the final division loop), in
	 * all iterations except the last, the first and second half of f[]
	 * (as an array of complex numbers) are separate. In our chosen
	 * representation, we do not keep the second half.
	 *
	 * The last iteration recombines the recomputed half with the
	 * implicit half, and should yield only real numbers since the
	 * target polynomial is real; moreover, s = i at that step.
	 * Thus, when considering x and y:
	 *    y = conj(x) since the final f[j] must be real
	 *    Therefore, f[j] is filled with 2*Re(x), and f[j + t] is
	 *    filled with 2*Im(x).
	 * But we already have Re(x) and Im(x) in array slots j and j+t
	 * in our chosen representation. That last iteration is thus a
	 * simple doubling of the values in all the array.
	 *
	 * We make the last iteration a no-op by tweaking the final
	 * division into a division by N/2, not N.
	 */
	size_t u, n, hn, t, m;

	n = (size_t)1 << logn;
	t = 1;
	m = n;
	hn = n >> 1;
	for (u = logn; u > 1; u --) {
		size_t hm, dt, i1, j1;

		hm = m >> 1;
		dt = t << 1;
		for (i1 = 0, j1 = 0; j1 < hn; i1 ++, j1 += dt) {
			size_t j, j2;
			DOUBLE s_re, s_im;

			j2 = j1 + t;
			s_re = fpr_gm_tab[((hm + i1) << 1) + 0];
			s_im = -(fpr_gm_tab[((hm + i1) << 1) + 1]);
			for (j = j1; j < j2; j ++) {
				DOUBLE x_re, x_im, y_re, y_im;

				x_re = f[j];
				x_im = f[j + hn];
				y_re = f[j + t];
				y_im = f[j + t + hn];
				FPC_ADD(f[j], f[j + hn],
					x_re, x_im, y_re, y_im);
				FPC_SUB(x_re, x_im, x_re, x_im, y_re, y_im);
				FPC_MUL(f[j + t], f[j + t + hn],
					x_re, x_im, s_re, s_im);
			}
		}
		t = dt;
		m = hm;
	}

	/*
	 * Last iteration is a no-op, provided that we divide by N/2
	 * instead of N. We need to make a special case for logn = 0.
	 */
	if (logn > 0) {
		DOUBLE ni;

		ni = ldexp(2, -(int)logn);
		for (u = 0; u < n; u ++) {
			f[u] = f[u] * ni;
		}
	}
}

/* see internal.h */
void
falcon_poly_add(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		a[u] = a[u] + b[u];
	}
}

/* see internal.h */
void
falcon_poly_addconst(DOUBLE *a, DOUBLE x, unsigned logn)
{
	(void)logn;
	a[0] = a[0] + x;
}

/* see internal.h */
void
falcon_poly_addconst_fft(DOUBLE *a, DOUBLE x, unsigned logn)
{
	size_t hn, u;

	hn = (size_t)1 << (logn - 1);
	for (u = 0; u < hn; u ++) {
		a[u] = a[u] + x;
	}
}

/* see internal.h */
void
falcon_poly_sub(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		a[u] = a[u] - b[u];
	}
}

/* see internal.h */
void
falcon_poly_neg(DOUBLE *a, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		a[u] = -a[u];
	}
}

/* see internal.h */
void
falcon_poly_adj(DOUBLE *a, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 1; u < hn; u ++) {
		DOUBLE t;

		t = -a[u];
		a[u] = -a[n - u];
		a[n - u] = t;
	}
	a[hn] = -a[hn];
}

/* see internal.h */
void
falcon_poly_adj_fft(DOUBLE *a, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = (n >> 1); u < n; u ++) {
		a[u] = -a[u];
	}
}

/* see internal.h */
void
falcon_poly_mul_fft(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_sqr_fft(DOUBLE *a, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;

		a_re = a[u];
		a_im = a[u + hn];
		FPC_SQR(a[u], a[u + hn], a_re, a_im);
	}
}

/* see internal.h */
void
falcon_poly_muladj_fft(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = -b[u + hn];
		FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_mulselfadj_fft(DOUBLE *a, unsigned logn)
{
	/*
	 * Since each coefficient is multiplied with its own conjugate,
	 * the result contains only real values.
	 */
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;

		a_re = a[u];
		a_im = a[u + hn];
		a[u] =(a_re*a_re)+ (a_im*a_im);
		a[u + hn] = 0;
	}
}

/* see internal.h */
void
falcon_poly_mulconst(DOUBLE *a, DOUBLE x, unsigned logn)
{
	size_t n, u;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		a[u] = a[u] * x;
	}
}

/* see internal.h */
void
falcon_poly_inv_fft(DOUBLE *a, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;

		a_re = a[u];
		a_im = a[u + hn];
		FPC_INV(a[u], a[u + hn], a_re, a_im);
	}
}

/* see internal.h */
void
falcon_poly_div_fft(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_divadj_fft(DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = -b[u + hn];
		FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_invnorm2_fft(DOUBLE *restrict d,
	const DOUBLE *restrict a, const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;
		DOUBLE b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		d[u] = 1/(
			(a_re*a_re) + (a_im*a_im) +
			(b_re*b_re) + (b_im*b_im));
	}
}

/* see internal.h */
void
falcon_poly_add_muladj_fft(DOUBLE *restrict d,
	const DOUBLE *restrict F, const DOUBLE *restrict G,
	const DOUBLE *restrict f, const DOUBLE *restrict g, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE F_re, F_im, G_re, G_im;
		DOUBLE f_re, f_im, g_re, g_im;
		DOUBLE a_re, a_im, b_re, b_im;

		F_re = F[u];
		F_im = F[u + hn];
		G_re = G[u];
		G_im = G[u + hn];
		f_re = f[u];
		f_im = f[u + hn];
		g_re = g[u];
		g_im = g[u + hn];

		FPC_MUL(a_re, a_im, F_re, F_im, f_re, -f_im);
		FPC_MUL(b_re, b_im, G_re, G_im, g_re, -g_im);
		d[u] = a_re + b_re;
		d[u + hn] = a_im + b_im;
	}
}

/* see internal.h */
void
falcon_poly_mul_autoadj_fft(DOUBLE *restrict a,
	const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		a[u] = a[u] * b[u];
		a[u + hn] = a[u + hn] * b[u];
	}
}

/* see internal.h */
void
falcon_poly_div_autoadj_fft(DOUBLE *restrict a,
	const DOUBLE *restrict b, unsigned logn)
{
	size_t n, hn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		a[u] = a[u] / b[u];
		a[u + hn] = a[u + hn] / b[u];
	}
}

/* see internal.h */
void
falcon_poly_split_fft(DOUBLE *restrict f0, DOUBLE *restrict f1,
	const DOUBLE *restrict f, unsigned logn)
{
	/*
	 * The FFT representation we use is in bit-reversed order
	 * (element i contains f(w^(rev(i))), where rev() is the
	 * bit-reversal function over the ring degree. This changes
	 * indexes with regards to the Falcon specification.
	 */
	size_t n, hn, qn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	qn = hn >> 1;

	/*
	 * We process complex values by pairs. For logn = 1, there is only
	 * one complex value (the other one is the implicit conjugate),
	 * so we add the two lines below because the loop will be
	 * skipped.
	 */
	f0[0] = f[0];
	f1[0] = f[hn];

	for (u = 0; u < qn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;
		DOUBLE t_re, t_im;

		a_re = f[(u << 1) + 0];
		a_im = f[(u << 1) + 0 + hn];
		b_re = f[(u << 1) + 1];
		b_im = f[(u << 1) + 1 + hn];

		FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
		f0[u] = t_re*0.5;
		f0[u + qn] = t_im * 0.5;

		FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
		FPC_MUL(t_re, t_im, t_re, t_im,
			fpr_gm_tab[((u + hn) << 1) + 0],
			-(fpr_gm_tab[((u + hn) << 1) + 1]));
		f1[u] = t_re * 0.5;
		f1[u + qn] = t_im * 0.5;
	}
}

/* see internal.h */
void
falcon_poly_merge_fft(DOUBLE *restrict f,
	const DOUBLE *restrict f0, const DOUBLE *restrict f1, unsigned logn)
{
	size_t n, hn, qn, u;

	n = (size_t)1 << logn;
	hn = n >> 1;
	qn = hn >> 1;

	/*
	 * An extra copy to handle the special case logn = 1.
	 */
	f[0] = f0[0];
	f[hn] = f1[0];

	for (u = 0; u < qn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;
		DOUBLE t_re, t_im;

		a_re = f0[u];
		a_im = f0[u + qn];
		FPC_MUL(b_re, b_im, f1[u], f1[u + qn],
			fpr_gm_tab[((u + hn) << 1) + 0],
			fpr_gm_tab[((u + hn) << 1) + 1]);
		FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
		f[(u << 1) + 0] = t_re;
		f[(u << 1) + 0 + hn] = t_im;
		FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
		f[(u << 1) + 1] = t_re;
		f[(u << 1) + 1 + hn] = t_im;
	}
}

/* ==================================================================== */
/*
 * Here begins code for FFT3. Modulus is X^N-X^(N/2)+1.
 *
 * (X^N-X^(N/2)+1)*(X^(N/2)+1) = X^(1.5*N)+1. The roots of X^N-X^(N/2)+1
 * are thus the roots of X^(1.5*N)+1 which are not roots of X^(N/2)+1.
 */

#define MKN(logn, full)   ((size_t)(1 + ((full) << 1)) << ((logn) - (full)))

/* see internal.h */
void
falcon_FFT3(DOUBLE *a, unsigned logn, unsigned full)
{
	size_t n, hn, u, t, tmin, m;

	n = MKN(logn, full);
	hn = n >> 1;

	/*
	 * First pass, for sub-polynomials of degree 2, each modulo
	 * X^2-X+1. If w = exp(i*pi/3), then the roots are w and w^5.
	 * We keep only a(w) = a0 + a1*w.
	 */
	for (u = 0; u < hn; u ++) {
		DOUBLE a0, a1;

		a0 = a[u];
		a1 = a[u + hn];
		a[u] = a0 + (a1 * fpr_W1R);
		a[u + hn] = a1 * fpr_W1I;
	}

	/*
	 * Intermediate steps for doubling the degree.
	 */
	t = hn;
	tmin = 1 + (full << 1);
	for (m = 2; t > tmin; m <<= 1) {
		size_t ht, hm, u1, v1;

		ht = t >> 1;
		hm = m >> 1;
		for (u1 = 0, v1 = 0; u1 < hm; u1 ++, v1 += t) {
			size_t v, v2;
			DOUBLE sr, si;

			sr = fpr_gm3_square[((m + u1) << 1) + 0];
			si = fpr_gm3_square[((m + u1) << 1) + 1];
			v2 = v1 + ht;
			for (v = v1; v < v2; v ++) {
				DOUBLE a0r, a0i, a1r, a1i;

				a0r = a[v];
				a0i = a[v + hn];
				a1r = a[v + ht];
				a1i = a[v + ht + hn];
				FPC_MUL(a1r, a1i, a1r, a1i, sr, si);
				FPC_ADD(a[v], a[v + hn],
					a0r, a0i, a1r, a1i);
				FPC_SUB(a[v + ht], a[v + ht + hn],
					a0r, a0i, a1r, a1i);
			}
		}
		t = ht;
	}

	/*
	 * Last step: degree tripling (only if degree is multiple of 3).
	 */
	if (full) {
		size_t v;

		for (u = 0, v = (size_t)1 << logn; u < hn; u += 3, v += 2) {
			DOUBLE fAr, fAi, fBr, fBi, fCr, fCi;
			DOUBLE xr, xi;
			DOUBLE fB0r, fB0i, fB1r, fB1i, fB2r, fB2i;
			DOUBLE fC0r, fC0i, fC1r, fC1i, fC2r, fC2i;

			fAr = a[u];
			fAi = a[u + hn];
			fBr = a[u + 1];
			fBi = a[u + 1 + hn];
			fCr = a[u + 2];
			fCi = a[u + 2 + hn];

			xr = fpr_gm3_cubic[v + 0];
			xi = fpr_gm3_cubic[v + 1];
			FPC_MUL(fB0r, fB0i, fBr, fBi, xr, xi);
			FPC_MUL(fB1r, fB1i, fB0r, fB0i, fpr_W2R, fpr_W2I);
			FPC_MUL(fB2r, fB2i, fB0r, fB0i, fpr_W4R, fpr_W4I);
			FPC_SQR(xr, xi, xr, xi);
			FPC_MUL(fC0r, fC0i, fCr, fCi, xr, xi);
			FPC_MUL(fC1r, fC1i, fC0r, fC0i, fpr_W2R, fpr_W2I);
			FPC_MUL(fC2r, fC2i, fC0r, fC0i, fpr_W4R, fpr_W4I);
			FPC_ADD(fB0r, fB0i, fB0r, fB0i, fC0r, fC0i);
			FPC_ADD(fB1r, fB1i, fB1r, fB1i, fC2r, fC2i);
			FPC_ADD(fB2r, fB2i, fB2r, fB2i, fC1r, fC1i);
			FPC_ADD(a[u + 0], a[u + 0 + hn], fAr, fAi, fB0r, fB0i);
			FPC_ADD(a[u + 1], a[u + 1 + hn], fAr, fAi, fB1r, fB1i);
			FPC_ADD(a[u + 2], a[u + 2 + hn], fAr, fAi, fB2r, fB2i);
		}
	}
}

/* see internal.h */
void
falcon_iFFT3(DOUBLE *a, unsigned logn, unsigned full)
{
	size_t n, hn, u, t, m;
	DOUBLE ni;

	n = MKN(logn, full);
	hn = n >> 1;

	/*
	 * First step: divide degree by 3.
	 */
	if (full) {
		size_t v;

		for (u = 0, v = (size_t)1 << logn; u < hn; u += 3, v += 2) {
			DOUBLE f0r, f0i, f1r, f1i, f2r, f2i, xr, xi;
			DOUBLE f11r, f11i, f12r, f12i, f21r, f21i, f22r, f22i;

			f0r = a[u];
			f0i = a[u + hn];
			f1r = a[u + 1];
			f1i = a[u + 1 + hn];
			f2r = a[u + 2];
			f2i = a[u + 2 + hn];

			xr = fpr_gm3_cubic[v + 0];
			xi = -(fpr_gm3_cubic[v + 1]);
			FPC_MUL(f11r, f11i, f1r, f1i, fpr_W4R, fpr_W4I);
			FPC_MUL(f12r, f12i, f1r, f1i, fpr_W2R, fpr_W2I);
			FPC_MUL(f21r, f21i, f2r, f2i, fpr_W4R, fpr_W4I);
			FPC_MUL(f22r, f22i, f2r, f2i, fpr_W2R, fpr_W2I);

			FPC_ADD(f1r, f1i, f1r, f1i, f2r, f2i);
			FPC_ADD(a[u], a[u + hn], f0r, f0i, f1r, f1i);

			FPC_ADD(f11r, f11i, f11r, f11i, f22r, f22i);
			FPC_ADD(f11r, f11i, f11r, f11i, f0r, f0i);
			FPC_MUL(a[u + 1], a[u + 1 + hn], xr, xi, f11r, f11i);

			FPC_SQR(xr, xi, xr, xi);
			FPC_ADD(f12r, f12i, f12r, f12i, f21r, f21i);
			FPC_ADD(f12r, f12i, f12r, f12i, f0r, f0i);
			FPC_MUL(a[u + 2], a[u + 2 + hn], xr, xi, f12r, f12i);
		}
	}

	/*
	 * Intermediate steps for halving the degree.
	 */
	t = 2 + (full << 2);
	for (m = (size_t)1 << (logn - 1 - full); t < n; m >>= 1) {
		size_t ht, hm, u1, v1;

		ht = t >> 1;
		hm = m >> 1;
		for (u1 = 0, v1 = 0; u1 < hm; u1 ++, v1 += t) {
			size_t v, v2;
			DOUBLE sr, si;

			sr = fpr_gm3_square[((m + u1) << 1) + 0];
			si = -(fpr_gm3_square[((m + u1) << 1) + 1]);
			v2 = v1 + ht;
			for (v = v1; v < v2; v ++) {
				DOUBLE a0r, a0i, a1r, a1i;

				a0r = a[v];
				a0i = a[v + hn];
				a1r = a[v + ht];
				a1i = a[v + ht + hn];
				FPC_ADD(a[v], a[v + hn],
					a0r, a0i, a1r, a1i);
				FPC_SUB(a0r, a0i, a0r, a0i, a1r, a1i);
				FPC_MUL(a[v + ht], a[v + ht + hn],
					a0r, a0i, sr, si);
			}
		}
		t <<= 1;
	}

	/*
	 * Last step: modulo X^2-X+1.
	 *
	 * For w = exp(i*pi/3), roots of X^2-X+1 are w and w^5. Since
	 * w^3 = -1, we have w^5 = -w^2 = -w + 1.
	 *
	 * The FFT computed a(w) = a0 + a1*w. Since a0 and a1 are
	 * real, we can recompute a0 and a1:
	 *
	 *   a1 = Im(a(w)) / Im(w)
	 *   a0 = Re(a(w)) - Re(w) * a1
	 *
	 * Note that Re(w) = 1/2.
	 */
	for (u = 0; u < hn; u ++) {
		DOUBLE xr, xi, a0, a1;

		xr = a[u];
		xi = a[u + hn];
		a1 = xi * fpr_IW1I;
		a0 = xr- (a1 * 0.5);
		a[u] = a0;
		a[u + hn] = a1;
	}

	/*
	 * We have an accumulated N/2 multiplier to remove.
	 */
	ni = 1/(n >> 1);
	for (u = 0; u < n; u ++) {
		a[u] = ni * a[u];
	}
}

/* see internal.h */
void
falcon_poly_add3(DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, u;

	n = MKN(logn, full);
	for (u = 0; u < n; u ++) {
		a[u] = a[u] + b[u];
	}
}

/* see internal.h */
void
falcon_poly_addconst3(DOUBLE *restrict a, DOUBLE x, unsigned logn, unsigned full)
{
	(void)logn;
	(void)full;
	a[0] = a[0] + x;
}

/* see internal.h */
void
falcon_poly_addconst_fft3(DOUBLE *restrict a, DOUBLE x, unsigned logn, unsigned full)
{
	size_t n, u;

	n = MKN(logn, full);
	for (u = 0; u < n; u ++) {
		a[u] = a[u] + x;
	}
}

/* see internal.h */
void
falcon_poly_sub3(DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, u;

	n = MKN(logn, full);
	for (u = 0; u < n; u ++) {
		a[u] = a[u]- b[u];
	}
}

/* see internal.h */
void
falcon_poly_neg3(DOUBLE *restrict a, unsigned logn, unsigned full)
{
	size_t n, u;

	n = MKN(logn, full);
	for (u = 0; u < n; u ++) {
		a[u] = -a[u];
	}
}

/* see internal.h */
void
falcon_poly_adj_fft3(DOUBLE *a, unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = hn; u < n; u ++) {
		a[u] = -a[u];
	}
}

/* see internal.h */
void
falcon_poly_mul_fft3(DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_sqr_fft3(DOUBLE *a, unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;

		a_re = a[u];
		a_im = a[u + hn];
		FPC_SQR(a[u], a[u + hn], a_re, a_im);
	}
}

/* see internal.h */
void
falcon_poly_muladj_fft3(DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = -b[u + hn];
		FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_mulselfadj_fft3(DOUBLE *a, unsigned logn, unsigned full)
{
	/*
	 * Since each coefficient is multiplied with its own conjugate,
	 * the result contains only real values.
	 */
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;

		a_re = a[u];
		a_im = a[u + hn];
		a[u] = a_re * a_re + a_im*a_im;
		a[u + hn] = 0;
	}
}

/* see internal.h */
void
falcon_poly_mulconst3(DOUBLE *a, DOUBLE x, unsigned logn, unsigned full)
{
	size_t n, u;

	n = MKN(logn, full);
	for (u = 0; u < n; u ++) {
		a[u] = a[u] * x;
	}
}

/* see internal.h */
void
falcon_poly_inv_fft3(DOUBLE *a, unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;

		a_re = a[u];
		a_im = a[u + hn];
		FPC_INV(a[u], a[u + hn], a_re, a_im);
	}
}

/* see internal.h */
void
falcon_poly_div_fft3(DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_divadj_fft3(DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = -b[u + hn];
		FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
	}
}

/* see internal.h */
void
falcon_poly_invnorm2_fft3(DOUBLE *restrict d,
	const DOUBLE *restrict a, const DOUBLE *restrict b,
	unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE a_re, a_im;
		DOUBLE b_re, b_im;

		a_re = a[u];
		a_im = a[u + hn];
		b_re = b[u];
		b_im = b[u + hn];
		d[u] = 1/(
			((a_re*a_re) + (a_im*a_im)) +
			((b_re*b_re) + (b_im*b_im)));
	}
}

/* see internal.h */
void
falcon_poly_add_muladj_fft3(DOUBLE *restrict d,
	const DOUBLE *restrict F, const DOUBLE *restrict G,
	const DOUBLE *restrict f, const DOUBLE *restrict g,
	unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		DOUBLE F_re, F_im, G_re, G_im;
		DOUBLE f_re, f_im, g_re, g_im;
		DOUBLE a_re, a_im, b_re, b_im;

		F_re = F[u];
		F_im = F[u + hn];
		G_re = G[u];
		G_im = G[u + hn];
		f_re = f[u];
		f_im = f[u + hn];
		g_re = g[u];
		g_im = g[u + hn];

		FPC_MUL(a_re, a_im, F_re, F_im, f_re, -f_im);
		FPC_MUL(b_re, b_im, G_re, G_im, g_re, -g_im);
		d[u] = a_re + b_re;
		d[u + hn] = a_im + b_im;
	}
}

/* see internal.h */
void
falcon_poly_mul_autoadj_fft3(DOUBLE *restrict a,
	const DOUBLE *restrict b, unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		a[u] = a[u] * b[u];
		a[u + hn] = a[u + hn] * b[u];
	}
}

/* see internal.h */
void
falcon_poly_div_autoadj_fft3(DOUBLE *restrict a,
	const DOUBLE *restrict b, unsigned logn, unsigned full)
{
	size_t n, hn, u;

	n = MKN(logn, full);
	hn = n >> 1;
	for (u = 0; u < hn; u ++) {
		a[u] = a[u]/ b[u];
		a[u + hn] = a[u + hn]/b[u];
	}
}

/* see internal.h */
void
falcon_poly_split_top_fft3(
	DOUBLE *restrict f0, DOUBLE *restrict f1, DOUBLE *restrict f2,
	const DOUBLE *restrict f, unsigned logn)
{
	size_t n, hn, qn, u, v;

	n = (size_t)3 << (logn - 1);
	hn = n >> 1;
	qn = (size_t)1 << (logn - 2);
	for (u = 0, v = 0; u < hn; u += 3, v ++) {
		DOUBLE fAr, fAi, fBr, fBi, fCr, fCi, xr, xi;
		DOUBLE fB1r, fB1i, fB2r, fB2i, fC1r, fC1i, fC2r, fC2i;
		DOUBLE t0r, t0i, t1r, t1i, t2r, t2i;

		fAr = f[u];
		fAi = f[u + hn];
		fBr = f[u + 1];
		fBi = f[u + 1 + hn];
		fCr = f[u + 2];
		fCi = f[u + 2 + hn];

		xr = fpr_gm3_cubic[(v << 1) + ((size_t)1 << logn) + 0];
		xi = -(fpr_gm3_cubic[(v << 1) + ((size_t)1 << logn) + 1]);
		FPC_MUL(fB1r, fB1i, fBr, fBi, fpr_W4R, fpr_W4I);
		FPC_MUL(fB2r, fB2i, fBr, fBi, fpr_W2R, fpr_W2I);
		FPC_MUL(fC1r, fC1i, fCr, fCi, fpr_W4R, fpr_W4I);
		FPC_MUL(fC2r, fC2i, fCr, fCi, fpr_W2R, fpr_W2I);

		FPC_ADD(fBr, fBi, fBr, fBi, fCr, fCi);
		FPC_ADD(t0r, t0i, fAr, fAi, fBr, fBi);

		FPC_ADD(fB1r, fB1i, fB1r, fB1i, fC2r, fC2i);
		FPC_ADD(fB1r, fB1i, fB1r, fB1i, fAr, fAi);
		FPC_MUL(t1r, t1i, xr, xi, fB1r, fB1i);

		FPC_SQR(xr, xi, xr, xi);
		FPC_ADD(fB2r, fB2i, fB2r, fB2i, fC1r, fC1i);
		FPC_ADD(fB2r, fB2i, fB2r, fB2i, fAr, fAi);
		FPC_MUL(t2r, t2i, xr, xi, fB2r, fB2i);

		f0[v] = t0r * (1/3);
		f0[v + qn] = t0i * (1/3);
		f1[v] = t1r * (1/3);
		f1[v + qn] = t1i * (1/3);
		f2[v] = t2r * (1/3);
		f2[v + qn] = t2i * (1/3);
	}
}

/* see internal.h */
void
falcon_poly_split_deep_fft3(DOUBLE *restrict f0, DOUBLE *restrict f1,
	const DOUBLE *restrict f, unsigned logn)
{
	size_t n, hn, qn, u, m;

	/*
	 * Special code for n = 2.
	 */
	if (logn == 1) {
		DOUBLE re, im, xx;

		re = f[0];
		im = f[1];
		xx = fpr_IW1I * im;
		*f1 = xx;
		*f0 = re - (xx*0.5);
		return;
	}

	n = (size_t)1 << logn;
	hn = n >> 1;
	qn = hn >> 1;

	m = (size_t)1 << (logn - 1);
	for (u = 0; u < qn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;
		DOUBLE t_re, t_im;

		a_re = f[(u << 1) + 0];
		a_im = f[(u << 1) + 0 + hn];
		b_re = f[(u << 1) + 1];
		b_im = f[(u << 1) + 1 + hn];

		FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
		f0[u] = t_re * 0.5;
		f0[u + qn] = t_im * 0.5;

		FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
		FPC_MUL(t_re, t_im, t_re, t_im,
			fpr_gm3_square[((u + m) << 1) + 0],
			-(fpr_gm3_square[((u + m) << 1) + 1]));
		f1[u] = t_re * 0.5;
		f1[u + qn] = t_im * 0.5;
	}
}

/* see internal.h */
void
falcon_poly_merge_top_fft3(DOUBLE *restrict f,
	const DOUBLE *restrict f0, const DOUBLE *restrict f1, const DOUBLE *restrict f2,
	unsigned logn)
{
	size_t n, hn, qn, u, v;

	n = (size_t)3 << (logn - 1);
	hn = n >> 1;
	qn = (size_t)1 << (logn - 2);
	for (u = 0, v = 0; u < hn; u += 3, v ++) {
		DOUBLE fAr, fAi, fBr, fBi, fCr, fCi;
		DOUBLE xr, xi;
		DOUBLE fB0r, fB0i, fB1r, fB1i, fB2r, fB2i;
		DOUBLE fC0r, fC0i, fC1r, fC1i, fC2r, fC2i;

		fAr = f0[v];
		fAi = f0[v + qn];
		fBr = f1[v];
		fBi = f1[v + qn];
		fCr = f2[v];
		fCi = f2[v + qn];

		xr = fpr_gm3_cubic[(v << 1) + ((size_t)1 << logn) + 0];
		xi = fpr_gm3_cubic[(v << 1) + ((size_t)1 << logn) + 1];
		FPC_MUL(fB0r, fB0i, fBr, fBi, xr, xi);
		FPC_MUL(fB1r, fB1i, fB0r, fB0i, fpr_W2R, fpr_W2I);
		FPC_MUL(fB2r, fB2i, fB0r, fB0i, fpr_W4R, fpr_W4I);
		FPC_SQR(xr, xi, xr, xi);
		FPC_MUL(fC0r, fC0i, fCr, fCi, xr, xi);
		FPC_MUL(fC1r, fC1i, fC0r, fC0i, fpr_W2R, fpr_W2I);
		FPC_MUL(fC2r, fC2i, fC0r, fC0i, fpr_W4R, fpr_W4I);
		FPC_ADD(fB0r, fB0i, fB0r, fB0i, fC0r, fC0i);
		FPC_ADD(fB1r, fB1i, fB1r, fB1i, fC2r, fC2i);
		FPC_ADD(fB2r, fB2i, fB2r, fB2i, fC1r, fC1i);
		FPC_ADD(f[u + 0], f[u + 0 + hn], fAr, fAi, fB0r, fB0i);
		FPC_ADD(f[u + 1], f[u + 1 + hn], fAr, fAi, fB1r, fB1i);
		FPC_ADD(f[u + 2], f[u + 2 + hn], fAr, fAi, fB2r, fB2i);
	}
}

/* see internal.h */
void
falcon_poly_merge_deep_fft3(DOUBLE *restrict f,
	const DOUBLE *restrict f0, const DOUBLE *restrict f1, unsigned logn)
{
	size_t n, hn, qn, u, m;

	/*
	 * Special code for n = 2.
	 */
	if (logn == 1) {
		DOUBLE x, y;

		x = *f0;
		y = *f1;
		f[0] = x + (y * fpr_W1R);
		f[1] = y * fpr_W1I;
		return;
	}

	n = (size_t)1 << logn;
	hn = n >> 1;
	qn = hn >> 1;

	m = (size_t)1 << (logn - 1);
	for (u = 0; u < qn; u ++) {
		DOUBLE a_re, a_im, b_re, b_im;
		DOUBLE t_re, t_im;

		a_re = f0[u];
		a_im = f0[u + qn];
		b_re = f1[u];
		b_im = f1[u + qn];
		FPC_MUL(t_re, t_im, b_re, b_im,
			fpr_gm3_square[((u + m) << 1) + 0],
			fpr_gm3_square[((u + m) << 1) + 1]);
		FPC_ADD(f[(u << 1) + 0], f[(u << 1) + 0 + hn],
			a_re, a_im, t_re, t_im);
		FPC_SUB(f[(u << 1) + 1], f[(u << 1) + 1 + hn],
			a_re, a_im, t_re, t_im);
	}
}
