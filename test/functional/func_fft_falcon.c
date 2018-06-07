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
 *   Author: Neil Smyth <n.smyth@qub.ac.uk>
 *   Date:   Mon Oct 16 15:43:23 2017 +0100
 *   Branch: master
 *   Id:     71b278f6cc324587696337d6e06e77c3fee03c59
 */

#include <stdlib.h>
#include "safecrypto.h"
#include "safecrypto_debug.h"
#include "utils/arith/ntt.h"

#include <string.h>
#include <math.h>

//falcon code included
#include "utils/arith/falcon_fft.h"

/*static void
mk_rand_poly(prng *p, DOUBLE *f, unsigned logn)
{
	size_t u, n;

	n = (size_t)1 << logn;
	for (u = 0; u < n; u ++) {
		int32_t x;
		
		x = falcon_prng_get_u8(p);
		x = (x << 8) + falcon_prng_get_u8(p);
		x &= 0x3FF;
		f[u] = (x - 512);
	}
}*/

//initial read-in test
/*int main(void)
{	typedef struct { double v; } fpr;
	size_t n=4;
	int64_t f[1024], g[1024];
	FILE *pFile;
	pFile=fopen("fft_input.txt", "r");
if(NULL==pFile){fprintf(stderr, "pfile error code=%zu \n", (size_t) pFile);};
int error;
for (size_t u = 0; u < n; u ++) {
fprintf(stderr, "u=%zu \n", u);
	error=fscanf(pFile, "%016lX \n", &g[u]);
if(1!=error){fprintf(stderr, "Error code=%d \n", error); return EXIT_FAILURE;}

	fprintf(stderr, "%016lX \n", g[u]);
printf("g[u]");
}
    return EXIT_SUCCESS;
}
*/

/*//*****my inserted test_fft function****
static void 
test_fft(unsigned logn)
{	DOUBLE f[1024], g[1024];
	
	prng p;
	unsigned char xb;
	size_t n;
	shake_context rng;
	n = (size_t)1 << logn;
	xb = logn;
	shake_init(&rng, 512);
	shake_inject(&rng, &xb, 1);
	shake_flip(&rng);
	falcon_prng_init(&p, &rng, PRNG_CHACHA20);

mk_rand_poly(&p, f, logn);
		memcpy(g, f, n * sizeof *f);
//print out g
FILE * pFile;
pFile=fopen("SAFEcrypto_fft_input.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile, "%016lX (%3.3g) \n ", llrint(g[u]), g[u]);
	}
fclose(pFile);

		falcon_FFT(g, logn);
//print out FFT(g)
pFile=fopen("SAFEcrypto_fft_output.txt", "w");
for (size_t u = 0; u < n; u ++) 
{
	fprintf(pFile, "%016lX (%3.3g) \n ", llrint(g[u]), g[u]);	
	//fprintf(stderr, "the FFT in/output values are %016lX (%3.3g) and %016lX (%3.3g) \n", llrint(f[u]), f[u], llrint(g[u]), g[u]);
}
fclose(pFile);
		falcon_iFFT(g, logn);
pFile=fopen("SAFEcrypto_ifft_output.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile, "%016lX (%3.3g) \n ", llrint(g[u]), g[u]);
	}
fclose(pFile);

		for (size_t u = 0; u < n; u ++) {
			if (llrint(f[u]) != llrint(g[u])) {
				fprintf(stderr, "FFT/iFFT error for u= %d \n", u);
				//fprintf(stderr, "the output values are %016lX (%3.3g) and %016lX (%3.3g) \n", llrint(f[u]), f[u], llrint(g[u]), g[u]);
				}
	}
}

//*****my inserted test_split function****
static void 
test_split(unsigned logn)
{	DOUBLE f[1024], g[1024], h[1024];
	DOUBLE f0[512], f1[512], g0[512], g1[512];
	prng p;
	unsigned char xb;
	size_t n;
	shake_context rng;
	n = (size_t)1 << logn;
	xb = logn;
	shake_init(&rng, 512);
	shake_inject(&rng, &xb, 1);
	shake_flip(&rng);
	falcon_prng_init(&p, &rng, PRNG_CHACHA20);


mk_rand_poly(&p, f, logn);
		memcpy(h, f, n * sizeof *f);
//print out h
FILE * pFile;
pFile=fopen("SAFEcrypto_split_input.txt", "w");
for (size_t u = 0; u < n; u ++) {
fprintf(pFile, "%016lX  (%3.3g)\n", llrint(h[u]), h[u]);
	}
fclose(pFile);
		falcon_FFT(f, logn);
		falcon_poly_split_fft(f0, f1, f, logn);

		memcpy(g0, f0, (n >> 1) * sizeof *f0);
		memcpy(g1, f1, (n >> 1) * sizeof *f1);

		falcon_iFFT(g0, logn - 1);
		falcon_iFFT(g1, logn - 1);
//print out g0
pFile=fopen("SAFEcrypto_split_output_0.txt", "w");
for (size_t u = 0; u < (n>>1); u ++) {
fprintf(pFile, "%016lX (%3.3g) \n ", llrint(g0[u]), g0[u]);
	}
fclose(pFile);
//print out g1
pFile=fopen("SAFEcrypto_split_output_1.txt", "w");
for (size_t u = 0; u < (n>>1); u ++) {
fprintf(pFile, "%016lX (%3.3g) \n ", llrint(g1[u]), g1[u]);
	}
fclose(pFile);
		for (size_t u = 0; u < (n >> 1); u ++) {
			if (llrint(g0[u]) != llrint(h[(u << 1) + 0])
				|| llrint(g1[u]) != llrint(h[(u << 1) + 1]))
			{
				fprintf(stderr, "split error for u= %d \n", u);
				//fprintf(stderr, "the  first output values are %016lX and %016lX \n", llrint(g0[u]), llrint(h[u <<1]+0));
				//fprintf(stderr, "the second output values are %016lX and %016lX \n", llrint(g1[u]), llrint(h[u << 1]+1));
}
}
//test merge function (no output)
falcon_poly_merge_fft(g, f0, f1, logn);
		falcon_iFFT(g, logn);
		for (size_t u = 0; u < n; u ++) {
			if (llrint(g[u]) != llrint(h[u])) {
				fprintf(stderr, "merge error for u= %d \n", u);
			//fprintf(stderr, "the output values are %016lX and %016lX \n", llrint(g[u]), llrint(h[u]));
				exit(EXIT_FAILURE);
			}
		}
}*/

int main(void)
{
	//test_fft(2);
	//test_split(2);
return 0;
}	
