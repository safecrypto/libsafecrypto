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

#include "bac.h"

#include <math.h>

#define BYTE_MASK             0xFF
#define BYTE_UPPER_LIMIT      0x100

#define BAC_64_LOWER_BOUND    0x0000000000000000
#define BAC_64_RANGE          0xFFFFFFFFFFFFFFFF
#define BAC_64_RANGE_MSB      0x8000000000000000
#define BAC_64_MID_LSB_MASK   0xFFFFFFFE

#define BAC_32_LOWER_BOUND    0x00000000
#define BAC_32_RANGE          0xFFFFFFFF
#define BAC_32_RANGE_MSB      0x80000000
#define BAC_32_MID_LSB_MASK   0xFFFFFFFE


#ifndef HAVE_128BIT
/// A multiplier suitable for processors that support uint64_t
static inline UINT64 mpmul32(UINT32 *x, UINT32 *y)
{
    UINT32 c;
    UINT64 uv;

    uv = (UINT64)x[0] * (UINT64)y[0];
    c = uv >> 32;
    uv = (UINT64)x[1] * (UINT64)y[0] + c;
    c = uv >> 32;
    uv = (uv & 0xFFFFFFFF) + (UINT64)x[0] * (UINT64)y[1] + c;
    c = uv >> 32;
    uv = (uv & 0xFFFFFFFF) + (UINT64)x[1] * (UINT64)y[1] + c;
    return uv;
}
#endif

inline UINT64 mul64hi(UINT64 x, UINT64 y)
{
#ifdef HAVE_128BIT
    return (UINT64) ((((UINT128) x) * ((UINT128) y)) >> 64);
#else
    UINT32 a[2], b[2] = {0};
    a[0] = x;
    a[1] = x >> 32;
    b[0] = y;
    b[1] = y >> 32;
    return mpmul32(a, b);
#endif

}

static inline UINT64 div64fr(UINT64 x, UINT64 y)
{
#ifdef HAVE_128BIT
    return (UINT64) (((((UINT128) x) << 64) - 1) / ((UINT128) y));
#else
    return 0;
#endif
}

#ifdef HAVE_64BIT
SINT32 gauss_freq_bac_64(UINT64 *dist, FLOAT sig, size_t n)
{
    size_t i, j, k;
    SINT32 x;
    LONGDOUBLE a, b, sig2i;
    UINT64 r;

    sig2i = -0.5 / (sig * sig);

    for (i=0; i<n; i++)
        dist[i] = 0;

    for (i=n>>1; i>=1; i>>=1) {
        for (j=0; j<n; j+=i+i) {

            a = 0.0;
            b = 0.0;

            for (k=0; k<i; k++) {
                // x is normalized
                x = (j + k) - ((SINT32) (n >> 1));
                a += expl(sig2i * ((LONGDOUBLE) (x * x)));
                x = (i + j + k) - ((SINT32) (n >> 1));
                b += expl(sig2i * ((LONGDOUBLE) (x * x)));
            }
            a = a / (a + b);
            r = (UINT64) (0x1.p64 * a);
            if (r < 4) {
                if (a > 0.5)
                    r = -4;
                else
                    r = 4;
            }
            /*if (r > -4)
                r = -4;*/

            dist[j + i] = r;
        }
    }

    return SC_FUNC_SUCCESS;
}
#endif

void bac_distfreq_64(UINT64 *dist, UINT64 *freq, size_t n)
{
    size_t i, j, k;
    UINT64 a, b, r;

    for (i = 0; i < n; i++)
        dist[i] = 0;

    for (i = n >> 1; i >= 1; i >>= 1) {
        for (j = 0; j < n; j += i + i) {

            a = 1;
            b = 1;

            for (k = 0; k < i; k++) {
                a += freq[j + k];
                b += freq[i + j + k];
            }
            r = div64fr(a, a + b);
            if (r < 4)
                r = 4;
            /*if (r > -4)
                r = -4;*/
            dist[j + i] = r;
        }
    }
}

static inline void carry_propagation(SINT32 optr, SINT32 obyte, UINT8 *buffer)
{
    SINT32 i;

    for (i = optr - 1; obyte >= BYTE_UPPER_LIMIT && i >= 0; i--) {
        obyte >>= 8;
        obyte += (UINT32) buffer[i];
        buffer[i] = obyte & BYTE_MASK;
    }
}

SINT32 bac_encode_64_32(sc_packer_t *packer, const SINT32 *in, size_t inlen,
    const UINT64 *dist, SINT32 bits, SINT32 offset)
{
    SINT32 iptr, icnt, optr, ocnt;
    UINT32 data;                          // output byte; can handle carry
    UINT32 iwrd;                          // input word
    UINT64 b, l, c;                       // range variables
    UINT8 *buffer, *bufhdr;
    SINT32 *l_in = (SINT32*)in;

    // Flush the packer to obtain byte alignment
    utils_entropy.pack_flush(packer);

    bufhdr = utils_entropy.pack_get_write_ptr(packer);
    if (SC_FUNC_FAILURE == packer->write(packer, 0x0000, 16)) {
        return SC_FUNC_FAILURE;
    }
    utils_entropy.pack_flush(packer);
    buffer = utils_entropy.pack_get_write_ptr(packer);

    b = BAC_64_LOWER_BOUND;                 // lower bound
    l = BAC_64_RANGE;                       // range

    data = 0;                               // (partial) output byte
    ocnt = 0;                               // bit count 0..7
    optr = 0;

    for (iptr=inlen; iptr--;) {

        iwrd = offset + *l_in++;

        for (icnt = bits; icnt--;) {

            // Midpoint split
            c = dist[(iwrd & (BAC_64_MID_LSB_MASK << icnt)) | (1 << icnt)];
            c = mul64hi(l, c);              // scale to range

            if (0 == ((iwrd >> icnt) & 1)) {
                l = c;                      // 0 bit; lower part
            }
            else {
                b += c;                     // 1 bit; higher part
                l -= c;                     // flip range to upper half
                if (b < c) {                // overflow ?
                    data++;                 // carry
                }
            }

            // Normalize and output bits whilst the range is within bounds
            if (l) {
            while (l < BAC_64_RANGE_MSB) {
                data <<= 1;
                data |= (b >> 63) & 1;
                ocnt++;
                if (ocnt >= 8) {            // full byte ?
                    if (SC_FUNC_FAILURE == packer->write(packer, data & BYTE_MASK, 8)) {
                        return SC_FUNC_FAILURE;
                    }
                    utils_entropy.pack_flush(packer);
                    carry_propagation(optr, data, buffer);
                    optr++;
                    ocnt = 0;
                    data = 0;
                }

                b <<= 1;                    // shift left
                l <<= 1;                    // double range
            }
            }
        }
    }

    while (ocnt < 8) {                      // flush output byte
        data = (data << 1) ^ (b >> 63);
        b <<= 1;
        ocnt++;
    }

    if (SC_FUNC_FAILURE == packer->write(packer, data, 8)) {  // final carry
        return SC_FUNC_FAILURE;
    } 
    utils_entropy.pack_flush(packer);
    carry_propagation(optr, data, buffer);
    optr++;
    while (0 != b) {
        if (SC_FUNC_FAILURE == packer->write(packer, b >> 56, 8)) {
            return SC_FUNC_FAILURE;
        }
        b <<= 8;
        optr++;
    }

    // Assign the length of the encoded stream
    bufhdr[0] = optr >> 8;
    bufhdr[1] = optr & BYTE_MASK;

    return SC_FUNC_SUCCESS;
}

SINT32 bac_decode_64_32(sc_packer_t *packer, SINT32 *out, size_t outlen,
    const UINT64 *dist, SINT32 bits, SINT32 offset)
{
    SINT32 iptr, icnt, optr, ocnt;
    UINT64 b, l, c, v;
    UINT32 ibyt;
    UINT32 owrd;
    UINT32 value, length;
    SINT32 *l_out = out;

    b = BAC_64_LOWER_BOUND;                    // lower bound
    l = BAC_64_RANGE;                          // range

    SINT32 num_bits = utils_entropy.pack_get_bits(packer);
    packer->read(packer, &value, num_bits & 0x7);  // byte alignment
    packer->read(packer, &value, 8);        // header
    packer->read(packer, &length, 8);       // header
    length += value << 8;

    // Read 64 bits
    if (SC_FUNC_FAILURE == packer->read(packer, &ibyt, 32)) {
        return SC_FUNC_FAILURE;
    }
    v = (UINT64) ibyt;
    v <<= 32;
    if (SC_FUNC_FAILURE == packer->read(packer, &ibyt, 32)) {
        return SC_FUNC_FAILURE;
    }
    v |= (UINT64) ibyt;
    ibyt = 0;
    icnt = 0;
    iptr = 8;

    for (optr=outlen; optr--;) {

        owrd = 0;
        for (ocnt = bits; ocnt--;) {

            // Midpoint split
            c = dist[(owrd & (BAC_64_MID_LSB_MASK << ocnt)) | (1 << ocnt)];
            c = mul64hi(l, c);              // scale to range

            if (v - b < c) {                // compare
                l = c;                      // 0 bit; lower part
            }
            else {
                b += c;                     // 1 bit; higher part
                l -= c;                     // flip range to upper half
                owrd |= 1 << ocnt;          // set the bit
            }

            while (l < BAC_64_RANGE_MSB) {

                icnt--;                     // fetch a new bit
                if (icnt < 0 && iptr < (SINT32)length) {
                    if (SC_FUNC_FAILURE == packer->read(packer, &ibyt, 8)) {     // insert zeros is over buffer
                        ibyt = 0;
                    }
                    iptr++;
                    icnt = 7;
                }
                v <<= 1;                    // add bit to v
                v += (ibyt >> icnt) & 1;

                b <<= 1;                    // shift left
                l <<= 1;                    // double range
            }
        }

        *l_out++ = owrd - offset;          // have full output byte
    }

    return SC_FUNC_SUCCESS;
}


SINT32 bac_encode_64_16(sc_packer_t *packer, const SINT16 *in, size_t inlen,
    const UINT64 *dist, SINT32 bits, SINT32 offset)
{
    SINT32 iptr, icnt, optr, ocnt;
    UINT32 data;                          // output byte; can handle carry
    UINT32 iwrd;                          // input word
    UINT64 b, l, c;                       // range variables
    UINT8 *buffer, *bufhdr;
    SINT16 *l_in = (SINT16*)in;

    // Flush the packer to obtain byte alignment
    utils_entropy.pack_flush(packer);

    bufhdr = utils_entropy.pack_get_write_ptr(packer);
    if (SC_FUNC_FAILURE == packer->write(packer, 0x0000, 16)) {
        return SC_FUNC_FAILURE;
    }
    utils_entropy.pack_flush(packer);
    buffer = utils_entropy.pack_get_write_ptr(packer);

    b = BAC_64_LOWER_BOUND;                 // lower bound
    l = BAC_64_RANGE;                       // range

    data = 0;                               // (partial) output byte
    ocnt = 0;                               // bit count 0..7
    optr = 0;

    for (iptr=inlen; iptr--;) {

        iwrd = offset + *l_in++;

        for (icnt = bits; icnt--;) {

            // Midpoint split
            c = dist[(iwrd & (BAC_64_MID_LSB_MASK << icnt)) | (1 << icnt)];
            c = mul64hi(l, c);              // scale to range

            if (0 == ((iwrd >> icnt) & 1)) {
                l = c;                      // 0 bit; lower part
            }
            else {
                b += c;                     // 1 bit; higher part
                l -= c;                     // flip range to upper half
                if (b < c) {                // overflow ?
                    data++;                 // carry
                }
            }

            // Norrmalize and output bits whilst the range is within bounds
            if (l) {
            while (l < BAC_64_RANGE_MSB) {
                data <<= 1;
                data |= (b >> 63) & 1;
                ocnt++;
                if (ocnt >= 8) {            // full byte ?
                    if (SC_FUNC_FAILURE == packer->write(packer, data & BYTE_MASK, 8)) {
                        return SC_FUNC_FAILURE;
                    }
                    utils_entropy.pack_flush(packer);
                    carry_propagation(optr, data, buffer);
                    optr++;
                    ocnt = 0;
                    data = 0;
                }

                b <<= 1;                    // shift left
                l <<= 1;                    // double range
            }
            }
        }
    }

    while (ocnt < 8) {                      // flush output byte
        data = (data << 1) ^ (b >> 63);
        b <<= 1;
        ocnt++;
    }

    if (SC_FUNC_FAILURE == packer->write(packer, data, 8)) {  // final carry
        return SC_FUNC_FAILURE;
    } 
    utils_entropy.pack_flush(packer);
    carry_propagation(optr, data, buffer);
    optr++;
    while (0 != b) {
        if (SC_FUNC_FAILURE == packer->write(packer, b >> 56, 8)) {
            return SC_FUNC_FAILURE;
        }
        b <<= 8;
        optr++;
    }

    // Assign the length of the encoded stream
    bufhdr[0] = optr >> 8;
    bufhdr[1] = optr & BYTE_MASK;

    return SC_FUNC_SUCCESS;
}

SINT32 bac_decode_64_16(sc_packer_t *packer, SINT16 *out, size_t outlen,
    const UINT64 *dist, SINT32 bits, SINT32 offset)
{
    SINT32 iptr, icnt, optr, ocnt;
    UINT64 b, l, c, v;
    UINT32 ibyt;
    UINT32 owrd;
    UINT32 value, length;
    SINT16 *l_out = out;

    b = BAC_64_LOWER_BOUND;                    // lower bound
    l = BAC_64_RANGE;                          // range

    SINT32 num_bits = utils_entropy.pack_get_bits(packer);
    packer->read(packer, &value, num_bits & 0x7);  // byte alignment
    packer->read(packer, &value, 8);        // header
    packer->read(packer, &length, 8);       // header
    length += value << 8;

    // Read 64 bits
    if (SC_FUNC_FAILURE == packer->read(packer, &ibyt, 32)) {
        return SC_FUNC_FAILURE;
    }
    v = (UINT64) ibyt;
    v <<= 32;
    if (SC_FUNC_FAILURE == packer->read(packer, &ibyt, 32)) {
        return SC_FUNC_FAILURE;
    }
    v |= (UINT64) ibyt;
    ibyt = 0;
    icnt = 0;
    iptr = 8;

    for (optr=outlen; optr--;) {

        owrd = 0;
        for (ocnt = bits; ocnt--;) {

            // Midpoint split
            c = dist[(owrd & (BAC_64_MID_LSB_MASK << ocnt)) | (1 << ocnt)];
            c = mul64hi(l, c);              // scale to range

            if (v - b < c) {                // compare
                l = c;                      // 0 bit; lower part
            }
            else {
                b += c;                     // 1 bit; higher part
                l -= c;                     // flip range to upper half
                owrd |= 1 << ocnt;          // set the bit
            }

            while (l < BAC_64_RANGE_MSB) {

                icnt--;                     // fetch a new bit
                if (icnt < 0 && iptr < (SINT32)length) {
                    if (SC_FUNC_FAILURE == packer->read(packer, &ibyt, 8)) {     // insert zeros is over buffer
                        ibyt = 0;
                    }
                    iptr++;
                    icnt = 7;
                }
                v <<= 1;                    // add bit to v
                v += (ibyt >> icnt) & 1;

                b <<= 1;                    // shift left
                l <<= 1;                    // double range
            }
        }
        
        *l_out++ = owrd - offset;          // have full output byte
    }

    return SC_FUNC_SUCCESS;
}
