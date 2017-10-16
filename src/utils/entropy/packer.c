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

#include "packer.h"
#if defined(__linux__) || defined(_WIN32)
#include <arpa/inet.h>
#else

uint32_t htonl(uint32_t hostlong)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return hostlong;
#else
    return ((hostlong & 0xff        ) << 24) |
           ((hostlong & 0xff00      ) <<  8) |
           ((hostlong & 0xff0000UL  ) >>  8) |
           ((hostlong & 0xff000000UL) >> 24);
#endif
}

uint32_t ntohl(uint32_t netlong)
{
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
    return netlong;
#else
    return ((netlong & 0xff        ) << 24) |
           ((netlong & 0xff00      ) <<  8) |
           ((netlong & 0xff0000UL  ) >>  8) |
           ((netlong & 0xff000000UL) >> 24);
#endif
}

#endif



static SINT32 peek_bits(sc_packer_t *packer, UINT32 *value, size_t bits);
static SINT32 read_bits(sc_packer_t *packer, UINT32 *value, size_t bits);
static SINT32 write_bits(sc_packer_t *packer, UINT32 value, size_t bits);


static inline UINT32 u8_to_u32(void *network)
{
    UINT8 *unaligned = (UINT8*) network;
    UINT32 tmp;

    memcpy(&tmp, unaligned, sizeof(tmp));
    return ntohl(tmp);
}

static inline UINT32 u32_to_u8(void *network, UINT32 host)
{
    UINT8 *unaligned = (UINT8*) network;

    host = htonl(host);
    memcpy((UINT8 *) unaligned, &host, sizeof(host));
    return SC_FUNC_SUCCESS;
}

static sc_packer_t * create(safecrypto_t *sc, sc_entropy_t *coder,
    size_t max_bits, const UINT8 *ibuffer, size_t ilen,
    UINT8 **obuffer, size_t *olen)
{
    (void) coder;
    SINT32 use_internal_buffer = (NULL == obuffer) || (0 == *olen);

    // Allocate the maximum number of bits rounded up to the nearest factor of 32
    size_t max_bytes;
    if (use_internal_buffer) {
        max_bytes = (max_bits + 7) >> 3;
        if (ilen > max_bytes) max_bytes = ilen;
        max_bytes = ((max_bytes + 3) >> 2) << 2;
    }
    else {
        // If the fixed length buffer is too small then return NULL
        max_bytes = *olen;
        if (NULL == *obuffer || (max_bits>>3) > *olen) {
            return NULL;
        }
    }

    // Create an instance of the packer
    sc_packer_t *packer = SC_MALLOC(sizeof(sc_packer_t));
    if (NULL == packer) {
        return NULL;
    }

    // Indicate if an external buffer is to be used
    packer->use_internal_buffer = use_internal_buffer;

    // Assign memory or the output buffer pointer to the packer
    if (use_internal_buffer) {
        packer->buffer = SC_MALLOC(max_bytes);
        if (NULL == packer->buffer) {
            return NULL;
        }
    }
    else {
        packer->buffer = *obuffer;
    }

    // If the buffer is not to be filled from the input arguments then initialise
    // it as empty, otherwise the buffer should be filled and the 32-bit scratch
    // buffer initialised as empty.
    if (NULL == ibuffer || 0 == ilen) {
        packer->bits        = max_bytes << 3;
        packer->bits_left   = 32; // i.e. 32 bits left to fill
        packer->scratch     = 0;
        packer->head        = 0;
        packer->tail        = 0;
    }
    else {
        packer->bits        = max_bytes << 3;
        packer->bits_left   = 0; // i.e. empty
        packer->scratch     = 0;
        packer->head        = max_bytes;
        packer->tail        = 0;

        // Copy the input buffer
        memcpy(packer->buffer, ibuffer, ilen);
    }

    // Initialise the remaining variables
    packer->buffer_alloc = max_bytes;
    packer->sc           = sc;
    packer->peek         = peek_bits;
    packer->read         = read_bits;
    packer->write        = write_bits;
    packer->bits_in      = 0;
    packer->bits_out     = 0;

    return packer;
}

static SINT32 destroy(sc_packer_t **packer)
{
    if (NULL == packer) {
        return SC_FUNC_FAILURE;
    }

    sc_packer_t *l_packer = *packer;

    if (NULL == l_packer) {
        return SC_FUNC_FAILURE;
    }

    SINT32 max_bytes = l_packer->buffer_alloc;
    if (l_packer->use_internal_buffer) {
        SC_FREE(l_packer->buffer, max_bytes);
    }
    SC_FREE(*packer, sizeof(sc_packer_t));

    return SC_FUNC_SUCCESS;
}

static SINT32 peek_bits(sc_packer_t *packer, UINT32 *value, size_t bits)
{
    *value = 0;

    if (0 == bits) {
        return SC_FUNC_SUCCESS;
    }

    if (packer->tail > ((packer->bits >> 3) - 4)) {
        return SC_FUNC_FAILURE;
    }

    size_t bits_left = packer->bits_left;
    UINT32 scratch   = packer->scratch;
    if (bits > bits_left) {
        scratch = (scratch << (bits - bits_left)) | (u8_to_u32(packer->buffer + packer->tail) >> (bits_left - bits));
        bits_left = 32;
    }

    *value = scratch >> (bits_left - bits);
    return SC_FUNC_SUCCESS;
}

static SINT32 read_bits(sc_packer_t *packer, UINT32 *value, size_t bits)
{
    *value = 0;

    if (0 == bits) {
        return SC_FUNC_SUCCESS;
    }

    for(;;) {
        if (packer->bits_left == 0) {
            if (packer->tail > ((packer->bits >> 3) - 4)) {
                return SC_FUNC_FAILURE;
            }

            packer->scratch     = u8_to_u32(packer->buffer + packer->tail);
            packer->tail       += 4;
            packer->head       -= 4;
            packer->bits_left   = 32;
        }

        if (bits <= packer->bits_left) {
            *value |= packer->scratch >> (packer->bits_left - bits);
            packer->scratch &= (1 << (packer->bits_left - bits)) - 1;
            packer->bits_left -= bits;
            packer->bits_out += bits;
            return SC_FUNC_SUCCESS;
        }

        *value |= packer->scratch << (bits - packer->bits_left);
        bits -= packer->bits_left;
        packer->bits_left = 0;
    }
}

static SINT32 write_bits(sc_packer_t *packer, UINT32 value, size_t bits)
{
    // Verify that there is sufficient space in the output buffer to continue
    if (packer->head > ((packer->bits >> 3) - 4)) {
        return SC_FUNC_FAILURE;
    }

    // Mask the value to exclude unwanted bits
    value &= 0xFFFFFFFF >> (32 - bits);

    packer->bits += bits;

    // If the number of bits to be written is less than that available in the
    // scratch buffer then write the data and return
    if (bits <= packer->bits_left) {
        packer->scratch   |= value << (packer->bits_left - bits);
        packer->bits_left -= bits;
        packer->bits_in   += bits;
        return SC_FUNC_SUCCESS;
    }

    // Update the scratch buffer to fill it and update the input data
    packer->scratch |= value >> (bits - packer->bits_left);

    // Copy the 32-bit scratch buffer contents to the output buffer
    u32_to_u8(packer->buffer + packer->head, packer->scratch);
    packer->head       += 4;
    packer->bits_in    += bits;
    bits                = 32 - bits + packer->bits_left;
    packer->scratch     = value << bits;
    packer->bits_left   = bits;
    return SC_FUNC_SUCCESS;
}

static SINT32 flush(sc_packer_t *packer)
{
    // Flush any outstanding bits in the flash buffer to the output buffer
    if (packer->bits_left < 32) {
        SINT32 num_bytes = (32 - packer->bits_left + 7) >> 3;
        packer->bits_out += num_bytes << 3;

        if (packer->head > ((packer->bits >> 3) - num_bytes)) {
            return SC_FUNC_FAILURE;
        }

        u32_to_u8(packer->buffer + packer->head, packer->scratch);
        packer->head       += num_bytes;
        packer->scratch     = 0;
        packer->bits_left   = 32;
    }

    return SC_FUNC_SUCCESS;
}

static size_t is_data_avail(sc_packer_t *packer)
{
    return packer->tail <= ((packer->bits >> 3) - 4);
}

static size_t get_bits(sc_packer_t *packer)
{
    return packer->bits;
}

static SINT32 get_buffer(sc_packer_t *packer, UINT8 **buffer, size_t *len)
{
    // Flush the buffer
    if (SC_FUNC_FAILURE == flush(packer)) {
        return SC_FUNC_FAILURE;
    }

    // Assign the output buffer arguments
    *buffer = packer->buffer;
    *len    = packer->head;

    if (packer->use_internal_buffer) {
        // Allocate resources for a new buffer
        SINT32 max_bytes = (((packer->bits + 31)>>5)<<2);
        packer->buffer = SC_MALLOC(max_bytes);
        if (NULL == packer->buffer) {
            return SC_FUNC_FAILURE;
        }
    }

    packer->bits_left  = 32;
    packer->scratch    = 0;
    packer->head       = 0;
    packer->tail       = 0;

    return SC_FUNC_SUCCESS;
}

SINT32 encode(sc_packer_t *packer, UINT32 value, size_t bits)
{
    return packer->write(packer, value, bits);
}

SINT32 push(sc_packer_t *packer, UINT32 value, size_t bits)
{
    return write_bits(packer, value, bits);
}

SINT32 decode(sc_packer_t *packer, UINT32 *value, size_t bits)
{
    return packer->read(packer, value, bits);
}

SINT32 pull(sc_packer_t *packer, UINT32 *value, size_t bits)
{
    return read_bits(packer, value, bits);
}

UINT8* get_write_ptr(sc_packer_t *packer)
{
    return packer->buffer + packer->head;
}

SINT32 reset_io_count(sc_packer_t *packer)
{
    packer->bits_in = 0;
    packer->bits_out = 0;
    return SC_FUNC_SUCCESS;
}

SINT32 get_bits_in(sc_packer_t *packer)
{
    return packer->bits_in;
}

SINT32 get_bits_out(sc_packer_t *packer)
{
    return packer->bits_out;
}

utils_entropy_t utils_entropy = {
    create, destroy, encode, decode, push, pull, flush, is_data_avail, get_bits, get_buffer, get_write_ptr,
    reset_io_count, get_bits_in, get_bits_out
};


