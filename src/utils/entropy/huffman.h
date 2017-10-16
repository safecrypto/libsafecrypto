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

#pragma once

#include "packer.h"


SC_STRUCT_PACK_START
typedef struct huffman_code_t {
    UINT32 code;
    UINT16 bits;
} SC_STRUCT_PACKED huffman_code_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct huffman_code_64_t {
    UINT64 code;
    UINT16 bits;
} SC_STRUCT_PACKED huffman_code_64_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct huffman_node_t {
	SINT16 left;
	SINT16 right;
} SC_STRUCT_PACKED huffman_node_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct huffman_table_t {
    const huffman_code_t *codes;
    const huffman_code_64_t *codes_64;
    const huffman_node_t *nodes;
    UINT32 depth;
    UINT32 max_bits;
} SC_STRUCT_PACKED huffman_table_t;
SC_STRUCT_PACK_END

// Generated from Matlab/Octave using 2 bits and sigma=0.800000
static const huffman_code_t huff_code_gaussian_2[] = {
    { 0x00000001,    1 },
    { 0x00000001,    2 },
    { 0x00000001,    3 },
    { 0x00000000,    3 },
};
static const huffman_node_t huff_node_gaussian_2[] = {
    {   1,    6  },
    {   2,    5  },
    {   3,    4  },
    {  -1,    3  },
    {  -1,    2  },
    {  -1,    1  },
    {  -1,    0  },
};
static const huffman_table_t huff_table_gaussian_2[] = {
    {huff_code_gaussian_2, NULL, huff_node_gaussian_2, 4, 3}
};

// Generated from Matlab/Octave using 3 bits and sigma=0.400000
static const huffman_code_t huff_code_gaussian_3[] = {
    { 0x00000001,    1 },
    { 0x00000001,    2 },
    { 0x00000001,    3 },
    { 0x00000001,    4 },
    { 0x00000001,    5 },
    { 0x00000001,    6 },
    { 0x00000001,    7 },
    { 0x00000000,    7 },
};
static const huffman_node_t huff_node_gaussian_3[] = {
    {   1,   14  },
    {   2,   13  },
    {   3,   12  },
    {   4,   11  },
    {   5,   10  },
    {   6,    9  },
    {   7,    8  },
    {  -1,    7  },
    {  -1,    6  },
    {  -1,    5  },
    {  -1,    4  },
    {  -1,    3  },
    {  -1,    2  },
    {  -1,    1  },
    {  -1,    0  },
};
static const huffman_table_t huff_table_gaussian_3[] = {
    {huff_code_gaussian_3, NULL, huff_node_gaussian_3, 8, 7}
};

// Generated from Matlab/Octave using 4 bits and sigma=0.800000
static const huffman_code_t huff_code_gaussian_4[] = {
    { 0x00000001,    1 },
    { 0x00000001,    2 },
    { 0x00000001,    3 },
    { 0x00000001,    4 },
    { 0x00000001,    5 },
    { 0x00000001,    6 },
    { 0x00000001,    7 },
    { 0x00000001,    8 },
    { 0x00000001,    9 },
    { 0x00000001,   10 },
    { 0x00000001,   11 },
    { 0x00000001,   12 },
    { 0x00000001,   13 },
    { 0x00000001,   14 },
    { 0x00000001,   15 },
    { 0x00000000,   15 },
};
static const huffman_node_t huff_node_gaussian_4[] = {
    {   1,   30  },
    {   2,   29  },
    {   3,   28  },
    {   4,   27  },
    {   5,   26  },
    {   6,   25  },
    {   7,   24  },
    {   8,   23  },
    {   9,   22  },
    {  10,   21  },
    {  11,   20  },
    {  12,   19  },
    {  13,   18  },
    {  14,   17  },
    {  15,   16  },
    {  -1,   15  },
    {  -1,   14  },
    {  -1,   13  },
    {  -1,   12  },
    {  -1,   11  },
    {  -1,   10  },
    {  -1,    9  },
    {  -1,    8  },
    {  -1,    7  },
    {  -1,    6  },
    {  -1,    5  },
    {  -1,    4  },
    {  -1,    3  },
    {  -1,    2  },
    {  -1,    1  },
    {  -1,    0  },
};
static const huffman_table_t huff_table_gaussian_4[] = {
    {huff_code_gaussian_4, NULL, huff_node_gaussian_4, 16, 15}
};

// Generated from Matlab/Octave using 5 bits and sigma=1.600000
static const huffman_code_t huff_code_gaussian_5[] = {
    { 0x00000000,    1 },
    { 0x00000003,    2 },
    { 0x00000005,    3 },
    { 0x00000009,    4 },
    { 0x00000011,    5 },
    { 0x00000021,    6 },
    { 0x00000041,    7 },
    { 0x00000081,    8 },
    { 0x00000101,    9 },
    { 0x00000201,   10 },
    { 0x00000401,   11 },
    { 0x00000801,   12 },
    { 0x00001001,   13 },
    { 0x00002001,   14 },
    { 0x00004001,   15 },
    { 0x00008001,   16 },
    { 0x00010001,   17 },
    { 0x00020001,   18 },
    { 0x00040001,   19 },
    { 0x00080001,   20 },
    { 0x00100001,   21 },
    { 0x00200001,   22 },
    { 0x00400001,   23 },
    { 0x00800001,   24 },
    { 0x01000001,   25 },
    { 0x02000001,   26 },
    { 0x04000001,   27 },
    { 0x08000001,   28 },
    { 0x10000001,   29 },
    { 0x20000001,   30 },
    { 0x40000001,   31 },
    { 0x40000000,   31 },
};
static const huffman_node_t huff_node_gaussian_5[] = {
    {   1,    2  },
    {  -1,    0  },
    {   3,   62  },
    {   4,   61  },
    {   5,   60  },
    {   6,   59  },
    {   7,   58  },
    {   8,   57  },
    {   9,   56  },
    {  10,   55  },
    {  11,   54  },
    {  12,   53  },
    {  13,   52  },
    {  14,   51  },
    {  15,   50  },
    {  16,   49  },
    {  17,   48  },
    {  18,   47  },
    {  19,   46  },
    {  20,   45  },
    {  21,   44  },
    {  22,   43  },
    {  23,   42  },
    {  24,   41  },
    {  25,   40  },
    {  26,   39  },
    {  27,   38  },
    {  28,   37  },
    {  29,   36  },
    {  30,   35  },
    {  31,   34  },
    {  32,   33  },
    {  -1,   31  },
    {  -1,   30  },
    {  -1,   29  },
    {  -1,   28  },
    {  -1,   27  },
    {  -1,   26  },
    {  -1,   25  },
    {  -1,   24  },
    {  -1,   23  },
    {  -1,   22  },
    {  -1,   21  },
    {  -1,   20  },
    {  -1,   19  },
    {  -1,   18  },
    {  -1,   17  },
    {  -1,   16  },
    {  -1,   15  },
    {  -1,   14  },
    {  -1,   13  },
    {  -1,   12  },
    {  -1,   11  },
    {  -1,   10  },
    {  -1,    9  },
    {  -1,    8  },
    {  -1,    7  },
    {  -1,    6  },
    {  -1,    5  },
    {  -1,    4  },
    {  -1,    3  },
    {  -1,    2  },
    {  -1,    1  },
};
static const huffman_table_t huff_table_gaussian_5[] = {
    {huff_code_gaussian_5, NULL, huff_node_gaussian_5, 32, 31}
};

// Generated from Matlab/Octave using 6 bits and sigma=12.800000
static const huffman_code_t huff_code_gaussian_6[] = {
    { 0x0000000A,    4 },
    { 0x00000009,    4 },
    { 0x00000008,    4 },
    { 0x00000007,    4 },
    { 0x00000006,    4 },
    { 0x00000005,    4 },
    { 0x00000003,    4 },
    { 0x00000002,    4 },
    { 0x00000001,    4 },
    { 0x0000001F,    5 },
    { 0x0000001E,    5 },
    { 0x0000001C,    5 },
    { 0x0000001B,    5 },
    { 0x00000019,    5 },
    { 0x00000018,    5 },
    { 0x00000016,    5 },
    { 0x00000008,    5 },
    { 0x00000001,    5 },
    { 0x0000003B,    6 },
    { 0x00000035,    6 },
    { 0x00000034,    6 },
    { 0x0000002E,    6 },
    { 0x00000012,    6 },
    { 0x00000000,    6 },
    { 0x00000075,    7 },
    { 0x0000005F,    7 },
    { 0x00000027,    7 },
    { 0x00000003,    7 },
    { 0x00000002,    7 },
    { 0x000000E8,    8 },
    { 0x000000BC,    8 },
    { 0x0000004C,    8 },
    { 0x000001D2,    9 },
    { 0x0000017A,    9 },
    { 0x0000009B,    9 },
    { 0x000003A7,   10 },
    { 0x000002F7,   10 },
    { 0x00000135,   10 },
    { 0x0000074D,   11 },
    { 0x000005ED,   11 },
    { 0x00000269,   11 },
    { 0x00000E99,   12 },
    { 0x00000BD9,   12 },
    { 0x00000BD8,   12 },
    { 0x000004D0,   12 },
    { 0x00001D30,   13 },
    { 0x000009A2,   13 },
    { 0x00003A62,   14 },
    { 0x00001346,   14 },
    { 0x000074C6,   15 },
    { 0x0000268E,   15 },
    { 0x0000E98E,   16 },
    { 0x00004D1E,   16 },
    { 0x0001D31F,   17 },
    { 0x00009A3F,   17 },
    { 0x0003A63D,   18 },
    { 0x0001347D,   18 },
    { 0x00074C79,   19 },
    { 0x000268F9,   19 },
    { 0x000E98F1,   20 },
    { 0x000E98F0,   20 },
    { 0x0004D1F0,   20 },
    { 0x0009A3E3,   21 },
    { 0x0009A3E2,   21 },
};
static const huffman_node_t huff_node_gaussian_6[] = {
    {   1,   56  },
    {   2,   15  },
    {   3,   12  },
    {   4,   11  },
    {   5,   10  },
    {   6,    7  },
    {  -1,   23  },
    {   8,    9  },
    {  -1,   28  },
    {  -1,   27  },
    {  -1,   17  },
    {  -1,    8  },
    {  13,   14  },
    {  -1,    7  },
    {  -1,    6  },
    {  16,   53  },
    {  17,   52  },
    {  18,   19  },
    {  -1,   16  },
    {  20,   21  },
    {  -1,   22  },
    {  22,   51  },
    {  23,   24  },
    {  -1,   31  },
    {  25,   50  },
    {  26,   49  },
    {  27,   48  },
    {  28,   29  },
    {  -1,   44  },
    {  30,   31  },
    {  -1,   46  },
    {  32,   33  },
    {  -1,   48  },
    {  34,   35  },
    {  -1,   50  },
    {  36,   37  },
    {  -1,   52  },
    {  38,   47  },
    {  39,   46  },
    {  40,   45  },
    {  41,   42  },
    {  -1,   61  },
    {  43,   44  },
    {  -1,   63  },
    {  -1,   62  },
    {  -1,   58  },
    {  -1,   56  },
    {  -1,   54  },
    {  -1,   40  },
    {  -1,   37  },
    {  -1,   34  },
    {  -1,   26  },
    {  -1,    5  },
    {  54,   55  },
    {  -1,    4  },
    {  -1,    3  },
    {  57,   80  },
    {  58,   61  },
    {  59,   60  },
    {  -1,    2  },
    {  -1,    1  },
    {  62,   63  },
    {  -1,    0  },
    {  64,   65  },
    {  -1,   15  },
    {  66,   67  },
    {  -1,   21  },
    {  68,   79  },
    {  69,   70  },
    {  -1,   30  },
    {  71,   72  },
    {  -1,   33  },
    {  73,   78  },
    {  74,   77  },
    {  75,   76  },
    {  -1,   43  },
    {  -1,   42  },
    {  -1,   39  },
    {  -1,   36  },
    {  -1,   25  },
    {  81,   90  },
    {  82,   85  },
    {  83,   84  },
    {  -1,   14  },
    {  -1,   13  },
    {  86,   89  },
    {  87,   88  },
    {  -1,   20  },
    {  -1,   19  },
    {  -1,   12  },
    {  91,  124  },
    {  92,   93  },
    {  -1,   11  },
    {  94,  123  },
    {  95,  122  },
    {  96,   97  },
    {  -1,   29  },
    {  98,   99  },
    {  -1,   32  },
    { 100,  121  },
    { 101,  120  },
    { 102,  119  },
    { 103,  104  },
    {  -1,   45  },
    { 105,  106  },
    {  -1,   47  },
    { 107,  108  },
    {  -1,   49  },
    { 109,  110  },
    {  -1,   51  },
    { 111,  118  },
    { 112,  117  },
    { 113,  116  },
    { 114,  115  },
    {  -1,   60  },
    {  -1,   59  },
    {  -1,   57  },
    {  -1,   55  },
    {  -1,   53  },
    {  -1,   41  },
    {  -1,   38  },
    {  -1,   35  },
    {  -1,   24  },
    {  -1,   18  },
    { 125,  126  },
    {  -1,   10  },
    {  -1,    9  },
};
static const huffman_table_t huff_table_gaussian_6[] = {
    {huff_code_gaussian_6, NULL, huff_node_gaussian_6, 64, 21}
};

/** @brief Encode a value using the specified Huffman encoder
 *
 *  @param packer A pointer to the bit packing struct
 *  @param table A pointer to the Huffman entropy coding struct
 *  @param value The unsigned 32-bit value to be encoded into the byte stream
 *  @return A detailed error code
 */
SINT32 encode_huffman(sc_packer_t *packer, const huffman_table_t *table, UINT32 value);

/** @brief Decode a value using the specified Huffman decoder
 *
 *  @param packer A pointer to the bit packing struct
 *  @param table A pointer to the Huffman entropy coding struct
 *  @param value The unsigned 32-bit value to be decoded from the byte stream
 *  @return A detailed error code
 */
SINT32 decode_huffman(sc_packer_t *packer, const huffman_table_t *table, UINT32 *value);

/** @brief Generate a Huffman node LUT for use as a Gaussian sampler
 *
 *  @param bits The desired bit width of the output samples
 *  @param sigma The standard deviation of the distribution
 *  @return A pointer to the Huffman table to be used for sampling purposes
 */
huffman_table_t * create_huffman_gaussian_sampler(SINT32 bits, FLOAT sigma);

/// Free all resources associated with the given Huffman tables
SINT32 destroy_huffman(huffman_table_t **table);

/** @brief A random gaussian sampler that uses the specified Huffman decoder
 *
 *  @param prng_ctx A pointer to the prng_ctx_t struct
 *  @param table A pointer to the Huffman entropy coding struct
 *  @param value The unsigned 32-bit value to be sampled from the distribution
 *               encoded into the Huffman table
 *  @return A detailed error code
 */
SINT32 sample_huffman(prng_ctx_t *prng_ctx, const huffman_table_t *table,
    SINT32 *value);

