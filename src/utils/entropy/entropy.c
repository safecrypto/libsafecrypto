/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2017                      *
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

#include "entropy.h"
#include "packer.h"
#include "bac.h"
#include "entropy_huffman.h"
#include "entropy_raw.h"


SINT32 entropy_dist_create(safecrypto_t *sc, sc_entropy_type_e type,
    size_t dist, FLOAT sigma, size_t n)
{
    if (NULL == sc) {
        return SC_ERROR;
    }

    if (dist >= ENTROPY_MAX_DIST) {
        return SC_ERROR;
    }

    // Initialise the distribution pointer to NULL (i.e. unused)
    sc->dist[dist] = NULL;

    if (SC_ENTROPY_BAC == type) {
        sc->dist[dist] = SC_MALLOC((1 << n) * sizeof(UINT64));
        if (NULL == sc->dist[dist]) {
            return SC_ERROR;
        }

        sc->dist_n[dist] = n;
        gauss_freq_bac_64(sc->dist[dist], sigma, 1 << n);
    }

    return SC_OK;
}

SINT32 entropy_dist_destroy(safecrypto_t *sc, size_t dist)
{
    if (NULL == sc) {
        return SC_ERROR;
    }

    if (dist >= ENTROPY_MAX_DIST) {
        return SC_ERROR;
    }

    if (NULL != sc->dist[dist]) {
        SC_FREE(sc->dist[dist], (1 << sc->dist_n[dist]) * sizeof(UINT64));
    }

    return SC_OK;
}


SINT32 entropy_poly_encode_32(sc_packer_t *packer, size_t n, const SINT32 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits)
{
    SINT32 retval;
    if (NULL == packer) {
        return SC_NULL_POINTER;
    }

    size_t coded = utils_entropy.pack_get_bits(packer);

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
		if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
			retval = encode_huffman_unsigned_32(packer, n, p, bits - beta, beta);
		}
		else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
			retval = encode_huffman_signed_32(packer, n, p, bits - beta, beta);
		}
	}
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_encode_64_32(packer, p, n, packer->sc->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
	else {
		retval = encode_raw_32(packer, n, p, bits);
	}

    if (NULL != coded_bits) {
        *coded_bits += utils_entropy.pack_get_bits(packer) - coded;
    }
    return retval;
}

SINT32 entropy_poly_decode_32(sc_packer_t *packer, size_t n, SINT32 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_NULL_POINTER;
    }

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
    	if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
	    	retval = decode_huffman_unsigned_32(packer, n, p, bits - beta, beta);
	    }
	    else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
    		retval = decode_huffman_signed_32(packer, n, p, bits - beta, beta);
    	}
    }
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_decode_64_32(packer, p, n, packer->sc->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
    else {
    	if (UNSIGNED_COEFF == signedness) {
	    	retval = decode_raw_unsigned_32(packer, n, p, bits);
	    }
	    else {
    		retval = decode_raw_signed_32(packer, n, p, bits);
    	}
    }

    return retval;
}

SINT32 entropy_poly_encode_16(sc_packer_t *packer, size_t n, const SINT16 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_NULL_POINTER;
    }

    size_t coded = utils_entropy.pack_get_bits(packer);

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
		if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
			retval = encode_huffman_unsigned_16(packer, n, p, bits - beta, beta);
		}
		else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
			retval = encode_huffman_signed_16(packer, n, p, bits - beta, beta);
		}
	}
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_encode_64_16(packer, p, n, packer->sc->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
	else {
		retval = encode_raw_16(packer, n, p, bits);
	}

    if (NULL != coded_bits) {
        *coded_bits += utils_entropy.pack_get_bits(packer) - coded;
    }
    return retval;
}

SINT32 entropy_poly_decode_16(sc_packer_t *packer, size_t n, SINT16 *p,
	size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_NULL_POINTER;
    }

	if (SC_ENTROPY_HUFFMAN_STATIC == type) {
    	if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
	    	retval = decode_huffman_unsigned_16(packer, n, p, bits - beta, beta);
	    }
	    else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
    		retval = decode_huffman_signed_16(packer, n, p, bits - beta, beta);
    	}
    }
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_decode_64_16(packer, p, n, packer->sc->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
    else {
		if (UNSIGNED_COEFF == signedness) {
    		retval = decode_raw_unsigned_16(packer, n, p, bits);
    	}
    	else {
	    	retval = decode_raw_signed_16(packer, n, p, bits);
	    }
	}

    return retval;
}

SINT32 entropy_poly_encode_8(sc_packer_t *packer, size_t n, const SINT8 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type,
    size_t dist, size_t *coded_bits)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_NULL_POINTER;
    }

    size_t coded = utils_entropy.pack_get_bits(packer);

    if (SC_ENTROPY_HUFFMAN_STATIC == type) {
        if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
            retval = encode_huffman_unsigned_8(packer, n, p, bits - beta, beta);
        }
        else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
            retval = encode_huffman_signed_8(packer, n, p, bits - beta, beta);
        }
    }
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_encode_64_8(packer, p, n, packer->sc->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
    else {
        retval = encode_raw_8(packer, n, p, bits);
    }

    if (NULL != coded_bits) {
        *coded_bits += utils_entropy.pack_get_bits(packer) - coded;
    }
    return retval;
}

SINT32 entropy_poly_decode_8(sc_packer_t *packer, size_t n, SINT8 *p,
    size_t bits, entropy_sign_e signedness, sc_entropy_type_e type, size_t dist)
{
    SINT32 retval;

    if (NULL == packer) {
        return SC_NULL_POINTER;
    }

    if (SC_ENTROPY_HUFFMAN_STATIC == type) {
        if (UNSIGNED_COEFF == signedness) {
            SINT32 beta = bits - 7;
            if (beta < 0) beta = 0;
            retval = decode_huffman_unsigned_8(packer, n, p, bits - beta, beta);
        }
        else {
            SINT32 beta = bits - 6;
            if (beta < 0) beta = 0;
            retval = decode_huffman_signed_8(packer, n, p, bits - beta, beta);
        }
    }
    else if (SC_ENTROPY_BAC == type) {
        SINT32 offset = 0;
        if (SIGNED_COEFF == signedness) {
            offset = 1 << (bits - 1);
        }
        retval = bac_decode_64_8(packer, p, n, packer->sc->dist[dist], bits, offset);
        retval = (SC_FUNC_SUCCESS == retval)? SC_OK : SC_ERROR;
    }
    else {
        if (UNSIGNED_COEFF == signedness) {
            retval = decode_raw_unsigned_8(packer, n, p, bits);
        }
        else {
            retval = decode_raw_signed_8(packer, n, p, bits);
        }
    }

    return retval;
}
