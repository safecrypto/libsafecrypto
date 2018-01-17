/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2018                      *
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

#include <stdint.h>
#include "safecrypto_private.h"
#include "hash.h"


typedef struct _ec_set_t ec_set_t;
typedef struct _ecdh_cfg_t ecdh_cfg_t;


/// Scheme creation
SINT32 ecdh_create(safecrypto_t *sc, SINT32 set, const UINT32 *flags);

/// Scheme destruction
SINT32 ecdh_destroy(safecrypto_t *sc);

/// Diffie-Hellman message initial exchange
SINT32 ecdh_diffie_hellman_init(safecrypto_t *sc, size_t *tlen, UINT8 **to);

/// Diffie-Hellman message final exchange
SINT32 ecdh_diffie_hellman_final(safecrypto_t *sc, size_t flen, const UINT8 *from, size_t *tlen, UINT8 **to);

/// Return a C-string output detailing the operation of the specified BLISS-B instance
char * ecdh_stats(safecrypto_t *sc);

