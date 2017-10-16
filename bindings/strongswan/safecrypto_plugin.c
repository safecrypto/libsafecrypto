/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "safecrypto_plugin.h"
#include "safecrypto_private_key.h"
#include "safecrypto_public_key.h"

#include <library.h>


typedef struct private_safecrypto_plugin_t private_safecrypto_plugin_t;

/**
 * private data of safecrypto_plugin
 */
struct private_safecrypto_plugin_t {
    /**
     * public functions
     */
    safecrypto_plugin_t public;
};

METHOD(plugin_t, get_name, char*, private_safecrypto_plugin_t *this)
{
    return "safecrypto";
}

METHOD(plugin_t, get_features, int,
    private_safecrypto_plugin_t *this, plugin_feature_t *features[])
{
    static plugin_feature_t f[] = {
        // private/public keys
        PLUGIN_REGISTER(PRIVKEY, safecrypto_private_key_decode, TRUE),
            PLUGIN_PROVIDE(PRIVKEY, KEY_BLISS),
        PLUGIN_REGISTER(PRIVKEY, safecrypto_private_key_decode, TRUE),
            PLUGIN_PROVIDE(PRIVKEY, KEY_ANY),
        PLUGIN_REGISTER(PRIVKEY_GEN, safecrypto_private_key_gen, FALSE),
            PLUGIN_PROVIDE(PRIVKEY_GEN, KEY_BLISS),
                PLUGIN_DEPENDS(RNG, RNG_TRUE),
        PLUGIN_REGISTER(PUBKEY, safecrypto_public_key_parse, TRUE),
            PLUGIN_PROVIDE(PUBKEY, KEY_BLISS),
        PLUGIN_REGISTER(PUBKEY, safecrypto_public_key_parse, TRUE),
            PLUGIN_PROVIDE(PUBKEY, KEY_ANY),

        // signature schemes
        PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_BLISS_WITH_SHA2_256),
            PLUGIN_DEPENDS(HASHER, HASH_SHA256),
        PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_BLISS_WITH_SHA2_384),
            PLUGIN_DEPENDS(HASHER, HASH_SHA384),
        PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_BLISS_WITH_SHA2_512),
            PLUGIN_DEPENDS(HASHER, HASH_SHA512),
        PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_BLISS_WITH_SHA3_256),
            PLUGIN_DEPENDS(HASHER, HASH_SHA3_256),
        PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_BLISS_WITH_SHA3_384),
            PLUGIN_DEPENDS(HASHER, HASH_SHA3_384),
        PLUGIN_PROVIDE(PRIVKEY_SIGN, SIGN_BLISS_WITH_SHA3_512),
            PLUGIN_DEPENDS(HASHER, HASH_SHA3_512),

        // signature verification schemes
        PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_BLISS_WITH_SHA2_256),
            PLUGIN_DEPENDS(HASHER, HASH_SHA256),
        PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_BLISS_WITH_SHA2_384),
            PLUGIN_DEPENDS(HASHER, HASH_SHA384),
        PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_BLISS_WITH_SHA2_512),
            PLUGIN_DEPENDS(HASHER, HASH_SHA512),
        PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_BLISS_WITH_SHA3_256),
            PLUGIN_DEPENDS(HASHER, HASH_SHA3_256),
        PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_BLISS_WITH_SHA3_384),
            PLUGIN_DEPENDS(HASHER, HASH_SHA3_384),
        PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_BLISS_WITH_SHA3_512),
            PLUGIN_DEPENDS(HASHER, HASH_SHA3_512),
    };

    *features = f;

    return countof(f);
}

METHOD(plugin_t, destroy, void, private_safecrypto_plugin_t *this)
{
    free(this);
}

/*
 * see header file
 */
plugin_t *safecrypto_plugin_create()
{
    private_safecrypto_plugin_t *this;

    INIT(this,
        .public = {
            .plugin = {
                .get_name = _get_name,
                .get_features = _get_features,
                .destroy = _destroy,
            },
        },
    );

    return &this->public.plugin;
}
