/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "safecrypto_private_key.h"
#include "safecrypto_public_key.h"
#include "safecrypto.h"
#include <crypto/mgf1/mgf1_bitspender.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>
#define _GNU_SOURCE
#include <stdlib.h>

typedef struct private_sc_private_key_t private_sc_private_key_t;

#define SECRET_KEY_TRIALS_MAX    50

/**
 * Private data of a SAFEcrypto_private_key_t object.
 */
struct private_sc_private_key_t {

    /**
     * Public interface for this signer.
     */
    sc_private_key_t public;

    /**
     * BLISS signature parameter set
     */
    const sc_param_set_t *set;

    /**
     * SAFEcrypto struct
     */
    safecrypto_t *sc;

    /**
     * reference count
     */
    refcount_t ref;
};

METHOD(private_key_t, get_type, key_type_t,
    private_sc_private_key_t *this)

{
    return KEY_BLISS;
}

/**
 * Compute a SAFEcrypto signature
 */
static bool sign_safecrypto(private_sc_private_key_t *this, hash_algorithm_t alg,
    chunk_t data, chunk_t *signature)
{
    hasher_t *hasher;
    uint8_t data_hash_buf[HASH_SIZE_SHA512];
    chunk_t data_hash;
    int retcode;
    bool success = FALSE;

    /* Initialize signature */
    *signature = chunk_empty;

    /* Create data hash using configurable hash algorithm */
    hasher = lib->crypto->create_hasher(lib->crypto, alg);
    if (!hasher)
    {
        return FALSE;
    }

    data_hash = chunk_create(data_hash_buf, hasher->get_hash_size(hasher));
    if (!hasher->get_hash(hasher, data, data_hash_buf))
    {
        hasher->destroy(hasher);
        return FALSE;
    }
    hasher->destroy(hasher);

    retcode = safecrypto_sign(this->sc, data_hash.ptr, data_hash.len,
    	&signature->ptr, &signature->len);

    success = SC_FUNC_SUCCESS == retcode;
    return success;
}

METHOD(private_key_t, sign, bool,
    private_sc_private_key_t *this, signature_scheme_t scheme,
    chunk_t data, chunk_t *signature)
{
    switch (scheme)
    {
        case SIGN_BLISS_WITH_SHA2_256:
            return sign_safecrypto(this, HASH_SHA256, data, signature);
        case SIGN_BLISS_WITH_SHA2_384:
            return sign_safecrypto(this, HASH_SHA384, data, signature);
        case SIGN_BLISS_WITH_SHA2_512:
            return sign_safecrypto(this, HASH_SHA512, data, signature);
        case SIGN_BLISS_WITH_SHA3_256:
            return sign_safecrypto(this, HASH_SHA3_256, data, signature);
        case SIGN_BLISS_WITH_SHA3_384:
            return sign_safecrypto(this, HASH_SHA3_384, data, signature);
        case SIGN_BLISS_WITH_SHA3_512:
            return sign_safecrypto(this, HASH_SHA3_512, data, signature);
        default:
            DBG1(DBG_LIB, "signature scheme %N not supported with SAFEcrypto",
                 signature_scheme_names, scheme);
            return FALSE;
    }
}

METHOD(private_key_t, decrypt, bool,
    private_sc_private_key_t *this, encryption_scheme_t scheme,
    chunk_t crypto, chunk_t *plain)
{
    DBG1(DBG_LIB, "encryption scheme %N not supported with SAFEcrypto",
                   encryption_scheme_names, scheme);
    return FALSE;
}

METHOD(private_key_t, get_keysize, int,
    private_sc_private_key_t *this)
{
    return this->set->strength;
}

METHOD(private_key_t, get_public_key, public_key_t*,
    private_sc_private_key_t *this)
{
    public_key_t *public;
    chunk_t pubkey;
    pubkey = safecrypto_public_key_info_extract(this->set->oid, this->sc, this->set);
    public = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_BLISS,
                                BUILD_BLOB_ASN1_DER, pubkey, BUILD_END);
    free(pubkey.ptr);
    return public;
}

METHOD(private_key_t, get_encoding, bool,
    private_sc_private_key_t *this, cred_encoding_type_t type,
    chunk_t *encoding)
{
    switch (type)
    {
        case PRIVKEY_ASN1_DER:
        case PRIVKEY_PEM:
        {
            chunk_t privkey, pubkey;
            bool success = TRUE;

            safecrypto_public_key_encode(this->sc, &pubkey.ptr, &pubkey.len);
            safecrypto_private_key_encode(this->sc, &privkey.ptr, &privkey.len);

            *encoding = asn1_wrap(ASN1_SEQUENCE, "mmss",
                            asn1_build_known_oid(this->set->oid),
                            asn1_bitstring("m", pubkey),
                            asn1_bitstring("m", privkey)
                        );

            if (type == PRIVKEY_PEM)
            {
                chunk_t asn1_encoding = *encoding;
                success = lib->encoding->encode(lib->encoding, PRIVKEY_PEM,
                                NULL, encoding, CRED_PART_BLISS_PRIV_ASN1_DER,
                                asn1_encoding, CRED_PART_END);

                chunk_clear(&asn1_encoding);
            }

            return success;
        }
        default:
            return FALSE;
    }
}

METHOD(private_key_t, get_fingerprint, bool,
    private_sc_private_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
    bool success;
    if (lib->encoding->get_cache(lib->encoding, type, this, fp))
    {
        return TRUE;
    }

    success = safecrypto_public_key_fingerprint(this->set->oid,
        this->sc, this->set, type, fp);
    if (success)
    {
        lib->encoding->cache(lib->encoding, type, this, *fp);
    }

    return success;
}

METHOD(private_key_t, get_ref, private_key_t*,
    private_sc_private_key_t *this)
{
    ref_get(&this->ref);

    return &this->public.key;
}

METHOD(private_key_t, destroy, void,
    private_sc_private_key_t *this)
{
    if (ref_put(&this->ref))
    {
        lib->encoding->clear_cache(lib->encoding, this);

        if (this->sc)
        {
            safecrypto_destroy(this->sc);
        }

        free(this);
    }
}

/**
 * Internal generic constructor
 */
static private_sc_private_key_t *safecrypto_private_key_create_empty(void)
{
    private_sc_private_key_t *this;

    INIT(this,
        .public = {
            .key = {
                .get_type = _get_type,
                .sign = _sign,
                .decrypt = _decrypt,
                .get_keysize = _get_keysize,
                .get_public_key = _get_public_key,
                .equals = private_key_equals,
                .belongs_to = private_key_belongs_to,
                .get_fingerprint = _get_fingerprint,
                .has_fingerprint = private_key_has_fingerprint,
                .get_encoding = _get_encoding,
                .get_ref = _get_ref,
                .destroy = _destroy,
            },
        },
        .ref = 1,
    );

    return this;
}

/**

 * See header.

 */

sc_private_key_t *safecrypto_private_key_gen(key_type_t type, va_list args)
{
    private_sc_private_key_t *this;
    u_int key_size = SAFECRYPTO_BLISS_B_I;
    const sc_param_set_t *set;
    int retcode;

    while (TRUE)
    {
        switch (va_arg(args, builder_part_t))
        {
            case BUILD_KEY_SIZE:
                key_size = va_arg(args, u_int);
                continue;
            case BUILD_END:
                break;
            default:
                return NULL;
        }
        break;
    }

    switch (key_size)
    {
        case SAFECRYPTO_BLISS_I:
            key_size = SAFECRYPTO_BLISS_B_I;
            break;
        case SAFECRYPTO_BLISS_II:
            key_size = SAFECRYPTO_BLISS_B_II;
            break;
        case SAFECRYPTO_BLISS_III:
            key_size = SAFECRYPTO_BLISS_B_III;
            break;
        case SAFECRYPTO_BLISS_IV:
            key_size = SAFECRYPTO_BLISS_B_IV;
            break;
        default:
            break;
    }

    set = safecrypto_param_set_get_by_id(key_size);
    if (!set)
    {
        DBG1(DBG_LIB, "BLISS-B parameter set %u not supported", key_size);
        return NULL;
    }

    this = safecrypto_private_key_create_empty();
    this->set = set;


    this->sc = safecrypto_create("BLISS-B");
    if (NULL == this->sc)
        return NULL;

    retcode = safecrypto_keygen(this->sc);
    if (SC_FUNC_FAILURE == retcode) {
        safecrypto_destroy(this->sc);
        return NULL;
    }

    return &this->public;
}

/**
 * ASN.1 definition of a BLISS private key
 */
static const asn1Object_t privkeyObjects[] = {
    { 0, "SAFEcryptoPrivateKey",   ASN1_SEQUENCE,   ASN1_NONE }, /*  0 */
    { 1, "keyType",                ASN1_OID,        ASN1_BODY }, /*  1 */
    { 1, "public",                 ASN1_BIT_STRING, ASN1_BODY }, /*  2 */
    { 1, "secret",                 ASN1_BIT_STRING, ASN1_BODY }, /*  3 */
    { 0, "exit",                   ASN1_EOC,        ASN1_EXIT }
};

#define PRIV_KEY_TYPE           1
#define PRIV_KEY_PUBLIC         2
#define PRIV_KEY_SECRET         3

/**
 * See header.
 */
sc_private_key_t *safecrypto_private_key_decode(key_type_t type, va_list args)
{
    private_sc_private_key_t *this;
    chunk_t key = chunk_empty, object;
    asn1_parser_t *parser;
    UINT8 *privkey = NULL;
    SINT32 privkey_len = 0;
    bool success = FALSE;
    int objectID, oid;

    while (TRUE)
    {
        switch (va_arg(args, builder_part_t))
        {
            case BUILD_BLOB_ASN1_DER:
                key = va_arg(args, chunk_t);
                continue;
            case BUILD_END:
                break;
            default:
                return NULL;
        }
        break;
    }

    if (key.len == 0)
    {
        return NULL;
    }

    this = safecrypto_private_key_create_empty();
    parser = asn1_parser_create(privkeyObjects, key);
    parser->set_flags(parser, FALSE, TRUE);

    while (parser->iterate(parser, &objectID, &object))
    {
        switch (objectID)
        {
            case PRIV_KEY_TYPE:
                oid = asn1_known_oid(object);
                DBG3(DBG_LIB, "PRIV_KEY_TYPE: oid = %d", oid);
                if (oid == OID_UNKNOWN)
                {
                    goto end;
                }

                this->set = safecrypto_param_set_get_by_oid(oid);
                if (this->set == NULL)
                {
                	DBG3(DBG_LIB, "PRIV_KEY_TYPE: Parameter set unknown");
                    goto end;
                }

                /// @todo Configure the parameter set to be used

                break;

            case PRIV_KEY_PUBLIC:
                if (!safecrypto_public_key_from_asn1(object, this->set, &this->sc))
                {
                	DBG3(DBG_LIB, "PRIV_KEY_PUBLIC: Could not parse from ASN1");
                    goto end;
                }

                break;

            case PRIV_KEY_SECRET:
                /* Skip unused bits octet */
                object = chunk_skip(object, 1);

                privkey_len = object.len;
                privkey = object.ptr;

                safecrypto_private_key_load(this->sc, privkey, privkey_len);
                DBG3(DBG_LIB, "PRIV_KEY_SECRET: Loaded private key polynomials");

                break;
        }
    }
    success = parser->success(parser);

end:
    parser->destroy(parser);
    if (!success)
    {
        destroy(this);
        return NULL;
    }

    return &this->public;
}
