/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "safecrypto_public_key.h"
#include "safecrypto.h"
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <asn1/oid.h>

typedef struct private_sc_public_key_t private_sc_public_key_t;

/**
 * Private data structure with signing context.
 */
struct private_sc_public_key_t {
    /**
     * Public interface for this signer.
     */
    sc_public_key_t public;

    /**
     * SAFEcrypto signature parameter set
     */
    const sc_param_set_t *set;

    /**
     * SAFEcrypto struct
     */
    safecrypto_t *sc;

    /**
     * reference counter
     */
    refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t,
    private_sc_public_key_t *this)
{
    return KEY_BLISS;
}

/**
 * Verify a SAFEcrypto BLISS-B signature based on a SHA-2/3 hash
 */
static bool verify_bliss_b(private_sc_public_key_t *this, hash_algorithm_t alg,
                         chunk_t data, chunk_t signature)
{
	int retcode;
    uint8_t data_hash_buf[HASH_SIZE_SHA512];
    chunk_t data_hash;
    hasher_t *hasher;
    bool success = FALSE;

    /* Create data hash using configurable hash algorithm */
    hasher = lib->crypto->create_hasher(lib->crypto, alg);
    if (!hasher )
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

    // Verify the signature of the hashed data message
    retcode = safecrypto_verify(this->sc, data_hash.ptr, data_hash.len,
    	signature.ptr, signature.len);
    if (SC_FUNC_SUCCESS != retcode) {
    	goto end;
    }

    success = TRUE;

end:

    return success;
}

METHOD(public_key_t, verify, bool,
    private_sc_public_key_t *this, signature_scheme_t scheme,
    chunk_t data, chunk_t signature)
{
    switch (scheme)
    {
        case SIGN_BLISS_WITH_SHA2_256:
            return verify_bliss_b(this, HASH_SHA256, data, signature);
        case SIGN_BLISS_WITH_SHA2_384:
            return verify_bliss_b(this, HASH_SHA384, data, signature);
        case SIGN_BLISS_WITH_SHA2_512:
            return verify_bliss_b(this, HASH_SHA512, data, signature);
        case SIGN_BLISS_WITH_SHA3_256:
            return verify_bliss_b(this, HASH_SHA3_256, data, signature);
        case SIGN_BLISS_WITH_SHA3_384:
            return verify_bliss_b(this, HASH_SHA3_384, data, signature);
        case SIGN_BLISS_WITH_SHA3_512:
            return verify_bliss_b(this, HASH_SHA3_512, data, signature);
        default:
            DBG1(DBG_LIB, "signature scheme %N not supported by SAFEcrypto",
                 signature_scheme_names, scheme);
            return FALSE;
    }
}

METHOD(public_key_t, encrypt_, bool,
    private_sc_public_key_t *this, encryption_scheme_t scheme,
    chunk_t plain, chunk_t *crypto)
{
    DBG1(DBG_LIB, "encryption scheme %N not supported by SAFEcrypto",
                   encryption_scheme_names, scheme);
    return FALSE;
}

METHOD(public_key_t, get_keysize, int,
    private_sc_public_key_t *this)
{
    return this->set->strength;
}

METHOD(public_key_t, get_encoding, bool,
    private_sc_public_key_t *this, cred_encoding_type_t type,
    chunk_t *encoding)
{
    bool success = TRUE;

    *encoding = safecrypto_public_key_info_extract(this->set->oid, this->sc, this->set);
    DBG1(DBG_LIB, "get_encoding() type = %d", type);
    if (type != PUBKEY_SPKI_ASN1_DER)
    {
    	DBG1(DBG_LIB, "ANS1 Encoding ...");

        chunk_t asn1_encoding = *encoding;
        success = lib->encoding->encode(lib->encoding, type,
                        NULL, encoding, CRED_PART_BLISS_PUB_ASN1_DER,
                        asn1_encoding, CRED_PART_END);
        chunk_clear(&asn1_encoding);
    }

    return success;
}

METHOD(public_key_t, get_fingerprint, bool,
    private_sc_public_key_t *this, cred_encoding_type_t type, chunk_t *fp)
{
    bool success;
    if (lib->encoding->get_cache(lib->encoding, type, this, fp))
    {
        return TRUE;
    }

    success = safecrypto_public_key_fingerprint(this->set->oid, this->sc,
                                           this->set, type, fp);

    if (success)
    {
        lib->encoding->cache(lib->encoding, type, this, *fp);
    }

    return success;
}

METHOD(public_key_t, get_ref, public_key_t*,
    private_sc_public_key_t *this)
{
    ref_get(&this->ref);
    return &this->public.key;
}

METHOD(public_key_t, destroy, void,
    private_sc_public_key_t *this)
{
    if (ref_put(&this->ref))
    {
        lib->encoding->clear_cache(lib->encoding, this);
        safecrypto_destroy(this->sc);
        free(this);
    }
}

/**
 * ASN.1 definition of a BLISS-B public key
 */
static const asn1Object_t pubkeyObjects[] = {
    { 0, "subjectPublicKeyInfo", ASN1_SEQUENCE,   ASN1_OBJ  }, /*  0 */
    { 1, "algorithm",            ASN1_EOC,        ASN1_RAW  }, /*  1 */
    { 1, "subjectPublicKey",     ASN1_BIT_STRING, ASN1_BODY }, /*  2 */
    { 0, "exit",                 ASN1_EOC,        ASN1_EXIT }
};

#define SAFECRYPTO_SUBJECT_PUBLIC_KEY_ALGORITHM    1
#define SAFECRYPTO_SUBJECT_PUBLIC_KEY              2

/**
 * See header.
 */
sc_public_key_t *safecrypto_public_key_parse(key_type_t type, va_list args)
{
    private_sc_public_key_t *this;
    chunk_t blob = chunk_empty, object, param;
    asn1_parser_t *parser;
    bool success = FALSE;
    int objectID, oid, i;
    uint32_t r2;

    while (TRUE)
    {
        switch (va_arg(args, builder_part_t))
        {
            case BUILD_BLOB_ASN1_DER:
                blob = va_arg(args, chunk_t);
                continue;
            case BUILD_END:
                break;
            default:
                return NULL;
        }
        break;
    }

    if (blob.len == 0)
    {
        return NULL;
    }

    INIT(this,
        .public = {
            .key = {
                .get_type = _get_type,
                .verify = _verify,
                .encrypt = _encrypt_,
                .equals = public_key_equals,
                .get_keysize = _get_keysize,
                .get_fingerprint = _get_fingerprint,
                .has_fingerprint = public_key_has_fingerprint,
                .get_encoding = _get_encoding,
                .get_ref = _get_ref,
                .destroy = _destroy,
            },
        },
        .ref = 1,
    );

    parser = asn1_parser_create(pubkeyObjects, blob);

    while (parser->iterate(parser, &objectID, &object))
    {
        switch (objectID)
        {
            case SAFECRYPTO_SUBJECT_PUBLIC_KEY_ALGORITHM:
            {
                oid = asn1_parse_algorithmIdentifier(object,
                                parser->get_level(parser)+1, &param);
                if (oid != OID_BLISS_PUBLICKEY)
                {
                	DBG1(DBG_LIB, "oid != OID_BLISS_PUBLICKEY");
                    goto end;
                }

                if (!asn1_parse_simple_object(&param, ASN1_OID,
                                parser->get_level(parser)+3, "SAFEcryptoKeyType"))
                {
                	DBG1(DBG_LIB, "SAFEcryptoKeyType set is unknown");
                    goto end;
                }

                oid = asn1_known_oid(param);
                if (oid == OID_UNKNOWN)
                {
                	DBG1(DBG_LIB, "OID is unknown");
                    goto end;
                }

                this->set = safecrypto_param_set_get_by_oid(oid);
                if (this->set == NULL)
                {
                	DBG1(DBG_LIB, "Parameter set is unknown");
                    goto end;
                }

                break;
            }

            case SAFECRYPTO_SUBJECT_PUBLIC_KEY:
                if (!safecrypto_public_key_from_asn1(object, this->set, &this->sc))
                {
                	DBG1(DBG_LIB, "Loading of public key from ASN1 failed");
                    goto end;
                }
                DBG3(DBG_LIB, "Created SAFEcrypto using public key");

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

/**
 * See header.
 */
bool safecrypto_public_key_from_asn1(chunk_t object, const sc_param_set_t *set,
                                safecrypto_t **sc)
{
    int retcode;

    /* skip initial bit string octet defining unused bits */
    object = chunk_skip(object, 1);

    *sc = safecrypto_create("BLISS-B");
    retcode = safecrypto_public_key_load(*sc, object.ptr, object.len);
    if (SC_FUNC_SUCCESS != retcode) {
    	safecrypto_destroy(*sc);
    	*sc = NULL;
        return FALSE;
    }

    return TRUE;
}

/**
 * See header.
 */
chunk_t safecrypto_public_key_extract(safecrypto_t *sc, const sc_param_set_t *set)
{
    chunk_t encoding;

    safecrypto_public_key_encode(sc, &encoding.ptr, &encoding.len);

    return encoding;
}

/**
 * See header.
 */
chunk_t safecrypto_public_key_info_extract(int oid, safecrypto_t *sc,
                                     const sc_param_set_t *set)
{
    chunk_t encoding, pubkey_encoding;
    pubkey_encoding = safecrypto_public_key_extract(sc, set);
    encoding = asn1_wrap(ASN1_SEQUENCE, "mm",
                    asn1_wrap(ASN1_SEQUENCE, "mm",
                        asn1_build_known_oid(OID_BLISS_PUBLICKEY),
                        asn1_build_known_oid(oid)),
                    asn1_bitstring("m", pubkey_encoding));

    return encoding;
}

/**
 * See header.
 */
bool safecrypto_public_key_fingerprint(int oid, safecrypto_t *sc,
                                  const sc_param_set_t *set,
                                  cred_encoding_type_t type, chunk_t *fp)
{
    hasher_t *hasher;
    chunk_t key;

    switch (type)
    {
        case KEYID_PUBKEY_SHA1:
            key = safecrypto_public_key_extract(sc, set);
            break;
        case KEYID_PUBKEY_INFO_SHA1:
            key = safecrypto_public_key_info_extract(oid, sc, set);
            break;
        default:
            return FALSE;
    }

    hasher = lib->crypto->create_hasher(lib->crypto, HASH_SHA1);
    if (!hasher || !hasher->allocate_hash(hasher, key, fp))
    {
        DBG1(DBG_LIB, "SHA1 hash algorithm not supported, fingerprinting failed");
        DESTROY_IF(hasher);
        free(key.ptr);
        return FALSE;
    }

    hasher->destroy(hasher);
    free(key.ptr);

    return TRUE;
}

