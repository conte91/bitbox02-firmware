// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <inttypes.h>
#include <stdint.h>

#include "cbor.h"

#include "ctap.h"
#include "ctap_parse.h"
#include "ctap_errors.h"
#include "cose_key.h"
#include "util.h"

#include <u2f/u2f_keyhandle.h>

extern struct _getAssertionState getAssertionState;

/**
 * Field tags used in MakeCredential requests.
 */
#define MAKE_CREDENTIAL_TAG_CLIENT_DATA_HASH (0x01)
#define MAKE_CREDENTIAL_TAG_RELYING_PARTY (0x02)
#define MAKE_CREDENTIAL_TAG_USER (0x03)
#define MAKE_CREDENTIAL_TAG_PUB_KEY_CRED_PARAMS (0x04)
#define MAKE_CREDENTIAL_TAG_EXCLUDE_LIST (0x05)
#define MAKE_CREDENTIAL_TAG_EXTENSIONS (0x06)
#define MAKE_CREDENTIAL_TAG_OPTIONS (0x07)
#define MAKE_CREDENTIAL_TAG_PIN_AUTH (0x08)
#define MAKE_CREDENTIAL_TAG_PIN_PROTOCOL (0x09)

/**
 * Field tags used in MakeCredential requests.
 */
#define GA_rpId                   0x01
#define GA_clientDataHash         0x02
#define GA_allowList              0x03
#define GA_extensions             0x04
#define GA_options                0x05
#define GA_pinAuth                0x06
#define GA_pinProtocol            0x07

const char * cbor_value_get_type_string(const CborValue *value)
{
    switch(cbor_value_get_type(value))
    {
        case CborIntegerType:
            return "CborIntegerType";
            break;
        case CborByteStringType:
            return "CborByteStringType";
            break;
        case CborTextStringType:
            return "CborTextStringType";
            break;
        case CborArrayType:
            return "CborArrayType";
            break;
        case CborMapType:
            return "CborMapType";
            break;
        case CborTagType:
            return "CborTagType";
            break;
        case CborSimpleType:
            return "CborSimpleType";
            break;
        case CborBooleanType:
            return "CborBooleanType";
            break;
        case CborNullType:
            return "CborNullType";
            break;
        case CborUndefinedType:
            return "CborUndefinedType";
            break;
        case CborHalfFloatType:
            return "CborHalfFloatType";
            break;
        case CborFloatType:
            return "CborFloatType";
            break;
        case CborDoubleType:
            return "CborDoubleType";
            break;
        default:
            return "Invalid type";
    }
}


static uint8_t _parse_user(CTAP_makeCredential * MC, CborValue * val)
{
    size_t sz, map_length;
    uint8_t key[24];
    int ret;
    unsigned int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, (char *)key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }

        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (strcmp((const char*)key, "id") == 0)
        {

            if (cbor_value_get_type(&map) != CborByteStringType)
            {
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }

            sz = CTAP_USER_ID_MAX_SIZE;
            ret = cbor_value_copy_byte_string(&map, MC->credInfo.user.id, &sz, NULL);
            if (ret == CborErrorOutOfMemory)
            {
                return CTAP2_ERR_LIMIT_EXCEEDED;
            }
            MC->credInfo.user.id_size = sz;
            check_ret(ret);
        }
        else if (strcmp((const char *)key, "name") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = CTAP_USER_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.name, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->credInfo.user.name[CTAP_USER_NAME_LIMIT - 1] = 0;
        }
        else if (strcmp((const char *)key, "displayName") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = DISPLAY_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.displayName, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->credInfo.user.displayName[DISPLAY_NAME_LIMIT - 1] = 0;
        }
        else if (strcmp((const char *)key, "icon") == 0)
        {
            if (cbor_value_get_type(&map) != CborTextStringType)
            {
                return CTAP2_ERR_INVALID_CBOR_TYPE;
            }
            sz = ICON_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char *)MC->credInfo.user.icon, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            MC->credInfo.user.icon[ICON_LIMIT - 1] = 0;

        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }

    MC->paramsParsed |= PARAM_user;

    return 0;
}


static uint8_t _parse_pub_key_cred_param(CborValue * val, uint8_t * cred_type, int32_t * alg_type)
{
    CborValue cred;
    CborValue alg;
    int ret;
    uint8_t type_str[16];
    size_t sz = sizeof(type_str);

    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_map_find_value(val, "type", &cred);
    check_ret(ret);
    ret = cbor_value_map_find_value(val, "alg", &alg);
    check_ret(ret);

    if (cbor_value_get_type(&cred) != CborTextStringType)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    if (cbor_value_get_type(&alg) != CborIntegerType)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    ret = cbor_value_copy_text_string(&cred, (char*)type_str, &sz, NULL);
    check_ret(ret);

    type_str[sizeof(type_str) - 1] = 0;

    if (strcmp((const char*)type_str, "public-key") == 0)
    {
        *cred_type = PUB_KEY_CRED_PUB_KEY;
    }
    else
    {
        *cred_type = PUB_KEY_CRED_UNKNOWN;
    }

    ret = cbor_value_get_int_checked(&alg, (int*)alg_type);
    check_ret(ret);

    return 0;
}

// Check if public key credential+algorithm type is supported
static int _pub_key_cred_param_supported(uint8_t cred, int32_t alg)
{
    if (cred == PUB_KEY_CRED_PUB_KEY)
    {
        if (alg == COSE_ALG_ES256)
        {
            return  CREDENTIAL_IS_SUPPORTED;
        }
    }

    return  CREDENTIAL_NOT_SUPPORTED;
}

static uint8_t _parse_pub_key_cred_params(CTAP_makeCredential * MC, CborValue * val)
{
    size_t arr_length;
    uint8_t cred_type;
    int32_t alg_type;
    int ret;
    unsigned int i;
    CborValue arr;


    if (cbor_value_get_type(val) != CborArrayType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);

    ret = cbor_value_get_array_length(val, &arr_length);
    check_ret(ret);

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = _parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) != 0)
        {
            return ret;
        }
        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }

    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);

    for (i = 0; i < arr_length; i++)
    {
        if ((ret = _parse_pub_key_cred_param(&arr, &cred_type, &alg_type)) == 0)
        {
            if (_pub_key_cred_param_supported(cred_type, alg_type) == CREDENTIAL_IS_SUPPORTED)
            {
                MC->credInfo.publicKeyCredentialType = cred_type;
                MC->credInfo.COSEAlgorithmIdentifier = alg_type;
                MC->paramsParsed |= PARAM_pubKeyCredParams;
                return 0;
            }
        }
        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }

    return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

static uint8_t _parse_fixed_byte_string(CborValue * map, uint8_t * dst, unsigned int len)
{
    size_t sz;
    int ret;
    if (cbor_value_get_type(map) == CborByteStringType)
    {
        sz = len;
        ret = cbor_value_copy_byte_string(map, dst, &sz, NULL);
        check_ret(ret);
        if (sz != len)
        {
            return CTAP1_ERR_INVALID_LENGTH;
        }
    }
    else
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    return 0;
}

static uint8_t parse_verify_exclude_list(CborValue * val)
{
    unsigned int i;
    int ret;
    CborValue arr;
    size_t size;
    u2f_keyhandle_t cred;
    if (cbor_value_get_type(val) != CborArrayType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    ret = cbor_value_get_array_length(val, &size);
    check_ret(ret);
    ret = cbor_value_enter_container(val,&arr);
    check_ret(ret);
    for (i = 0; i < size; i++)
    {
        bool cred_valid;
        ret = ctap_parse_credential_descriptor(&arr, &cred, &cred_valid);
        if (!cred_valid) {
            return CTAP2_ERR_INVALID_CBOR;
        }
        check_ret(ret);
        ret = cbor_value_advance(&arr);
        check_ret(ret);

    }
    return 0;
}

static uint8_t _parse_rp_id(struct rpId * rp, CborValue * val)
{
    size_t sz = DOMAIN_NAME_MAX_SIZE;
    if (cbor_value_get_type(val) != CborTextStringType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }
    int ret = cbor_value_copy_text_string(val, (char*)rp->id, &sz, NULL);
    if (ret == CborErrorOutOfMemory)
    {
        return CTAP2_ERR_LIMIT_EXCEEDED;
    }
    check_ret(ret);
    rp->id[DOMAIN_NAME_MAX_SIZE] = 0;     // Extra byte defined in struct.
    rp->size = sz;
    return 0;
}

static uint8_t _parse_rp(struct rpId * rp, CborValue * val)
{
    size_t sz, map_length;
    char key[8];
    int ret;
    unsigned int i;
    CborValue map;


    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    rp->size = 0;

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        if (strcmp(key, "id") == 0)
        {
            ret = _parse_rp_id(rp, &map);
            if (ret != 0)
            {
                return ret;
            }
        }
        else if (strcmp(key, "name") == 0)
        {
            sz = RP_NAME_LIMIT;
            ret = cbor_value_copy_text_string(&map, (char*)rp->name, &sz, NULL);
            if (ret != CborErrorOutOfMemory)
            {   // Just truncate the name it's okay
                check_ret(ret);
            }
            rp->name[RP_NAME_LIMIT - 1] = 0;
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);

    }
    if (rp->size == 0)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }


    return 0;
}

static uint8_t _parse_options(CborValue * val, uint8_t * rk, uint8_t * uv, uint8_t * up)
{
    size_t sz, map_length;
    char key[8];
    int ret;
    unsigned int i;
    _Bool b;
    CborValue map;

    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);


    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            return CTAP2_ERR_LIMIT_EXCEEDED;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);

        if (cbor_value_get_type(&map) != CborBooleanType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        if (strncmp(key, "rk",2) == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            *rk = b;
        }
        else if (strncmp(key, "uv",2) == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            *uv = b;
        }
        else if (strncmp(key, "up",2) == 0)
        {
            ret = cbor_value_get_boolean(&map, &b);
            check_ret(ret);
            *up = b;
        }
        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    return 0;
}

static uint8_t _parse_cose_key(CborValue * it, COSE_key * cose)
{
    CborValue map;
    size_t map_length;
    int ret,key;
    unsigned int i;
    int xkey = 0,ykey = 0;
    cose->kty = 0;
    cose->crv = 0;


    CborType type = cbor_value_get_type(it);
    if (type != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(it, &map_length);
    check_ret(ret);


    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborIntegerType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }

        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);

        switch(key)
        {
            case COSE_KEY_LABEL_KTY:
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &cose->kty);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case COSE_KEY_LABEL_ALG:
                break;
            case COSE_KEY_LABEL_CRV:
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &cose->crv);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                break;
            case COSE_KEY_LABEL_X:
                ret = _parse_fixed_byte_string(&map, cose->pubkey.x, 32);
                check_retr(ret);
                xkey = 1;

                break;
            case COSE_KEY_LABEL_Y:
                ret = _parse_fixed_byte_string(&map, cose->pubkey.y, 32);
                check_retr(ret);
                ykey = 1;

                break;
            default:
                break;
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    if (xkey == 0 || ykey == 0 || cose->kty == 0 || cose->crv == 0)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }
    return 0;
}

static uint8_t ctap_parse_hmac_secret(CborValue * val, CTAP_hmac_secret * hs)
{
    size_t map_length;
    size_t salt_len;
    uint8_t parsed_count = 0;
    int key;
    int ret;
    unsigned int i;
    CborValue map;

    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborIntegerType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);

        switch(key)
        {
            case EXT_HMAC_SECRET_COSE_KEY:
                ret = _parse_cose_key(&map, &hs->keyAgreement);
                check_retr(ret);
                parsed_count++;
            break;
            case EXT_HMAC_SECRET_SALT_ENC:
                salt_len = 64;
                ret = cbor_value_copy_byte_string(&map, hs->saltEnc, &salt_len, NULL);
                if ((salt_len != 32 && salt_len != 64) || ret == CborErrorOutOfMemory)
                {
                    return CTAP1_ERR_INVALID_LENGTH;
                }
                check_ret(ret);
                hs->saltLen = salt_len;
                parsed_count++;
            break;
            case EXT_HMAC_SECRET_SALT_AUTH:
                salt_len = 32;
                ret = cbor_value_copy_byte_string(&map, hs->saltAuth, &salt_len, NULL);
                check_ret(ret);
                parsed_count++;
            break;
            default:
                Abort("ctap_parse_hmac_secret: bad key");
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }

    if (parsed_count != 3)
    {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    return 0;
}


static uint8_t ctap_parse_extensions(CborValue * val, CTAP_extensions * ext)
{
    CborValue map;
    size_t sz, map_length;
    char key[16];
    int ret;
    unsigned int i;
    bool b;

    if (cbor_value_get_type(val) != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(val, &map);
    check_ret(ret);

    ret = cbor_value_get_map_length(val, &map_length);
    check_ret(ret);

    for (i = 0; i < map_length; i++)
    {
        if (cbor_value_get_type(&map) != CborTextStringType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        sz = sizeof(key);
        ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

        if (ret == CborErrorOutOfMemory)
        {
            cbor_value_advance(&map);
            cbor_value_advance(&map);
            continue;
        }
        check_ret(ret);
        key[sizeof(key) - 1] = 0;

        ret = cbor_value_advance(&map);
        check_ret(ret);


        if (strncmp(key, "hmac-secret",11) == 0)
        {
            if (cbor_value_get_type(&map) == CborBooleanType)
            {
                ret = cbor_value_get_boolean(&map, &b);
                check_ret(ret);
                if (b) ext->hmac_secret_present = EXT_HMAC_SECRET_REQUESTED;
            }
            else if (cbor_value_get_type(&map) == CborMapType)
            {
                ret = ctap_parse_hmac_secret(&map, &ext->hmac_secret);
                check_retr(ret);
                ext->hmac_secret_present = EXT_HMAC_SECRET_PARSED;
            }
        }

        ret = cbor_value_advance(&map);
        check_ret(ret);
    }
    return 0;
}

uint8_t ctap_parse_make_credential(CTAP_makeCredential * MC, CborEncoder * encoder, const uint8_t* request, int length)
{
    (void)encoder;
    int ret;
    unsigned int i;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it,map;

    memset(MC, 0, sizeof(CTAP_makeCredential));
    MC->up = 0xff;
    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_retr(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);


    for (i = 0; i < map_length; i++)
    {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);
        ret = 0;

        switch(key)
        {

            case MAKE_CREDENTIAL_TAG_CLIENT_DATA_HASH:

                ret = _parse_fixed_byte_string(&map, MC->clientDataHash, CLIENT_DATA_HASH_SIZE);
                if (ret == 0)
                {
                    MC->paramsParsed |= PARAM_clientDataHash;
                }

                break;
            case MAKE_CREDENTIAL_TAG_RELYING_PARTY:

                ret = _parse_rp(&MC->rp, &map);
                if (ret == 0)
                {
                    MC->paramsParsed |= PARAM_rp;
                }


                break;
            case MAKE_CREDENTIAL_TAG_USER:

                ret = _parse_user(MC, &map);


                break;
            case MAKE_CREDENTIAL_TAG_PUB_KEY_CRED_PARAMS:

                ret = _parse_pub_key_cred_params(MC, &map);


                break;
            case MAKE_CREDENTIAL_TAG_EXCLUDE_LIST:
                ret = parse_verify_exclude_list(&map);
                check_ret(ret);

                ret = cbor_value_enter_container(&map, &MC->excludeList);
                check_ret(ret);

                ret = cbor_value_get_array_length(&map, &MC->excludeListSize);
                check_ret(ret);


                break;
            case MAKE_CREDENTIAL_TAG_EXTENSIONS:
                type = cbor_value_get_type(&map);
                if (type != CborMapType)
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }
                ret = ctap_parse_extensions(&map, &MC->extensions);
                check_retr(ret);
                break;

            case MAKE_CREDENTIAL_TAG_OPTIONS:
                ret = _parse_options(&map, &MC->credInfo.rk, &MC->uv, &MC->up);
                check_retr(ret);
                break;
            case MAKE_CREDENTIAL_TAG_PIN_AUTH: {

                size_t pinSize;
                if (cbor_value_get_type(&map) == CborByteStringType &&
                    cbor_value_get_string_length(&map, &pinSize) == CborNoError &&
                    pinSize == 0)
                {
                    MC->pinAuthEmpty = 1;
                    break;
                }

                ret = _parse_fixed_byte_string(&map, MC->pinAuth, 16);
                if (CTAP1_ERR_INVALID_LENGTH != ret)    // damn microsoft
                {
                    check_retr(ret);
                }
                else
                {
                    ret = 0;
                }
                MC->pinAuthPresent = 1;
                break;
            }
            case MAKE_CREDENTIAL_TAG_PIN_PROTOCOL:
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &MC->pinProtocol);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }

                break;

            default:
                break;

        }
        if (ret != 0)
        {
            return ret;
        }
        cbor_value_advance(&map);
        check_ret(ret);
    }

    return 0;
}

uint8_t ctap_parse_credential_descriptor(CborValue* arr, u2f_keyhandle_t* cred, bool* cred_valid_out)
{
    int ret;
    size_t buflen;
    char type[12];
    CborValue val;

    if (cbor_value_get_type(arr) != CborMapType) {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    /* Fetch the key handle. */
    ret = cbor_value_map_find_value(arr, "id", &val);
    check_ret(ret);

    if (cbor_value_get_type(&val) != CborByteStringType) {
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    buflen = sizeof(*cred);
    ret = cbor_value_copy_byte_string(&val, (uint8_t*)cred, &buflen, NULL);

    if (buflen < sizeof(*cred)) {
        /* Not enough bytes to be a credential that we've generated. Skip it. */
        *cred_valid_out = false;
        return 0;
    }
    check_ret(ret);

    /* Now check the "type" field. */
    ret = cbor_value_map_find_value(arr, "type", &val);
    check_ret(ret);

    if (cbor_value_get_type(&val) != CborTextStringType) {
        *cred_valid_out = false;
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    buflen = sizeof(type);
    ret = cbor_value_copy_text_string(&val, type, &buflen, NULL);
    if (ret == CborErrorOutOfMemory) {
        /*
         * The type string is too big, so type type of the key
         * is not something we know about.
         */
        *cred_valid_out = false;
        return 0;
    } else {
        check_ret(ret);
    }

    if (strncmp(type, "public-key", 11) != 0) {
        /* Not a keytype we know. */
        *cred_valid_out = false;
        return 0;
    }
    *cred_valid_out = true;
    return 0;
}

/**
 * Parses the list of allowed credentials into GA->creds.
 * Updates GA->creds and GA->credLen.
 * @return CTAP status code (0 is success).
 */
static uint8_t parse_allow_list(CTAP_getAssertion* GA, CborValue * it)
{
    CborValue arr;
    size_t len;
    int ret;
    unsigned int i;

    if (cbor_value_get_type(it) != CborArrayType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(it,&arr);
    check_ret(ret);

    ret = cbor_value_get_array_length(it, &len);
    check_ret(ret);

    GA->credLen = 0;

    for (i = 0; i < len; i++) {
        if (GA->credLen >= CTAP_CREDENTIAL_LIST_MAX_SIZE) {
            return CTAP2_ERR_TOO_MANY_ELEMENTS;
        }

        /* Check if this is a credential we should consider. */
        bool cred_valid = false;
        u2f_keyhandle_t* cred = &GA->creds[GA->credLen];
        ret = ctap_parse_credential_descriptor(&arr, cred, &cred_valid);

        check_retr(ret);
        if (cred_valid) {
            GA->credLen += 1;
        }

        ret = cbor_value_advance(&arr);
        check_ret(ret);
    }
    return 0;
}

uint8_t ctap_parse_get_assertion(CTAP_getAssertion * GA, const uint8_t * request, int length)
{
    int ret;
    int key;
    size_t map_length;
    CborParser parser;
    CborValue it,map;

    memset(GA, 0, sizeof(CTAP_getAssertion));
    GA->up = 0xff;

    ret = cbor_parser_init(request, length, CborValidateCanonicalFormat, &parser, &it);
    check_ret(ret);

    CborType type = cbor_value_get_type(&it);
    if (type != CborMapType)
    {
        return CTAP2_ERR_INVALID_CBOR_TYPE;
    }

    ret = cbor_value_enter_container(&it,&map);
    check_ret(ret);

    ret = cbor_value_get_map_length(&it, &map_length);
    check_ret(ret);


    for (size_t i = 0; i < map_length; i++) {
        type = cbor_value_get_type(&map);
        if (type != CborIntegerType)
        {
            return CTAP2_ERR_INVALID_CBOR_TYPE;
        }
        ret = cbor_value_get_int_checked(&map, &key);
        check_ret(ret);

        ret = cbor_value_advance(&map);
        check_ret(ret);
        ret = 0;

        switch(key)
        {

            case GA_clientDataHash:

                ret = _parse_fixed_byte_string(&map, GA->clientDataHash, CLIENT_DATA_HASH_SIZE);
                check_retr(ret);
                GA->clientDataHashPresent = 1;

                break;
            case GA_rpId:

                ret = _parse_rp_id(&GA->rp, &map);

                break;
            case GA_allowList:
                ret = parse_allow_list(GA, &map);
                check_ret(ret);
                GA->allowListPresent = 1;

                break;
            case GA_extensions:
                ret = ctap_parse_extensions(&map, &GA->extensions);
                check_retr(ret);
                break;

            case GA_options:
                ret = _parse_options(&map, &GA->rk, &GA->uv, &GA->up);
                check_retr(ret);
                break;
            case GA_pinAuth: {

                size_t pinSize;
                if (cbor_value_get_type(&map) == CborByteStringType &&
                    cbor_value_get_string_length(&map, &pinSize) == CborNoError &&
                    pinSize == 0)
                {
                    GA->pinAuthEmpty = 1;
                    break;
                }

                ret = _parse_fixed_byte_string(&map, GA->pinAuth, 16);
                if (CTAP1_ERR_INVALID_LENGTH != ret)    // damn microsoft
                {
                    check_retr(ret);

                }
                else
                {
                    ret = 0;
                }

                check_retr(ret);
                GA->pinAuthPresent = 1;

                break;
            }
            case GA_pinProtocol:
                if (cbor_value_get_type(&map) == CborIntegerType)
                {
                    ret = cbor_value_get_int_checked(&map, &GA->pinProtocol);
                    check_ret(ret);
                }
                else
                {
                    return CTAP2_ERR_INVALID_CBOR_TYPE;
                }

                break;

            default:
                Abort("ctap_parse_get_assertion: bad key.");
        }
        if (ret != 0)
        {
            return ret;
        }

        cbor_value_advance(&map);
        check_ret(ret);
    }


    return 0;
}


