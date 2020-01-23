// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctap.h"

#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctaphid.h"
#include "ctap_parse.h"
#include "device.h"
#include "extensions.h"
#include "fido2_keys.h"
#include "fido2_u2f.h"
#include "storage.h"

#include <memory/memory.h>
#include <crypto/sha2/sha256.h>
#include <screen.h>
#include <securechip/securechip.h>
#include <usb/usb_packet.h>
#include <util.h>
#include <workflow/confirm.h>
#include <workflow/select_ctap_credential.h>
#include <workflow/unlock.h>

static inline int timestamp(void) {
    /* Does nothing. */
    return 0;
}

uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
uint8_t KEY_AGREEMENT_PUB[64];
static uint8_t KEY_AGREEMENT_PRIV[32];
static int8_t PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;

AuthenticatorState STATE;

static void ctap_reset_key_agreement(void);

static uint8_t ctap_get_info(CborEncoder * encoder)
{
    int ret;
    CborEncoder array;
    CborEncoder map;
    CborEncoder options;
    CborEncoder pins;
    uint8_t aaguid[16];
    device_read_aaguid(aaguid);

    ret = cbor_encoder_create_map(encoder, &map, 6);
    check_ret(ret);
    {
        ret = cbor_encode_uint(&map, RESP_versions);     //  versions key
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 2);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "U2F_V2");
                check_ret(ret);
                ret = cbor_encode_text_stringz(&array, "FIDO_2_0");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_extensions);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &array, 1);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&array, "hmac-secret");
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &array);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_aaguid);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&map, aaguid, 16);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_options);
        check_ret(ret);
        {
            ret = cbor_encoder_create_map(&map, &options, 4);
            check_ret(ret);
            {
                ret = cbor_encode_text_string(&options, "rk", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of storing keys locally
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "up", 2);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 1);     // Capable of testing user presence
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "uv", 2); // Capable of verifying user
                check_ret(ret);
                {
                    /*
                     * The option should be true/false based on whether the UV function has already
                     * been initialized.
                     */
                    ret = cbor_encode_boolean(&options, device_is_uv_initialized());
                    check_ret(ret);
                }

                ret = cbor_encode_text_string(&options, "plat", 4);
                check_ret(ret);
                {
                    ret = cbor_encode_boolean(&options, 0);     // Not attached to platform
                    check_ret(ret);
                }
                /*
                 * We're not capable of PIN authentication, so the clientPin option
                 * should be unset.
                 */
            }
            ret = cbor_encoder_close_container(&map, &options);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_maxMsgSize);
        check_ret(ret);
        {
            ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
            check_ret(ret);
        }

        ret = cbor_encode_uint(&map, RESP_pinProtocols);
        check_ret(ret);
        {
            ret = cbor_encoder_create_array(&map, &pins, 1);
            check_ret(ret);
            {
                ret = cbor_encode_int(&pins, 1);
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&map, &pins);
            check_ret(ret);
        }
    }
    ret = cbor_encoder_close_container(encoder, &map);
    check_ret(ret);

    return CTAP1_ERR_SUCCESS;
}



static int ctap_add_cose_key(CborEncoder* cose_key, uint8_t* x, uint8_t* y, int32_t algtype)
{
    int ret;
    CborEncoder map;

    ret = cbor_encoder_create_map(cose_key, &map, 5);
    check_ret(ret);


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_KTY_EC2);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
        check_ret(ret);
        ret = cbor_encode_int(&map, algtype);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
        check_ret(ret);
        ret = cbor_encode_int(&map, COSE_KEY_CRV_P256);
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, x, 32);
        check_ret(ret);
    }

    {
        ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, y, 32);
        check_ret(ret);
    }

    ret = cbor_encoder_close_container(cose_key, &map);
    check_ret(ret);

    return 0;
}

static void ctap_flush_state(void)
{
    authenticator_write_state(&STATE);
}

/**
 * Encode the 32bit U2F counter value as a big-endian
 * sequence of bytes.
 * @param counter Counter to encode.
 * @param buf_out Buffer in which to encode the counter. Must be 4 bytes wide.
 */
static void _encode_u2f_counter(uint32_t counter, uint8_t* buf_out)
{
    *buf_out++ = (counter >> 24) & 0xff;
    *buf_out++ = (counter >> 16) & 0xff;
    *buf_out++ = (counter >> 8) & 0xff;
    *buf_out++ = (counter >> 0) & 0xff;
}

/**
 * Copy the source string into the destination buffer.
 * If the string is too long to fit the destination buffer,
 * truncate the string with "...", so that the resulting
 * string is always a valid NULL-terminated string.
 */
static void _copy_or_truncate(char* dst, size_t dst_size, const char* src)
{
    size_t src_size = strlen(src);
    bool truncate = false;

    const char* padding = "...";
    size_t padding_size = strlen(padding);

    if (dst_size < src_size + 1) {
        /*
         * String is too long.
         * Truncate the source string to the biggest possible size.
         */
        truncate = true;
        src_size = dst_size - 1 - padding_size;
    }
    strncpy(dst, src, src_size);
    if (!truncate) {
        dst[src_size] = '\0';
    } else {
        strcpy(dst, padding);
        dst[src_size + padding_size] = '\0';
    }
}

#if 0
static uint32_t auth_data_update_count(uint8_t* byte_out)
{
    uint32_t count = ctap_atomic_count( 0 );
    if (count == 0)     // count 0 will indicate invalid token
    {
        count = ctap_atomic_count( 0 );

    }
    _encode_u2f_counter(count, byte_out);
    return count;
}
#endif

#if 0
static void ctap_increment_rk_store(void)
{
    STATE.rk_stored++;
    ctap_flush_state();
}
#endif

static int _is_matching_rk(ctap_resident_key_t* rk, ctap_resident_key_t* rk2)
{
    return (memcmp(rk->rp_id_hash, rk2->rp_id_hash, 32) == 0) &&
            (memcmp(rk->rp_id, rk2->rp_id, CTAP_STORAGE_RP_ID_MAX_SIZE) == 0) &&
            (memcmp(rk->user_name, rk2->user_name, CTAP_STORAGE_USER_NAME_LIMIT) == 0);
}

#if 0
/* TODO: simone: manage extensions */
static int ctap_make_extensions(CTAP_extensions * ext, uint8_t * ext_encoder_buf, unsigned int * ext_encoder_buf_size)
{
    CborEncoder extensions;
    int ret;
    uint8_t output[64];
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    uint8_t credRandom[32];

    if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED)
    {
        printf1(TAG_CTAP, "Processing hmac-secret..\r\n");

        crypto_ecc256_shared_secret((uint8_t*) &ext->hmac_secret.keyAgreement.pubkey,
                                    KEY_AGREEMENT_PRIV,
                                    shared_secret);
        crypto_sha256_init();
        crypto_sha256_update(shared_secret, 32);
        crypto_sha256_final(shared_secret);

        crypto_sha256_hmac_init(shared_secret, 32, hmac);
        crypto_sha256_update(ext->hmac_secret.saltEnc, ext->hmac_secret.saltLen);
        crypto_sha256_hmac_final(shared_secret, 32, hmac);

        if (memcmp(ext->hmac_secret.saltAuth, hmac, 16) == 0)
        {
            printf1(TAG_CTAP, "saltAuth is valid\r\n");
        }
        else
        {
            printf1(TAG_CTAP, "saltAuth is invalid\r\n");
            return CTAP2_ERR_EXTENSION_FIRST;
        }

        // Generate credRandom
        crypto_sha256_hmac_init(CRYPTO_TRANSPORT_KEY2, 0, credRandom);
        crypto_sha256_update((uint8_t*)&ext->hmac_secret.credential->id, sizeof(CredentialId));
        crypto_sha256_hmac_final(CRYPTO_TRANSPORT_KEY2, 0, credRandom);

        // Decrypt saltEnc
        crypto_aes256_init(shared_secret, NULL);
        crypto_aes256_decrypt(ext->hmac_secret.saltEnc, ext->hmac_secret.saltLen);

        // Generate outputs
        crypto_sha256_hmac_init(credRandom, 32, output);
        crypto_sha256_update(ext->hmac_secret.saltEnc, 32);
        crypto_sha256_hmac_final(credRandom, 32, output);

        if (ext->hmac_secret.saltLen == 64)
        {
            crypto_sha256_hmac_init(credRandom, 32, output + 32);
            crypto_sha256_update(ext->hmac_secret.saltEnc + 32, 32);
            crypto_sha256_hmac_final(credRandom, 32, output + 32);
        }

        // Encrypt for final output
        crypto_aes256_init(shared_secret, NULL);
        crypto_aes256_encrypt(output, ext->hmac_secret.saltLen);

        // output
        cbor_encoder_init(&extensions, ext_encoder_buf, *ext_encoder_buf_size, 0);
        {
            CborEncoder hmac_secret_map;
            ret = cbor_encoder_create_map(&extensions, &hmac_secret_map, 1);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&hmac_secret_map, "hmac-secret");
                check_ret(ret);

                ret = cbor_encode_byte_string(&hmac_secret_map, output, ext->hmac_secret.saltLen);
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&extensions, &hmac_secret_map);
            check_ret(ret);
        }
        *ext_encoder_buf_size = cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);
    }
    else if (ext->hmac_secret_present == EXT_HMAC_SECRET_REQUESTED)
    {
        cbor_encoder_init(&extensions, ext_encoder_buf, *ext_encoder_buf_size, 0);
        {
            CborEncoder hmac_secret_map;
            ret = cbor_encoder_create_map(&extensions, &hmac_secret_map, 1);
            check_ret(ret);
            {
                ret = cbor_encode_text_stringz(&hmac_secret_map, "hmac-secret");
                check_ret(ret);

                ret = cbor_encode_boolean(&hmac_secret_map, 1);
                check_ret(ret);
            }
            ret = cbor_encoder_close_container(&extensions, &hmac_secret_map);
            check_ret(ret);
        }
        *ext_encoder_buf_size = cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);
    }
    else
    {
        *ext_encoder_buf_size = 0;
    }
    return 0;
}
#endif

static int ctap2_user_presence_test(const char* title, const char* prompt)
{
    device_set_status(CTAPHID_STATUS_UPNEEDED);
    int ret = ctap_user_presence_test(title, prompt, CTAP2_UP_DELAY_MS);
    if ( ret > 1 )
    {
        return CTAP2_ERR_PROCESSING;
    }
    else if ( ret > 0 )
    {
        return CTAP1_ERR_SUCCESS;
    }
    else if (ret < 0)
    {
        return CTAP2_ERR_KEEPALIVE_CANCEL;
    }
    else
    {
        return CTAP2_ERR_ACTION_TIMEOUT;
    }
}

static bool ctap_confirm_authentication(struct rpId* rp, bool up, bool uv)
{
    (void)up;
    (void)uv;
    char prompt_buf[100];
    size_t prompt_size;
    if (rp->name && rp->name[0] != '\0') {
        /* There is a human-readable name attached to this domain. */
        prompt_size = snprintf(prompt_buf, 100, "Authenticate on\n%s\n(%.*s)\n",
                                  rp->name, (int)rp->size, rp->id);
    } else {
        prompt_size = snprintf(prompt_buf, 100, "Authenticate on\n%.*s\n",
                                  (int)rp->size, rp->id);
    }
    if (prompt_size >= 100) {
        prompt_buf[99] = '\0';
    }
    int result = ctap2_user_presence_test("FIDO2", prompt_buf);
    return result == CTAP1_ERR_SUCCESS;
}

/**
 * @param sig[in] Location to deposit signature (must be 64 bytes)
 * @param out_encoded_sig[in] Location to deposit der signature (must be 72 bytes)
 * @return Length of DER encoded signature.
 * // FIXME add tests for maximum and minimum length of the input and output
 */
static int _encode_der_sig(const uint8_t* sig, uint8_t* out_encoded_sig)
{
    // Need to caress into dumb der format ..
    uint8_t lead_s = 0;  // leading zeros
    uint8_t lead_r = 0;
    for (int i=0; i < 32; i++) {
        if (sig[i] == 0) {
            lead_r++;
        }
        else {
            break;
        }
    }

    for (int i=0; i < 32; i++) {
        if (sig[i+32] == 0) {
            lead_s++;
        }
        else {
            break;
        }
    }

    int8_t pad_s = ((sig[32 + lead_s] & 0x80) == 0x80);
    int8_t pad_r = ((sig[0 + lead_r] & 0x80) == 0x80);

    memset(out_encoded_sig, 0, 72);
    out_encoded_sig[0] = 0x30;
    out_encoded_sig[1] = 0x44 + pad_s + pad_r - lead_s - lead_r;

    // R ingredient
    out_encoded_sig[2] = 0x02;
    out_encoded_sig[3 + pad_r] = 0;
    out_encoded_sig[3] = 0x20 + pad_r - lead_r;
    memmove(out_encoded_sig + 4 + pad_r, sig + lead_r, 32u - lead_r);

    // S ingredient
    out_encoded_sig[4 + 32 + pad_r - lead_r] = 0x02;
    out_encoded_sig[5 + 32 + pad_r + pad_s - lead_r] = 0;
    out_encoded_sig[5 + 32 + pad_r - lead_r] = 0x20 + pad_s - lead_s;
    memmove(out_encoded_sig + 6 + 32 + pad_r + pad_s - lead_r, sig + 32u + lead_s, 32u - lead_s);

    return 0x46 + pad_s + pad_r - lead_r - lead_s;
}

/**
 * Computes the EC256 
 * See [WebAuthn], 8.2 "Signing procedure"
 * require load_key prior to this
 * @param[in] auth_data Authenticator data for the attestation.
 * @param[in] auth_data_len Length of auth_data.
 * @param[in] client_data_hash Hash of the serialized client data.
 * @param[out] sigbuf_out Buffer in which to store the computed signature
 */
static bool _calculate_signature(const uint8_t* privkey, uint8_t* auth_data, size_t auth_data_len, uint8_t* client_data_hash, uint8_t* sigbuf_out)
{
    uint8_t hash_buf[SHA256_LEN];

    sha256_context_t ctx;
    sha256_reset(&ctx);
    noise_sha256_update(&ctx, auth_data, auth_data_len);
    noise_sha256_update(&ctx, client_data_hash, CLIENT_DATA_HASH_SIZE);
    sha256_finish(&ctx, hash_buf);
    if (!securechip_ecc_unsafe_sign(privkey, hash_buf, sigbuf_out)) {
        return false;
    }
    return true;
}

/**
 * Adds the encoding of an attestation statement into a CBOR encoder.
 *
 * @param map[in] Encoder in which to append the attestation statement.
 * @param signature[in] Signature to add to the statement.
 * @param len[in] Length of signature.
 * @return Error code (or 0 for success).
 */
static uint8_t _add_attest_statement(CborEncoder* map, const uint8_t* signature, int len)
{
    int ret;
    /* TODO: simo: generate another cert? */
    const uint8_t *cert = FIDO2_ATT_CERT;
    uint16_t cert_size = FIDO2_ATT_CERT_SIZE;

    CborEncoder stmtmap;
    CborEncoder x5carr;

    ret = cbor_encode_int(map, RESP_attStmt);
    check_ret(ret);
    ret = cbor_encoder_create_map(map, &stmtmap, 3);
    check_ret(ret);
    {
        ret = cbor_encode_text_stringz(&stmtmap,"alg");
        check_ret(ret);
        ret = cbor_encode_int(&stmtmap, COSE_ALG_ES256);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"sig");
        check_ret(ret);
        ret = cbor_encode_byte_string(&stmtmap, signature, len);
        check_ret(ret);
    }
    {
        ret = cbor_encode_text_stringz(&stmtmap,"x5c");
        check_ret(ret);
        ret = cbor_encoder_create_array(&stmtmap, &x5carr, 1);
        check_ret(ret);
        {
            ret = cbor_encode_byte_string(&x5carr, cert, cert_size);
            check_ret(ret);
            ret = cbor_encoder_close_container(&stmtmap, &x5carr);
            check_ret(ret);
        }
    }

    ret = cbor_encoder_close_container(map, &stmtmap);
    check_ret(ret);
    return 0;
}

/**
 * Computes the sha256 hash of the given RP id.
 * @param rp_hash_out Buffer in which to store the computed hash.
 *                    Must be SHA256_LEN bytes wide.
 */
static void _compute_rpid_hash(struct rpId* rp, uint8_t* rp_hash_out) {
    if (wally_sha256(rp->id, rp->size, rp_hash_out, SHA256_LEN) != WALLY_OK) {
        Abort("wally_sha256 failed");
    }
}


/**
 * Asks the user for confirmation when
 * a stored FIDO2 credential is about
 * to be overwritten with a new one for
 * the same user.
 */
static bool _confirm_overwrite_credential(void) {
    /* TODO */
    return true;
}

/**
 * Asks the user whether he wants to proceed
 * with the creation of a new credential.
 * @param req MakeCredential CTAP request.
 * @return Whether the user has agreed or not.
 */
static bool _allow_make_credential(CTAP_makeCredential* req)
{
    char prompt_buf[100];
    size_t prompt_size;
    if (req->rp.name && req->rp.name[0] != '\0') {
        /* There is a human-readable name attached to this domain. */
        prompt_size = snprintf(prompt_buf, 100, "Create credential for\n%s\n(%.*s)\n",
                               req->rp.name, (int)req->rp.size, req->rp.id);
    } else {
        prompt_size = snprintf(prompt_buf, 100, "Create credential for\n%.*s\n",
                               (int)req->rp.size, req->rp.id);
    }
    if (prompt_size >= 100) {
        prompt_buf[99] = '\0';
    }
    return workflow_confirm_with_timeout(
        "FIDO2", prompt_buf, NULL, false, 
        /*
         * We don't have realtime measures, 
         * just use a heuristic to convert ms -> #ticks
         */
        CTAP2_UP_DELAY_MS * 4.7
        );
}

/**
 * Check if any of the keys in a MakeCredential's
 * excludeList belong to our device.
 *
 * @param req MakeCredential request to analyze.
 * @return Verification status:
 *             - 0 if no invalid key was found;
 *             - CTAP2_ERR_CREDENTIAL_EXCLUDED if an excluded key belongs to us;
 *             - other errors if we failed to parse the exclude list.
 */
static uint8_t _verify_exclude_list(CTAP_makeCredential* req)
{
    for (size_t i = 0; i < req->excludeListSize; i++) {
        u2f_keyhandle_t excl_cred;
        bool cred_valid;
        uint8_t ret = parse_credential_descriptor(&req->excludeList, &excl_cred, &cred_valid);
        if (!cred_valid || ret == CTAP2_ERR_CBOR_UNEXPECTED_TYPE) {
            /* Skip credentials that fail to parse. */
            continue;
        }
        check_retr(ret);

        uint8_t privkey[HMAC_SHA256_LEN];
        UTIL_CLEANUP_32(privkey);
        bool key_is_ours = u2f_keyhandle_verify(req->rp.id, (uint8_t*)&excl_cred, sizeof(excl_cred), privkey);
        if (key_is_ours)
        {
            printf1(TAG_MC, "Cred %u failed!\r\n",i);
            return true;
        }

        ret = cbor_value_advance(&req->excludeList);
        check_ret(ret);
    }
    return false;
}

static uint8_t ctap_make_credential(CborEncoder * encoder, const uint8_t* request, int length) {
    CTAP_makeCredential MC;
    int ret;

    ret = ctap_parse_make_credential(&MC,encoder, request, length);

    if (ret != 0) {
        printf2(TAG_ERR,"error, parse_make_credential failed\n");
        return ret;
    }
    if (MC.pinAuthEmpty) {
        /*
         * pinAuth was present and was an empty string.
         * The client is asking us if we support pin
         * (and asks to check for user presence before we move on).
         */
        check_retr(ctap2_user_presence_test("FIDO2 pin", "Pin auth"));
        /* We don't support PIN semantics. */
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask) {
        printf2(TAG_ERR,"error, required parameter(s) for makeCredential are missing\n");
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    if (MC.pinAuthPresent) {
        /* We don't support pinAuth. */
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if (MC.up == 1 || MC.up == 0) {
        /*
         * The UP flag can't be set for authenticatorMakeCredential.
         * It must always be unset (0xFF).
         */
        return CTAP2_ERR_INVALID_OPTION;
    }

    if (!workflow_unlock()) {
        /*
         * User didn't authenticate.
         * Let's count this as a "user denied" error.
         */
        return CTAP2_ERR_OPERATION_DENIED;
    }

    /*
     * Request permission to the user.
     * This must be done before checking for excluded credentials etc.
     * so that we don't reveal the existance of credentials without
     * the user's consent.
     */
    if (!_allow_make_credential(&MC)) {
        return CTAP2_ERR_OPERATION_DENIED;
    }

    /*
     * The exclude list contains a list of credentials that we
     * must check. If any credential was generated by our device,
     * we must return with an error. This allows the server to avoid
     * us creating more than one credential for the same user/device pair.
     */
    ret = _verify_exclude_list(&MC);
    check_ret(ret);

    /* Update the U2F counter. */
    uint32_t u2f_counter;
    if (!securechip_u2f_counter_inc(&u2f_counter)) {
        return CTAP2_ERR_OPERATION_DENIED;
    }

    ctap_auth_data_t auth_data;
    _compute_rpid_hash(&MC.rp, auth_data.head.rpIdHash);

    device_set_status(CTAPHID_STATUS_PROCESSING);

    /* Generate the key. */
    memset((uint8_t*)&auth_data.attest.id, 0, sizeof(u2f_keyhandle_t));
    uint8_t* nonce = auth_data.attest.id.nonce;
    uint8_t* mac = auth_data.attest.id.mac;
    uint8_t pubkey[64];
    uint8_t privkey[HMAC_SHA256_LEN];
    UTIL_CLEANUP_32(privkey);
    bool key_create_success = u2f_keyhandle_create_key(MC.rp.id, nonce, privkey, mac, pubkey);
    if (!key_create_success) {
        /* TODO: simo: do something. */
        Abort("Failed to create new FIDO2 key.");
    }

    /*
     * Find where to store this key.
     * If it's new, store it in the first
     * available location. Otherwise, overwrite
     * the existing key (after confirming with the user).
     */
    if (MC.credInfo.rk) {
        ctap_resident_key_t rk_to_store;
        memset(&rk_to_store, 0, sizeof(rk_to_store));
        memcpy(&rk_to_store.key_handle, &auth_data.attest.id, sizeof(rk_to_store.key_handle));
        memcpy(&rk_to_store.rp_id_hash, auth_data.head.rpIdHash, sizeof(auth_data.head.rpIdHash));
        _copy_or_truncate((char*)rk_to_store.rp_id, sizeof(rk_to_store.rp_id), (const char*)MC.rp.id);
        _copy_or_truncate((char*)rk_to_store.user_name, sizeof(rk_to_store.user_name), (const char*)MC.credInfo.user.name);
        _copy_or_truncate((char*)rk_to_store.display_name, sizeof(rk_to_store.display_name), (const char*)MC.credInfo.user.displayName);
        rk_to_store.valid = CTAP_RESIDENT_KEY_VALID;
        rk_to_store.creation_time = u2f_counter;

        int store_location = 0;
        bool must_overwrite = false;
        bool free_spot_found = false;

        for (int i = 0; i < MEMORY_CTAP_RESIDENT_KEYS_MAX; i++) {
            /* Check if we want to overwrite */
            ctap_resident_key_t this_key;
            bool mem_result = memory_get_ctap_resident_key(i, &this_key);
            if (!mem_result) {
                /* Skip on error */
                continue;
            }
            if (this_key.valid != CTAP_RESIDENT_KEY_VALID) {
                /* Skip invalid keys, mark spot as free */
                if (!free_spot_found) {
                    store_location = i;
                    free_spot_found = true;
                }
                continue;
            }
            if (_is_matching_rk(&rk_to_store, &this_key)) {
                /* Found a matching key. Need to overwrite. */
                free_spot_found = true;
                must_overwrite = true;
                store_location = i;
                break;
            }
        }
        if (!free_spot_found) {
            printf2(TAG_ERR, "Out of memory for resident keys\r\n");
            return CTAP2_ERR_KEY_STORE_FULL;
        }
        if (must_overwrite) {
            if (!_confirm_overwrite_credential()) {
                return CTAP2_ERR_OPERATION_DENIED;
            }
        }
        memory_store_ctap_resident_key(store_location, &rk_to_store);
        screen_print_debug("Stored key\n", 500);
    }

    /*
     * Now create the response.
     * This is an attestation object, as defined
     * in [WebAuthn], 6.4 (Figure 5).
     */
    CborEncoder attest_obj;
    ret = cbor_encoder_create_map(encoder, &attest_obj, 3);
    check_ret(ret);

    /*
     * First comes the Authenticator Data.
     * (Note: the rpId has already been stored at the start of auth_data...)
     */
    auth_data.head.flags = CTAP_AUTH_DATA_FLAG_ATTESTED_CRED_DATA_INCLUDED |
        CTAP_AUTH_DATA_FLAG_USER_VERIFIED | CTAP_AUTH_DATA_FLAG_USER_PRESENT;

    _encode_u2f_counter(u2f_counter, (uint8_t*)&auth_data.head.signCount);

    device_read_aaguid(auth_data.attest.aaguid);
 
    /* Encode the length of the key handle in big endian. */
    uint16_t key_length = sizeof(u2f_keyhandle_t);
    auth_data.attest.cred_len[0] = (key_length & 0xFF00) >> 8;
    auth_data.attest.cred_len[1] =  (key_length & 0x00FF);

    printf1(TAG_GREEN, "MADE credId");

    CborEncoder cose_key;
    uint8_t* cose_key_buf = auth_data.other;
    cbor_encoder_init(&cose_key, cose_key_buf, sizeof(auth_data.other), 0);
    ret = ctap_add_cose_key(&cose_key, pubkey, pubkey + 32, COSE_ALG_ES256);
    check_retr(ret);
    size_t cose_key_len = cbor_encoder_get_buffer_size(&cose_key, cose_key_buf);
    size_t actual_auth_data_len = sizeof(auth_data) - sizeof(auth_data.other) + cose_key_len;

    #if 0
    /* TODO: simone: manage extensions */
    {
        unsigned int ext_encoder_buf_size = sizeof(auth_data.other) - actual_auth_data_len;
        uint8_t* ext_encoder_buf = auth_data.other + cose_key_len;

        ret = ctap_make_extensions(&MC.extensions, ext_encoder_buf, &ext_encoder_buf_size);
        check_retr(ret);
        if (ext_encoder_buf_size)
        {
            ((ctap_auth_data_t *)auth_data_buf)->head.flags |= CTAP_AUTH_DATA_FLAG_EXTENSION_DATA_INCLUDED;
            actual_auth_data_len += ext_encoder_buf_size;
        }
    }
    #endif

    /*
     * 3 fields in an attestation object:
     * - fmt
     * - authData
     * - attStmt
     */
    {
        ret = cbor_encode_int(&attest_obj, RESP_fmt);
        check_ret(ret);
        ret = cbor_encode_text_stringz(&attest_obj, "packed");
        check_ret(ret);
    }


    {
        ret = cbor_encode_int(&attest_obj, RESP_authData);
        check_ret(ret);
        ret = cbor_encode_byte_string(&attest_obj, (uint8_t*)&auth_data, actual_auth_data_len);
        check_ret(ret);
    }

    /* Compute the attestation statement. */
    uint8_t sigbuf[32];
    bool sig_success = _calculate_signature(FIDO2_ATT_PRIV_KEY, (uint8_t*)&auth_data, actual_auth_data_len, MC.clientDataHash, sigbuf);
    if (!sig_success) {
        return CTAP1_ERR_OTHER;
    }
    uint8_t attest_signature[72];
    int attest_sig_size = _encode_der_sig(sigbuf, attest_signature);

    ret = _add_attest_statement(&attest_obj, attest_signature, attest_sig_size);
    check_retr(ret);

    ret = cbor_encoder_close_container(encoder, &attest_obj);
    check_ret(ret);
    return CTAP1_ERR_SUCCESS;
}

static uint8_t ctap_add_credential_descriptor(CborEncoder* map, u2f_keyhandle_t* key_handle)
{
    CborEncoder desc;
    int ret = cbor_encode_int(map, RESP_credential);
    check_ret(ret);

    ret = cbor_encoder_create_map(map, &desc, 2);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&desc, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&desc, (uint8_t*)key_handle,
                sizeof(*key_handle));
        check_ret(ret);
    }

    {
        ret = cbor_encode_text_string(&desc, "type", 4);
        check_ret(ret);

        ret = cbor_encode_text_string(&desc, "public-key", 10);
        check_ret(ret);
    }


    ret = cbor_encoder_close_container(map, &desc);
    check_ret(ret);

    return 0;
}

#if 0
static uint8_t ctap_add_user_entity(CborEncoder * map, ctap_user_entity_t * user)
{
    CborEncoder entity;
    int ret = cbor_encode_int(map, RESP_publicKeyCredentialUserEntity);
    check_ret(ret);

    int dispname = (user->name[0] != 0) && getAssertionState.user_verified;

    if (dispname)
        ret = cbor_encoder_create_map(map, &entity, 4);
    else
        ret = cbor_encoder_create_map(map, &entity, 1);
    check_ret(ret);

    {
        ret = cbor_encode_text_string(&entity, "id", 2);
        check_ret(ret);

        ret = cbor_encode_byte_string(&entity, user->id, user->id_size);
        check_ret(ret);
    }

    if (dispname)
    {

        ret = cbor_encode_text_string(&entity, "icon", 4);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->icon);
        check_ret(ret);

        ret = cbor_encode_text_string(&entity, "name", 4);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->name);
        check_ret(ret);

        ret = cbor_encode_text_string(&entity, "displayName", 11);
        check_ret(ret);

        ret = cbor_encode_text_stringz(&entity, (const char *)user->displayName);
        check_ret(ret);

    }

    ret = cbor_encoder_close_container(map, &entity);
    check_ret(ret);

    return 0;
}
#endif

/**
 * Comparator function used to qsort() the credentials.
 * @return >0 if b is more recent than a, 0 if they have the same age (should never happen!),
 *         <0 otherwise.
 */
static int _compare_display_credentials(const void * _a, const void * _b)
{
    const ctap_credential_display_t* a = (const ctap_credential_display_t* )_a;
    const ctap_credential_display_t* b = (const ctap_credential_display_t* )_b;
    return b->creation_time - a->creation_time;
}

#if 0
static void add_existing_user_info(CTAP_credentialDescriptor * cred)
{
    CTAP_residentKey rk;
    int i;
    char* 
    for (i = 0; i < STATE.rk_stored; ++i) {
        ctap_load_rk(i, &rk);
        if (_is_matching_rk(&rk, (CTAP_residentKey *)&cred->credential))
        {
            printf1(TAG_GREEN, "found rk match for allowList item (%d)\r\n", i);
            memmove(&cred->credential.user, &rk.user, sizeof(ctap_user_entity_t));
            return;
        }
    }
    printf1(TAG_GREEN, "NO rk match for allowList item \r\n");
}

/**
 * Given a GetAssertion request with N credentials in its allow list,
 * check if each credential belongs to this token.
 * Mark the credentials not belonging to this token as having a count of 0 (no age),
 *
 * and return the number of valid credential found.
 * @param credentials Array of pointers. Will be filled with pointers to the credentials
 *                    that have been found. Must be at least CTAP_CREDENTIAL_LIST_MAX_SIZE
 *                    elements wide.
 * @return Number of valid credentials that have been found.
 */
static int _filter_credential_allow_list(CTAP_getAssertion* GA, u2f_keyhandle_t** credentials)
{
    int count = 0;
    for (int i = 0; i < GA->credLen; i++) {
        uint8_t privkey[HMAC_SHA256_LEN];
        UTIL_CLEANUP_32(privkey);
        u2f_keyhandle_t* this_key = &GA->creds[i];
        bool key_valid = u2f_keyhandle_verify(GA->rp.id, this_key, sizeof(*this_key), privkey);
        if (key_valid) {
            credentials[count] = this_key;
        }
    }
    return count;
}
#endif

#if 0
static int ctap_get_matching_rk_for_request(CTAP_getAssertion* GA)
{
    int count = 0;
    ctap_resident_key_t rk;
    uint8_t rpIdHash[32];
    crypto_sha256_init();
    crypto_sha256_update(GA->rp.id, GA->rp.size);
    crypto_sha256_final(rpIdHash);

    printf1(TAG_GREEN, "true rpIdHash: ");  dump_hex1(TAG_GREEN, rpIdHash, 32);
    for(int i = 0; i < STATE.rk_stored; i++) {
        ctap_load_rk(i, &rk);
        printf1(TAG_GREEN, "rpIdHash%d: ", i);  dump_hex1(TAG_GREEN, rk.id.rpIdHash, 32);
        if (memcmp(rk.id.rpIdHash, rpIdHash, 32) == 0) {
            printf1(TAG_GA, "RK %d is a rpId match!\r\n", i);
            if (count == CTAP_CREDENTIAL_LIST_MAX_SIZE-1) {
                printf2(TAG_ERR, "not enough ram allocated for matching RK's (%d).  Skipping.\r\n", count);
                break;
            }
            GA->creds[count].type = PUB_KEY_CRED_PUB_KEY;
            memmove(&(GA->creds[count].credential), &rk, sizeof(CTAP_residentKey));
            count++;
        }
    }
    GA->credLen = count;
    return count;
}
#endif

/**
 * Fills a getAssertion response, as defined in the FIDO2 specs, 5.2.
 *
 * The response map contains: 
 *    - Credential descriptor
 *    - Auth data
 *    - Signature
 *
 * Note that we don't include any user data as there is no need for that
 * (the user has already been selected on the device).
 */
static uint8_t ctap_end_get_assertion(CborEncoder* encoder, u2f_keyhandle_t* key_handle, uint8_t* auth_data_buf, unsigned int auth_data_buf_sz, uint8_t* privkey, uint8_t* clientDataHash)
{
    int ret;
    uint8_t signature[64];
    uint8_t encoded_sig[72];
    int encoded_sig_size;
    CborEncoder map;

    ret = cbor_encoder_create_map(encoder, &map, 3);
    check_ret(ret);

    ret = ctap_add_credential_descriptor(&map, key_handle);  // 1
    check_retr(ret);

    {
        ret = cbor_encode_int(&map, RESP_authData);  // 2
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, auth_data_buf, auth_data_buf_sz);
        check_ret(ret);
    }

    crypto_ecc256_load_key((uint8_t*)key_handle, sizeof(*key_handle), NULL, 0);

    bool sig_success = _calculate_signature(privkey, auth_data_buf, auth_data_buf_sz, clientDataHash, signature);
    if (!sig_success) {
        return CTAP1_ERR_OTHER;
    }
    encoded_sig_size = _encode_der_sig(signature, encoded_sig);

    {
        ret = cbor_encode_int(&map, RESP_signature);  // 3
        check_ret(ret);
        ret = cbor_encode_byte_string(&map, encoded_sig, encoded_sig_size);
        check_ret(ret);
    }
    ret = cbor_encoder_close_container(encoder, &map);
    return 0;
}

#if 0
static uint8_t ctap_get_next_assertion(CborEncoder* encoder)
{
    /*
     * We always select the credentials to login with
     * on the device screen, and send back a response with
     * a single credential. Hence "get_next_assertion" should
     * never be called (we never have any further buffered
     * credential to send). See section 5.3 point 1 of the FIDO2 specs.
     */
    (void)encoder;
    return CTAP2_ERR_NOT_ALLOWED;
}
#endif

/**
 * Selects one of the matching credentials in the given credential list.
 *
 * @param GA getAssertion request that must be examined. Must contain
 *           an allow list.
 * @param chosen_credential_out Will be filled with a pointer to the chosen credential,
 *                              or NULL if no key was found.
 * @param chosen_privkey Will be filled with the the private key corresponding to chosen_credential.
 *                       Must be at least HMAC_SHA256_LEN bytes wide.
 */
static void _authenticate_with_allow_list(CTAP_getAssertion* GA, u2f_keyhandle_t** chosen_credential_out, uint8_t* chosen_privkey)
{
    /*
     * We can just pick the first credential that we're able to authenticate with.
     * No need to ask the user to select one if many credentials match.
     * See Client to Authenticator Protocol, 5.2, point 9.
     */
    for (int i = 0; i < GA->credLen; i++) {
        u2f_keyhandle_t* this_key = GA->creds + i;
        bool key_valid = u2f_keyhandle_verify(GA->rp.id, (uint8_t*)this_key, sizeof(*this_key), chosen_privkey);
        if (key_valid) {
            /* Found an applicable credential. */
            *chosen_credential_out = this_key;
            return;
        }
    }
    /* No keys were found. */
    util_zero(chosen_privkey, HMAC_SHA256_LEN);
    *chosen_credential_out = NULL;
}

/**
 * Selects one of the stored credentials for authentication.
 *
 * @param GA getAssertion request that must be examined. Must contain
 *           an allow list.
 * @param chosen_credential_out Will be filled with the chosen credential.
 * @param chosen_privkey Will be filled with the the private key corresponding to chosen_credential.
 *                       Must be at least HMAC_SHA256_LEN bytes wide.
 */
static uint8_t _authenticate_with_rk(CTAP_getAssertion* GA, u2f_keyhandle_t* chosen_credential_out, uint8_t* chosen_privkey)
{
    /*
     * For each credential that we display, save which RK id it corresponds to.
     */
    int cred_idx[CTAP_CREDENTIAL_LIST_MAX_SIZE];
    ctap_credential_display_list_t creds;
    creds.n_elems = 0;

    /*
     * Compute the hash of the RP id so that we
     * can match it against the keys we have in memory.
     */
    uint8_t rp_id_hash[SHA256_LEN];
    _compute_rpid_hash(&GA->rp, rp_id_hash);
    /* Check all keys that match this RP. */
    for (int i = 0; i < MEMORY_CTAP_RESIDENT_KEYS_MAX; i++) {
        ctap_resident_key_t this_key;
        bool mem_result = memory_get_ctap_resident_key(i, &this_key);
        if (!mem_result || this_key.valid != CTAP_RESIDENT_KEY_VALID) {
            continue;
        }
        if (!memcmp(this_key.rp_id_hash, rp_id_hash, SHA256_LEN)) {
            /*
             * This key matches the RP! Add its user information to
             * our list.
             */
            cred_idx[creds.n_elems] = i;
            ctap_credential_display_t* this_cred = creds.creds + creds.n_elems;
            memcpy(this_cred->username, this_key.user_name, sizeof(this_key.user_name));
            memcpy(this_cred->display_name, this_key.display_name, sizeof(this_key.display_name));
            creds.n_elems++;
            if (creds.n_elems == CTAP_CREDENTIAL_LIST_MAX_SIZE) {
                /* No more space */
                break;
            }
        }
    }
    if (creds.n_elems == 0) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    /* Sort credentials by creation time. */
    qsort(creds.creds, creds.n_elems, sizeof(*creds.creds), _compare_display_credentials);
    int selected_cred = workflow_select_ctap_credential(&creds);
    if (selected_cred < 0) {
        /* User aborted. */
        return CTAP2_ERR_OPERATION_DENIED;
    }

    /* Now load the credential that was selected in the output buffer. */
    ctap_resident_key_t selected_key;
    bool mem_result = memory_get_ctap_resident_key(cred_idx[selected_cred], &selected_key);

    if (!mem_result) {
        /* Shouldn't happen, but if it does we effectively don't have any valid credential to provide. */
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    memcpy(chosen_credential_out, &selected_key.key_handle, sizeof(selected_key.key_handle));
    /* Sanity check the key and extract the private key. */
    bool key_valid = u2f_keyhandle_verify(GA->rp.id, (uint8_t*)chosen_credential_out, sizeof(*chosen_credential_out), chosen_privkey);
    if (!key_valid) {
        return CTAP2_ERR_NO_CREDENTIALS;
    }
    return CTAP1_ERR_SUCCESS;
}

/**
 * @param auth_data_buf Must be at least sizeof(ctap_auth_data_t) bytes wide.
 * @param data_buf_len_out Will be filled with the actual auth data size.
 */
static uint8_t _make_authentication_response(CTAP_getAssertion* GA, uint8_t* auth_data_buf, size_t* data_buf_len_out) {
    ctap_auth_data_header_t* auth_data_header = (ctap_auth_data_header_t*)auth_data_buf;

    auth_data_header->flags = 0;
    if (GA->up) {
        auth_data_header->flags |= CTAP_AUTH_DATA_FLAG_USER_PRESENT;        // User presence
    }
    if (GA->uv) {
        auth_data_header->flags |= CTAP_AUTH_DATA_FLAG_USER_VERIFIED;        // User presence
    }

    _compute_rpid_hash(&GA->rp, auth_data_header->rpIdHash);

    /* Update the U2F counter. */
    uint32_t u2f_counter;
    if (!securechip_u2f_counter_inc(&u2f_counter)) {
        return CTAP2_ERR_OPERATION_DENIED;
    }
    _encode_u2f_counter(u2f_counter, (uint8_t*)&auth_data_header->signCount);

    uint32_t actual_auth_data_size = sizeof(ctap_auth_data_header_t);

    #if 0
        /* TODO: simone: do something */
    if (GA->extensions.hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
        printf1(TAG_GA, "hmac-secret is present\r\n");
        /* TODO: simone: do something */
        GA->extensions.hmac_secret.key_handle = key_handle;

    }

    {
        /* Add extensions to the output data. */
        unsigned int ext_encoder_buf_size = auth_data_buf_len - actual_auth_data_size;
        uint8_t * ext_encoder_buf = auth_data_buf + actual_auth_data_size;

        ret = ctap_make_extensions(&GA->extensions, ext_encoder_buf, &ext_encoder_buf_size);
        check_retr(ret);
        if (ext_encoder_buf_size)
        {
            ((ctap_auth_data_header_t *)auth_data_buf)->flags |= CTAP_AUTH_DATA_FLAG_EXTENSION_DATA_INCLUDED;
            actual_auth_data_size += ext_encoder_buf_size;
        }
    }
    #endif
    *data_buf_len_out = actual_auth_data_size;
    return CTAP1_ERR_SUCCESS;
}

static uint8_t ctap_get_assertion(CborEncoder * encoder, const uint8_t* request, int length)
{
    CTAP_getAssertion GA;

    uint8_t auth_data_buf[sizeof(ctap_auth_data_header_t) + 80];
    int ret = ctap_parse_get_assertion(&GA, request, length);

    if (ret != 0) {
        printf2(TAG_ERR,"error, parse_get_assertion failed\n");
        return ret;
    }

    if (GA.pinAuthEmpty) {
        check_retr(ctap2_user_presence_test("FIDO2", "pinAuthEmpty"));
        return CTAP2_ERR_PIN_NOT_SET;
    }
    if (GA.pinAuthPresent) {
        /* We don't support pinAuth. */
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    if (!GA.rp.size || !GA.clientDataHashPresent) {
        /* Both parameters are mandatory. */
        return CTAP2_ERR_MISSING_PARAMETER;
    }

    printf1(TAG_GA, "CTAP_CREDENTIAL_LIST_MAX_SIZE has %d creds\n", GA.credLen);

    /*
     * Ask the user to confirm that he wants to authenticate.
     * This must be done before we check for credentials so that
     * we don't disclose the existance of credentials before the
     * user has proven his identity (See 5.2, point 7).
     */
    if (!ctap_confirm_authentication(&GA.rp, GA.up, GA.uv)) {
        return CTAP2_ERR_OPERATION_DENIED;
    }

    u2f_keyhandle_t auth_credential;
    uint8_t auth_privkey[HMAC_SHA256_LEN];
    UTIL_CLEANUP_32(auth_privkey);
    if (GA.credLen) {
        // allowlist is present -> check all the credentials that were actually generated by us.
        u2f_keyhandle_t* chosen_credential = NULL;
        _authenticate_with_allow_list(&GA, &chosen_credential, auth_privkey);
        if (!chosen_credential) {
            /* No credential selected (or no credential was known to the device). */
            return CTAP2_ERR_NO_CREDENTIALS;
        }
        memcpy(&auth_credential, chosen_credential, sizeof(auth_credential));
    } else {
        // No allowList, so use all matching RK's matching rpId
        uint8_t auth_status = _authenticate_with_rk(&GA, &auth_credential, auth_privkey);
        if (auth_status != 0) {
            return auth_status;
        }
    }

    size_t actual_auth_data_size;
    ret = _make_authentication_response(&GA, auth_data_buf, &actual_auth_data_size);
    check_ret(ret);

    ret = ctap_end_get_assertion(encoder, &auth_credential, auth_data_buf, actual_auth_data_size, auth_privkey, GA.clientDataHash);
    check_ret(ret);

    return 0;
}

// Return how many trailing zeros in a buffer
static int trailing_zeros(uint8_t * buf, int indx)
{
    int c = 0;
    while(0==buf[indx] && indx)
    {
        indx--;
        c++;
    }
    return c;
}

uint8_t ctap_update_pin_if_verified(uint8_t * pinEnc, int len, uint8_t * platform_pubkey, uint8_t * pinAuth, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];
    uint8_t hmac[32];
    int ret;

//    Validate incoming data packet len
    if (len < 64)
    {
        return CTAP1_ERR_OTHER;
    }

//    Validate device's state
    if (ctap_is_pin_set())  // Check first, prevent SCA
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
    }

//    calculate shared_secret
    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_sha256_hmac_init(shared_secret, 32, hmac);
    crypto_sha256_update(pinEnc, len);
    if (pinHashEnc != NULL)
    {
        crypto_sha256_update(pinHashEnc, 16);
    }
    crypto_sha256_hmac_final(shared_secret, 32, hmac);

    if (memcmp(hmac, pinAuth, 16) != 0)
    {
        printf2(TAG_ERR,"pinAuth failed for update pin\n");
        dump_hex1(TAG_ERR, hmac,16);
        dump_hex1(TAG_ERR, pinAuth,16);
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

//     decrypt new PIN with shared secret
    crypto_aes256_init(shared_secret, NULL);

    while((len & 0xf) != 0) // round up to nearest  AES block size multiple
    {
        len++;
    }

    crypto_aes256_decrypt(pinEnc, len);

//      validate new PIN (length)

    ret = trailing_zeros(pinEnc, NEW_PIN_ENC_MIN_SIZE - 1);
    ret = NEW_PIN_ENC_MIN_SIZE  - ret;

    if (ret < NEW_PIN_MIN_SIZE || ret >= NEW_PIN_MAX_SIZE)
    {
        printf2(TAG_ERR,"new PIN is too short or too long [%d bytes]\n", ret);
        return CTAP2_ERR_PIN_POLICY_VIOLATION;
    }
    else
    {
        printf1(TAG_CP,"new pin: %s [%d bytes]\n", pinEnc, ret);
        dump_hex1(TAG_CP, pinEnc, ret);
    }

//    validate device's state, decrypt and compare pinHashEnc (user provided current PIN hash) with stored PIN_CODE_HASH

    if (ctap_is_pin_set())
    {
        if (ctap_device_locked())
        {
            return CTAP2_ERR_PIN_BLOCKED;
        }
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        crypto_aes256_reset_iv(NULL);
        crypto_aes256_decrypt(pinHashEnc, 16);

        uint8_t pinHashEncSalted[32];
        crypto_sha256_init();
        crypto_sha256_update(pinHashEnc, 16);
        crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
        crypto_sha256_final(pinHashEncSalted);

        if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 16) != 0)
        {
            ctap_reset_key_agreement();
            ctap_decrement_pin_attempts();
            if (ctap_device_boot_locked())
            {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }
            return CTAP2_ERR_PIN_INVALID;
        }
        else
        {
            ctap_reset_pin_attempts();
        }
    }

//      set new PIN (update and store PIN_CODE_HASH)
    ctap_update_pin(pinEnc, ret);

    return 0;
}

uint8_t ctap_add_pin_if_verified(uint8_t * pinTokenEnc, uint8_t * platform_pubkey, uint8_t * pinHashEnc)
{
    uint8_t shared_secret[32];

    crypto_ecc256_shared_secret(platform_pubkey, KEY_AGREEMENT_PRIV, shared_secret);

    crypto_sha256_init();
    crypto_sha256_update(shared_secret, 32);
    crypto_sha256_final(shared_secret);

    crypto_aes256_init(shared_secret, NULL);

    crypto_aes256_decrypt(pinHashEnc, 16);

    uint8_t pinHashEncSalted[32];
    crypto_sha256_init();
    crypto_sha256_update(pinHashEnc, 16);
    crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
    crypto_sha256_final(pinHashEncSalted);
    if (memcmp(pinHashEncSalted, STATE.PIN_CODE_HASH, 16) != 0)
    {
        printf2(TAG_ERR,"Pin does not match!\n");
        printf2(TAG_ERR,"platform-pin-hash: "); dump_hex1(TAG_ERR, pinHashEnc, 16);
        printf2(TAG_ERR,"authentic-pin-hash: "); dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, 16);
        printf2(TAG_ERR,"shared-secret: "); dump_hex1(TAG_ERR, shared_secret, 32);
        printf2(TAG_ERR,"platform-pubkey: "); dump_hex1(TAG_ERR, platform_pubkey, 64);
        printf2(TAG_ERR,"device-pubkey: "); dump_hex1(TAG_ERR, KEY_AGREEMENT_PUB, 64);
        // Generate new keyAgreement pair
        ctap_reset_key_agreement();
        ctap_decrement_pin_attempts();
        if (ctap_device_boot_locked())
        {
            return CTAP2_ERR_PIN_AUTH_BLOCKED;
        }
        return CTAP2_ERR_PIN_INVALID;
    }

    ctap_reset_pin_attempts();
    crypto_aes256_reset_iv(NULL);

    memmove(pinTokenEnc, PIN_TOKEN, PIN_TOKEN_SIZE);
    crypto_aes256_encrypt(pinTokenEnc, PIN_TOKEN_SIZE);

    return 0;
}

static uint8_t ctap_client_pin(CborEncoder* encoder, const uint8_t* request, int length)
{
#if 0
    CTAP_clientPin CP;
    CborEncoder map;
    uint8_t pinTokenEnc[PIN_TOKEN_SIZE];
    int ret = ctap_parse_client_pin(&CP,request,length);


    switch(CP.subCommand)
    {
        case CP_cmdSetPin:
        case CP_cmdChangePin:
        case CP_cmdGetPinToken:
            if (ctap_device_locked())
            {
                return  CTAP2_ERR_PIN_BLOCKED;
            }
            if (ctap_device_boot_locked())
            {
                return CTAP2_ERR_PIN_AUTH_BLOCKED;
            }
            break;
        default:
            Abort("CTAP: bad subcommand");
    }

    if (ret != 0)
    {
        printf2(TAG_ERR,"error, parse_client_pin failed\n");
        return ret;
    }

    if (CP.pinProtocol != 1 || CP.subCommand == 0)
    {
        return CTAP1_ERR_OTHER;
    }

    int num_map = (CP.getRetries ? 1 : 0);

    switch(CP.subCommand)
    {
        case CP_cmdGetRetries:
            printf1(TAG_CP,"CP_cmdGetRetries\n");
            ret = cbor_encoder_create_map(encoder, &map, 1);
            check_ret(ret);

            CP.getRetries = 1;

            break;
        case CP_cmdGetKeyAgreement:
            printf1(TAG_CP,"CP_cmdGetKeyAgreement\n");
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            ret = cbor_encode_int(&map, RESP_keyAgreement);
            check_ret(ret);

            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_FAST);
            crypto_ecc256_compute_public_key(KEY_AGREEMENT_PRIV, KEY_AGREEMENT_PUB);
            if (device_is_nfc() == NFC_IS_ACTIVE) device_set_clock_rate(DEVICE_LOW_POWER_IDLE);

            ret = ctap_add_cose_key(&map, KEY_AGREEMENT_PUB, KEY_AGREEMENT_PUB+32, PUB_KEY_CRED_PUB_KEY, COSE_ALG_ECDH_ES_HKDF_256);
            check_retr(ret);

            break;
        case CP_cmdSetPin:
            printf1(TAG_CP,"CP_cmdSetPin\n");

            if (ctap_is_pin_set())
            {
                return CTAP2_ERR_NOT_ALLOWED;
            }
            if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent)
            {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth, NULL);
            check_retr(ret);
            break;
        case CP_cmdChangePin:
            printf1(TAG_CP,"CP_cmdChangePin\n");

            if (! ctap_is_pin_set())
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }

            if (!CP.newPinEncSize || !CP.pinAuthPresent || !CP.keyAgreementPresent || !CP.pinHashEncPresent)
            {
                return CTAP2_ERR_MISSING_PARAMETER;
            }

            ret = ctap_update_pin_if_verified(CP.newPinEnc, CP.newPinEncSize, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinAuth, CP.pinHashEnc);
            check_retr(ret);
            break;
        case CP_cmdGetPinToken:
            if (!ctap_is_pin_set())
            {
                return CTAP2_ERR_PIN_NOT_SET;
            }
            num_map++;
            ret = cbor_encoder_create_map(encoder, &map, num_map);
            check_ret(ret);

            printf1(TAG_CP,"CP_cmdGetPinToken\n");
            if (CP.keyAgreementPresent == 0 || CP.pinHashEncPresent == 0)
            {
                printf2(TAG_ERR,"Error, missing keyAgreement or pinHashEnc for cmdGetPin\n");
                return CTAP2_ERR_MISSING_PARAMETER;
            }
            ret = cbor_encode_int(&map, RESP_pinToken);
            check_ret(ret);

            /*ret = ctap_add_pin_if_verified(&map, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);*/
            ret = ctap_add_pin_if_verified(pinTokenEnc, (uint8_t*)&CP.keyAgreement.pubkey, CP.pinHashEnc);
            check_retr(ret);

            ret = cbor_encode_byte_string(&map, pinTokenEnc, PIN_TOKEN_SIZE);
            check_ret(ret);



            break;

        default:
            printf2(TAG_ERR,"Error, invalid client pin subcommand\n");
            return CTAP1_ERR_OTHER;
    }

    if (CP.getRetries)
    {
        ret = cbor_encode_int(&map, RESP_retries);
        check_ret(ret);
        ret = cbor_encode_int(&map, ctap_leftover_pin_attempts());
        check_ret(ret);
    }

    if (num_map || CP.getRetries)
    {
        ret = cbor_encoder_close_container(encoder, &map);
        check_ret(ret);
    }

    return 0;
#endif
    (void)encoder;
    (void)request;
    (void)length;
    return CTAP2_ERR_NOT_ALLOWED;
}

void ctap_response_init(CTAP_RESPONSE * resp)
{
    memset(resp, 0, sizeof(CTAP_RESPONSE));
    resp->data_size = CTAP_RESPONSE_BUFFER_SIZE;
}

uint8_t ctap_request(const uint8_t * pkt_raw, int length, uint8_t* out_data, size_t* out_len)
{
    CborEncoder encoder;
    memset(&encoder,0,sizeof(CborEncoder));
    uint8_t status = 0;
    uint8_t cmd = *pkt_raw;
    pkt_raw++;
    length--;

    uint8_t* buf = out_data;

    cbor_encoder_init(&encoder, buf, USB_DATA_MAX_LEN, 0);

    printf1(TAG_CTAP,"cbor input structure: %d bytes\n", length);
    printf1(TAG_DUMP,"cbor req: "); dump_hex1(TAG_DUMP, pkt_raw, length);

    printf1(TAG_DUMP,"cbor cmd: %d\n", cmd);

    switch(cmd)
    {
        case CTAP_MAKE_CREDENTIAL:
            printf1(TAG_CTAP,"CTAP_MAKE_CREDENTIAL\n");
            timestamp();
            status = ctap_make_credential(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"make_credential time: %d ms\n", timestamp());

            *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, *out_len);

            break;
        case CTAP_GET_ASSERTION:
            printf1(TAG_CTAP,"CTAP_GET_ASSERTION\n");
            timestamp();
            status = ctap_get_assertion(&encoder, pkt_raw, length);
            printf1(TAG_TIME,"get_assertion time: %d ms\n", timestamp());

            *out_len = cbor_encoder_get_buffer_size(&encoder, buf);

            printf1(TAG_DUMP,"cbor [%u]: \n",  *out_len);
                dump_hex1(TAG_DUMP,buf, *out_len);
            break;
        case CTAP_CANCEL:
            printf1(TAG_CTAP,"CTAP_CANCEL\n");
            break;
        case CTAP_GET_INFO:
            printf1(TAG_CTAP,"CTAP_GET_INFO\n");
            status = ctap_get_info(&encoder);

            *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
            printf("Resp len: %u\n", *out_len);
            dump_hex1(TAG_DUMP, buf, *out_len);

            break;
        case CTAP_CLIENT_PIN:
            printf1(TAG_CTAP,"CTAP_CLIENT_PIN\n");
            status = ctap_client_pin(&encoder, pkt_raw, length);

            *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
            dump_hex1(TAG_DUMP, buf, *out_len);
            break;
        case CTAP_RESET:
#if 0
            printf1(TAG_CTAP,"CTAP_RESET\n");
            status = ctap2_user_presence_test("FIDO2", "Perform reset?");
            if (status == CTAP1_ERR_SUCCESS)
            {
                ctap_reset();
            }
#else
            status = CTAP2_ERR_NOT_ALLOWED;
#endif
            break;
        case GET_NEXT_ASSERTION:
            printf1(TAG_CTAP,"CTAP_NEXT_ASSERTION\n");
#if 0
            if (getAssertionState.lastcmd == CTAP_GET_ASSERTION)
            {
                status = ctap_get_next_assertion(&encoder);
                *out_len = cbor_encoder_get_buffer_size(&encoder, buf);
                dump_hex1(TAG_DUMP, buf, *out_len);
                if (status == 0)
                {
                    cmd = CTAP_GET_ASSERTION;       // allow for next assertion
                }
            }
            else
            {
                printf2(TAG_ERR, "unwanted GET_NEXT_ASSERTION.  lastcmd == 0x%02x\n", getAssertionState.lastcmd);
                status = CTAP2_ERR_NOT_ALLOWED;
            }
#else
            status = CTAP2_ERR_NOT_ALLOWED;
#endif
            break;
        default:
            status = CTAP1_ERR_INVALID_COMMAND;
            printf2(TAG_ERR,"error, invalid cmd: 0x%02x\n", cmd);
    }

    device_set_status(CTAPHID_STATUS_IDLE);

    if (status != CTAP1_ERR_SUCCESS)
    {
        *out_len = 0;
    }

    printf1(TAG_CTAP,"cbor output structure: %u bytes.  Return 0x%02x\n", *out_len, status);

    return status;
}



#if 0
static void ctap_state_init(void)
{
    // Set to 0xff instead of 0x00 to be easier on flash
    memset(&STATE, 0xff, sizeof(AuthenticatorState));
    // Fresh RNG for key
    ctap_generate_rng(STATE.key_space, KEY_SPACE_BYTES);

    STATE.is_initialized = INITIALIZED_MARKER;
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    STATE.is_pin_set = 0;
    STATE.rk_stored = 0;
    STATE.data_version = STATE_VERSION;

    ctap_reset_rk();

    if (ctap_generate_rng(STATE.PIN_SALT, sizeof(STATE.PIN_SALT)) != 1) {
        printf2(TAG_ERR, "Error, rng failed\n");
        exit(1);
    }

    printf1(TAG_STOR, "Generated PIN SALT: ");
    dump_hex1(TAG_STOR, STATE.PIN_SALT, sizeof STATE.PIN_SALT);
}
#endif

/** Overwrite master secret from external source.
 * @param keybytes an array of KEY_SPACE_BYTES length.
 *
 * This function should only be called from a privilege mode.
*/
void ctap_load_external_keys(uint8_t * keybytes){
    memmove(STATE.key_space, keybytes, KEY_SPACE_BYTES);
    authenticator_write_state(&STATE);
    crypto_load_master_secret(STATE.key_space);
}

#include "version.h"
#if 0
void ctap_init(void)
{
    crypto_ecc256_init();

    int is_init = authenticator_read_state(&STATE);

    device_set_status(CTAPHID_STATUS_IDLE);

    if (is_init)
    {
        printf1(TAG_STOR,"Auth state is initialized\n");
    }
    else
    {
        ctap_state_init();
        authenticator_write_state(&STATE);
    }

    //do_migration_if_required(&STATE);

    crypto_load_master_secret(STATE.key_space);

    if (ctap_is_pin_set())
    {
        printf1(TAG_STOR, "attempts_left: %d\n", STATE.remaining_tries);
    }
    else
    {
        printf1(TAG_STOR,"pin not set.\n");
    }
    if (ctap_device_locked())
    {
        printf1(TAG_ERR, "DEVICE LOCKED!\n");
    }

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        exit(1);
    }

    ctap_reset_key_agreement();

#ifdef BRIDGE_TO_WALLET
    wallet_init();
#endif


}
#endif

uint8_t ctap_is_pin_set(void)
{
    return STATE.is_pin_set == 1;
}

/**
 * Set new PIN, by updating PIN hash. Save state.
 * Globals: STATE
 * @param pin new PIN (raw)
 * @param len pin array length
 */
void ctap_update_pin(uint8_t * pin, int len)
{
    if (len >= NEW_PIN_ENC_MIN_SIZE || len < 4)
    {
        printf2(TAG_ERR, "Update pin fail length\n");
        exit(1);
    }

    crypto_sha256_init();
    crypto_sha256_update(pin, len);
    uint8_t intermediateHash[32];
    crypto_sha256_final(intermediateHash);

    crypto_sha256_init();
    crypto_sha256_update(intermediateHash, 16);
    memset(intermediateHash, 0, sizeof(intermediateHash));
    crypto_sha256_update(STATE.PIN_SALT, sizeof(STATE.PIN_SALT));
    crypto_sha256_final(STATE.PIN_CODE_HASH);

    STATE.is_pin_set = 1;

    authenticator_write_state(&STATE);

    printf1(TAG_CTAP, "New pin set: %s [%d]\n", pin, len);
    dump_hex1(TAG_ERR, STATE.PIN_CODE_HASH, sizeof(STATE.PIN_CODE_HASH));
}

uint8_t ctap_decrement_pin_attempts(void)
{
    if (PIN_BOOT_ATTEMPTS_LEFT > 0)
    {
        PIN_BOOT_ATTEMPTS_LEFT--;
    }
    if (! ctap_device_locked())
    {
        STATE.remaining_tries--;
        ctap_flush_state();
        printf1(TAG_CP, "ATTEMPTS left: %d\n", STATE.remaining_tries);

        if (ctap_device_locked())
        {
            lock_device_permanently();
        }
    }
    else
    {
        printf1(TAG_CP, "Device locked!\n");
        return -1;
    }
    return 0;
}

int8_t ctap_device_locked(void)
{
    return STATE.remaining_tries <= 0;
}

int8_t ctap_device_boot_locked(void)
{
    return PIN_BOOT_ATTEMPTS_LEFT <= 0;
}

int8_t ctap_leftover_pin_attempts(void)
{
    return STATE.remaining_tries;
}

void ctap_reset_pin_attempts(void)
{
    STATE.remaining_tries = PIN_LOCKOUT_ATTEMPTS;
    PIN_BOOT_ATTEMPTS_LEFT = PIN_BOOT_ATTEMPTS;
    ctap_flush_state();
}

void ctap_reset_state(void)
{
    //memset(&getAssertionState, 0, sizeof(getAssertionState));
}

static uint16_t ctap_keys_stored(void)
{
    int total = 0;
    int i;
    for (i = 0; i < MAX_KEYS; i++)
    {
        if (STATE.key_lens[i] != 0xffff)
        {
            total += 1;
        }
        else
        {
            break;
        }
    }
    return total;
}

static uint16_t key_addr_offset(int index)
{
    uint16_t offset = 0;
    int i;
    for (i = 0; i < index; i++)
    {
        if (STATE.key_lens[i] != 0xffff) offset += STATE.key_lens[i];
    }
    return offset;
}

uint16_t ctap_key_len(uint8_t index)
{
    int i = ctap_keys_stored();
    if (index >= i || index >= MAX_KEYS)
    {
        return 0;
    }
    if (STATE.key_lens[index] == 0xffff) return 0;
    return STATE.key_lens[index];

}

int8_t ctap_store_key(uint8_t index, uint8_t * key, uint16_t len)
{
    int i = ctap_keys_stored();
    uint16_t offset;
    if (i >= MAX_KEYS || index >= MAX_KEYS || !len)
    {
        return ERR_NO_KEY_SPACE;
    }

    if (STATE.key_lens[index] != 0xffff)
    {
        return ERR_KEY_SPACE_TAKEN;
    }

    offset = key_addr_offset(index);

    if ((offset + len) > KEY_SPACE_BYTES)
    {
        return ERR_NO_KEY_SPACE;
    }

    STATE.key_lens[index] = len;

    memmove(STATE.key_space + offset, key, len);

    ctap_flush_state();

    return 0;
}

int8_t ctap_load_key(uint8_t index, uint8_t * key)
{
    int i = ctap_keys_stored();
    uint16_t offset;
    uint16_t len;
    if (index >= i || index >= MAX_KEYS) {
        return ERR_NO_KEY_SPACE;
    }

    if (STATE.key_lens[index] == 0xffff)
    {
        return ERR_KEY_SPACE_EMPTY;
    }

    offset = key_addr_offset(index);
    len = ctap_key_len(index);

    if ((offset + len) > KEY_SPACE_BYTES)
    {
        return ERR_NO_KEY_SPACE;
    }

    memmove(key, STATE.key_space + offset, len);

    return 0;
}

static void ctap_reset_key_agreement(void)
{
    ctap_generate_rng(KEY_AGREEMENT_PRIV, sizeof(KEY_AGREEMENT_PRIV));
}

#if 0
void ctap_reset(void)
{
    ctap_state_init();

    authenticator_write_state(&STATE);

    if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1)
    {
        printf2(TAG_ERR,"Error, rng failed\n");
        exit(1);
    }

    ctap_reset_state();
    ctap_reset_key_agreement();

    crypto_load_master_secret(STATE.key_space);
}
#endif
