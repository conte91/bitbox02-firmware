// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _CTAP_H
#define _CTAP_H

#include <hardfault.h>
#include <u2f/u2f_keyhandle.h>

#ifdef assert
#undef assert
#endif

/*
 * TinyCBOR will use the default definition for assert.
 * The USB driver will include its own definition though...
 *
 * Replace it with our custom definition (i.e. Abort if condition
 * is false).
 */
#define assert(cond) \
    do { \
        if (!(cond)) { \
            Abort("Assertion failed:\n" #cond); \
        } \
    } while(0);

#include <cbor.h>

#undef assert

#include <usb/usb_packet.h>

#define CTAP_MAKE_CREDENTIAL        0x01
#define CTAP_GET_ASSERTION          0x02
#define CTAP_CANCEL                 0x03
#define CTAP_GET_INFO               0x04
#define CTAP_CLIENT_PIN             0x06
#define CTAP_RESET                  0x07
#define GET_NEXT_ASSERTION          0x08
#define CTAP_VENDOR_FIRST           0x40
#define CTAP_VENDOR_LAST            0xBF

/**
 * Authenticator Status, transmitted through keepalive messages.
 */
#define CTAPHID_STATUS_IDLE         0
#define CTAPHID_STATUS_PROCESSING   1
#define CTAPHID_STATUS_UPNEEDED     2

#define MC_clientDataHash         0x01
#define MC_rp                     0x02
#define MC_user                   0x03
#define MC_pubKeyCredParams       0x04
#define MC_excludeList            0x05
#define MC_extensions             0x06
#define MC_options                0x07
#define MC_pinAuth                0x08
#define MC_pinProtocol            0x09

#define GA_rpId                   0x01
#define GA_clientDataHash         0x02
#define GA_allowList              0x03
#define GA_extensions             0x04
#define GA_options                0x05
#define GA_pinAuth                0x06
#define GA_pinProtocol            0x07

#define CP_pinProtocol            0x01
#define CP_subCommand             0x02
    #define CP_cmdGetRetries      0x01
    #define CP_cmdGetKeyAgreement 0x02
    #define CP_cmdSetPin          0x03
    #define CP_cmdChangePin       0x04
    #define CP_cmdGetPinToken     0x05
#define CP_keyAgreement           0x03
#define CP_pinAuth                0x04
#define CP_newPinEnc              0x05
#define CP_pinHashEnc             0x06
#define CP_getKeyAgreement        0x07
#define CP_getRetries             0x08

#define EXT_HMAC_SECRET_COSE_KEY    0x01
#define EXT_HMAC_SECRET_SALT_ENC    0x02
#define EXT_HMAC_SECRET_SALT_AUTH   0x03

#define EXT_HMAC_SECRET_REQUESTED   0x01
#define EXT_HMAC_SECRET_PARSED      0x02

#define RESP_versions               0x1
#define RESP_extensions             0x2
#define RESP_aaguid                 0x3
#define RESP_options                0x4
#define RESP_maxMsgSize             0x5
#define RESP_pinProtocols           0x6

#define RESP_fmt                    0x01
#define RESP_authData               0x02
#define RESP_attStmt                0x03

/* TODO: simone: change case */
#define RESP_credential             0x01
#define RESP_signature              0x03
#define RESP_publicKeyCredentialUserEntity 0x04
#define RESP_numberOfCredentials    0x05

#define RESP_keyAgreement           0x01
#define RESP_pinToken               0x02
#define RESP_retries                0x03

#define PARAM_clientDataHash        (1 << 0)
#define PARAM_rp                    (1 << 1)
#define PARAM_user                  (1 << 2)
#define PARAM_pubKeyCredParams      (1 << 3)
#define PARAM_excludeList           (1 << 4)
#define PARAM_extensions            (1 << 5)
#define PARAM_options               (1 << 6)
#define PARAM_pinAuth               (1 << 7)
#define PARAM_pinProtocol           (1 << 8)
#define PARAM_rpId                  (1 << 9)
#define PARAM_allowList             (1 << 10)

#define MC_requiredMask             (0x0f)

#define CLIENT_DATA_HASH_SIZE       32  //sha256 hash
#define DOMAIN_NAME_MAX_SIZE        253
#define RP_NAME_LIMIT               32  // application limit, name parameter isn't needed.
#define CTAP_USER_ID_MAX_SIZE            64

/**
 * Maximum length of the CTAP username getting stored
 * in a resident credential.
 * Can be longer than 32B, but we only store this
 * data for displaying it when authenticating.
 * So if the actual length is longer we can just display
 * a truncated string.
 */
#define CTAP_STORAGE_USER_NAME_LIMIT (20)

/**
 * Maximum length of the CTAP username getting stored
 * in a resident credential.
 * Can be longer than 32B, but we only store this
 * data for displaying it when authenticating.
 * So if the actual length is longer we can just display
 * a truncated string.
 */
#define CTAP_STORAGE_RP_ID_MAX_SIZE (20)

/**
 * Maximum length of the CTAP username getting stored
 * in a resident credential. It could be truncated.
 */
#define CTAP_STORAGE_DISPLAY_NAME_LIMIT (20)

/** Maximum length of the CTAP username. */
#define CTAP_USER_NAME_LIMIT             (64)
#define DISPLAY_NAME_LIMIT          32  // Must be minimum of 64 bytes but can be more.
#define ICON_LIMIT                  128 // Must be minimum of 64 bytes but can be more.
#define CTAP_MAX_MESSAGE_SIZE       1200

#define CREDENTIAL_RK_FLASH_PAD     2   // size of RK should be 8-byte aligned to store in flash easily.
    #define CREDENTIAL_TAG_SIZE         16
    #define CREDENTIAL_NONCE_SIZE       (16 + CREDENTIAL_RK_FLASH_PAD)
    #define CREDENTIAL_COUNTER_SIZE     (4)
    #define CREDENTIAL_ENC_SIZE         176  // pad to multiple of 16 bytes

    #define PUB_KEY_CRED_PUB_KEY        0x01
    #define PUB_KEY_CRED_CTAP1          0x41
    #define PUB_KEY_CRED_CUSTOM         0x42
    #define PUB_KEY_CRED_UNKNOWN        0x3F

    #define CREDENTIAL_IS_SUPPORTED     1
    #define CREDENTIAL_NOT_SUPPORTED    0

    #define CTAP_CREDENTIAL_LIST_MAX_SIZE 20

    #define NEW_PIN_ENC_MAX_SIZE        256     // includes NULL terminator
    #define NEW_PIN_ENC_MIN_SIZE        64
    #define NEW_PIN_MAX_SIZE            64
    #define NEW_PIN_MIN_SIZE            4

    #define CTAP_RESPONSE_BUFFER_SIZE   4096

    #define PIN_LOCKOUT_ATTEMPTS        8       // Number of attempts total
    #define PIN_BOOT_ATTEMPTS           3       // number of attempts per boot

    #define CTAP2_UP_DELAY_MS           29000

    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wpacked"
    #pragma GCC diagnostic ignored "-Wattributes"

typedef struct {
    uint8_t id[CTAP_USER_ID_MAX_SIZE];
    uint8_t id_size;
    uint8_t name[CTAP_USER_NAME_LIMIT];
    uint8_t displayName[DISPLAY_NAME_LIMIT];
    uint8_t icon[ICON_LIMIT];
} ctap_user_entity_t;

#define CTAP_RESIDENT_KEY_VALID (0x01)

/**
 * Invalid keys have their "valid" field
 * set to 0xFF so that erased flash is invalid.
 */
#define CTAP_RESIDENT_KEY_INVALID (0xff)

typedef struct __attribute__((__packed__)) {
    uint8_t valid;

    /** Key handle (credential ID) */
    u2f_keyhandle_t key_handle;

    /**
     * Human-readable ID of the RP that created the credential.
     * This is a NULL-terminated string.
     */
    uint8_t rp_id[CTAP_STORAGE_RP_ID_MAX_SIZE];
    /**
     * sha256 hash of the original RP id.
     * This is necessary (together with the ID) so
     * that we can make check RP ids for matching values
     * even if the actual RP id is longer than 32 bytes.
     */
    uint8_t rp_id_hash[32];
    /**
     * User ID that the RP has assigned to our user.
     * We need to store this and send it back together
     * with our keyhandle when we're asked to authenticate.
     */
    uint8_t user_id[CTAP_USER_ID_MAX_SIZE];
    /**
     * Size of user_id.
     */
    uint8_t user_id_size;
    /**
     * Username belonging to this credential.
     * This is a NULL terminated string.
     * Side effect: if a credential is created
     * which matches the first CTAP_STORAGE_USER_NAME_LIMIT
     * characters of the user and display name of an existing
     * credential, the latter is going to be overwritten.
     * Can this be used for evil purposes? (it shouldn't).
     */
    uint8_t user_name[CTAP_STORAGE_USER_NAME_LIMIT];
    /**
     * Display name of the user. Same considerations apply
     * as for the user_name.
     */
    uint8_t display_name[CTAP_STORAGE_DISPLAY_NAME_LIMIT];
    /**
     * Creation "time" of the key.
     * This is the value that the U2F counter had when the
     * key got created. We must not store any real timestamp,
     * but we must be able to sort keys by creation time.
     */
    uint32_t creation_time;
} ctap_resident_key_t;

/**
 * Attested credential data, defined
 * in [WebAuthn] 6.4.1.
 */
typedef struct __attribute__((packed)) {
    /** The AAGUID of the authenticator. */
    uint8_t aaguid[16];
    /** Length of the credential ID (big-endian) */
    uint8_t cred_len[2];
    /**  Credential ID */
    u2f_keyhandle_t id;
} ctap_attest_data_t;

/**
 * Authenticator data structure, to use
 * for authentication operations. It is
 * missing the attestedCredentialData
 * field. Defined in The WebAuthn specs, 6.1.
 */
typedef struct __attribute__((packed)) {
    uint8_t rpIdHash[32];
    uint8_t flags;
    uint32_t signCount;
} ctap_auth_data_header_t;

/**
 * Authenticator data structure, including
 * the attestedCredentialData field.
 * Defined in The WebAuthn specs, 6.1.
 */
typedef struct __attribute__((packed)) {
    ctap_auth_data_header_t head;
    ctap_attest_data_t attest;
    /* COSE-encoded pubkey and extension data */
    uint8_t other[310 - sizeof(ctap_auth_data_header_t) - sizeof(ctap_attest_data_t)];
} ctap_auth_data_t;

#pragma GCC diagnostic pop

typedef struct
{
    uint8_t data[CTAP_RESPONSE_BUFFER_SIZE];
    uint16_t data_size;
    uint16_t length;
} CTAP_RESPONSE;

struct rpId
{
    uint8_t id[DOMAIN_NAME_MAX_SIZE + 1];     // extra for NULL termination
    /* TODO change to id_size */
    size_t size;
    uint8_t name[RP_NAME_LIMIT];
};

typedef struct
{
    struct{
        uint8_t x[32];
        uint8_t y[32];
    } pubkey;

    int kty;
    int crv;
} COSE_key;

typedef struct
{
    uint8_t saltLen;
    uint8_t saltEnc[64];
    uint8_t saltAuth[32];
    COSE_key keyAgreement;
    u2f_keyhandle_t* key_handle;
} CTAP_hmac_secret;

typedef struct
{
    uint8_t hmac_secret_present;
    CTAP_hmac_secret hmac_secret;
} CTAP_extensions;

typedef struct
{
    ctap_user_entity_t user;
    uint8_t publicKeyCredentialType;
    int32_t COSEAlgorithmIdentifier;
    uint8_t rk;
} CTAP_credInfo;

typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    struct rpId rp;

    CTAP_credInfo credInfo;

    CborValue excludeList;
    size_t excludeListSize;

    uint8_t uv;
    uint8_t up;

    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    // pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
    // This is exclusive with |pinAuthPresent|. It exists because an empty
    // pinAuth is a special signal to block for touch. See
    // https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorMakeCredential
    uint8_t pinAuthEmpty;
    int pinProtocol;
    CTAP_extensions extensions;

} CTAP_makeCredential;



typedef struct
{
    uint32_t paramsParsed;
    uint8_t clientDataHash[CLIENT_DATA_HASH_SIZE];
    uint8_t clientDataHashPresent;

    struct rpId rp;

    uint8_t rk;
    uint8_t uv;
    uint8_t up;

    /* TODO remove pinAuth, we don't use it anyway. */
    uint8_t pinAuth[16];
    uint8_t pinAuthPresent;
    /**
     * pinAuthEmpty is true iff an empty bytestring was provided as pinAuth.
     * This is exclusive with |pinAuthPresent|. It exists because an empty
     * pinAuth is a special signal to block for touch. See
     * https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#using-pinToken-in-authenticatorGetAssertion
     */
    uint8_t pinAuthEmpty;
    int pinProtocol;

    /**
     * List of allowed credential descriptors for authentication.
     * If this parameter is present, then the authenticator MUST
     * use one of these credentials to authenticate.
     */
    u2f_keyhandle_t creds[CTAP_CREDENTIAL_LIST_MAX_SIZE];
    /** Number of credential descriptors present in this request. */
    int credLen;

    uint8_t allowListPresent;

    CTAP_extensions extensions;

} CTAP_getAssertion;

void ctap_response_init(CTAP_RESPONSE * resp);

typedef struct {
    /** Whether the request has been completed (and a response should be sent immediately). */
    bool request_completed;
    /** Response status code. Only valid if request_completed is true. */
    uint8_t status;
} ctap_request_result_t;

ctap_request_result_t ctap_request(const uint8_t * pkt_raw, int length, uint8_t* out_data, size_t* out_len);

/**
 * Polls an outstanding operation for completion.
 *
 * @param out_data Buffer to fill with a response (if any is ready).
 * @param out_len[out] Length of the response contained in out_data.
 * @return Request status.
 */
ctap_request_result_t ctap_retry(uint8_t* out_data, size_t* out_len);

// Encodes R,S signature to 2 der sequence of two integers.  Sigder must be at least 72 bytes.
// @return length of der signature
int ctap_encode_der_sig(uint8_t const * const in_sigbuf, uint8_t * const out_sigder);

// Run ctap related power-up procedures (init pinToken, generate shared secret)
void ctap_init(void);

// Key storage API

// Return length of key at index.  0 if not exist.
uint16_t ctap_key_len(uint8_t index);

// See error codes in storage.h
int8_t ctap_store_key(uint8_t index, uint8_t * key, uint16_t len);
int8_t ctap_load_key(uint8_t index, uint8_t * key);

#define PIN_TOKEN_SIZE      16
extern uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
extern uint8_t KEY_AGREEMENT_PUB[64];

void lock_device_permanently(void);

void ctap_load_external_keys(uint8_t * keybytes);

#include <screen.h>

void make_auth_tag(uint8_t * rpIdHash, uint8_t * nonce, uint32_t count, uint8_t * tag);

/**
 * Auth data flags, defined in [WebAuthn] sec. 6.1. Authenticator Data.
 */
/**
 * User is present/not present.
 */
#define CTAP_AUTH_DATA_FLAG_USER_PRESENT (1 << 0)
/**
 * User is verified/not verified.
 */
#define CTAP_AUTH_DATA_FLAG_USER_VERIFIED (1 << 2)
/**
 * Indicates whether the authenticator added attested credential data.
 */
#define CTAP_AUTH_DATA_FLAG_ATTESTED_CRED_DATA_INCLUDED (1 << 6)
/**
 * Indicates if the authenticator data has extensions.
 */
#define CTAP_AUTH_DATA_FLAG_EXTENSION_DATA_INCLUDED (1 << 7)
#endif // _CTAP_H