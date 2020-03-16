// Copyright 2019 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "u2f.h"

#include <stdio.h>
#include <string.h>

#include <fido2/ctap.h>
#include <fido2/ctap_errors.h>
#include <hardfault.h>
#include <keystore.h>
#include <memory/memory.h>
#include <random.h>
#include <screen.h>
#include <securechip/securechip.h>
#include <ui/component.h>
#include <ui/components/confirm.h>
#include <ui/components/info_centered.h>
#include <ui/screen_process.h>
#include <ui/screen_stack.h>
#include <u2f/u2f_app.h>
#include <u2f/u2f_keyhandle.h>
#include <usb/u2f/u2f.h>
#include <usb/u2f/u2f_hid.h>
#include <usb/u2f/u2f_keys.h>
#include <usb/usb_packet.h>
#include <usb/usb_processing.h>
#include <wally_crypto.h>
#include <workflow/status.h>
#include <workflow/unlock.h>

#define APPID_BOGUS_CHROMIUM "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define APPID_BOGUS_FIREFOX "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"

typedef struct {
    uint8_t cla, ins, p1, p2;
    uint8_t lc1, lc2, lc3;
    uint8_t data[];
} USB_APDU;

#define APDU_LEN(A) (uint32_t)(((A).lc1 << 16) + ((A).lc2 << 8) + ((A).lc3))
#define U2F_KEYHANDLE_LEN (U2F_NONCE_LENGTH + SHA256_LEN)

#if (U2F_EC_COORD_SIZE != SHA256_LEN) || (U2F_EC_COORD_SIZE != U2F_NONCE_LENGTH)
#error "Incorrect macro values for u2f"
#endif

typedef struct {
    uint32_t cid;
    /**
     * Command that is currently executing
     * (blocking) on the U2F stack.
     */
    uint8_t last_cmd;
    /**
     * last_cmd points to a valid byte,
     * and incoming requests that match that
     * command should be allowed. This is true
     * for blocking U2F requests, but false for CTAP
     * requests (as CTAP requests are not sent multiple times).
     */
    bool allow_cmd_retries;
    /**
     * Keeps track of whether there is an outstanding
     * U2F operation going on in the background.
     * This is not strictly necessary, but it's useful
     * to have as a sanity checking mechanism.
     */
    bool locked;
} u2f_state_t;

static u2f_state_t _state = {0};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpacked"
#pragma GCC diagnostic ignored "-Wattributes"

typedef struct __attribute__((__packed__)) {
    uint8_t reserved;
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t challenge[U2F_NONCE_LENGTH];
    uint8_t keyHandle[U2F_KEYHANDLE_LEN];
    uint8_t pubKey[U2F_EC_POINT_SIZE];
} U2F_REGISTER_SIG_STR;

typedef struct __attribute__((__packed__)) {
    uint8_t appId[U2F_APPID_SIZE];
    uint8_t flags;
    uint8_t ctr[4];
    uint8_t challenge[U2F_NONCE_LENGTH];
} U2F_AUTHENTICATE_SIG_STR;

#pragma GCC diagnostic pop

static component_t* _create_refresh_webpage(void)
{
    return info_centered_create("Refresh webpage", NULL);
}

/**
 * Unlocks the USB stack.
 */
static void _unlock(void)
{
    usb_processing_unlock();
    _state.locked = false;
}

/**
 * Locks the USB stack to process the given
 * U2F request.
 *
 * @param apdu U2F packet that will own the lock on the USB stack. No other request
 *             will be processed by the USB stack until this request completes.
 */
static void _lock(const USB_APDU* apdu)
{
    usb_processing_lock(usb_processing_u2f());
    _state.locked = true;
    if (apdu) {
        _state.last_cmd = apdu->ins;
        _state.allow_cmd_retries = true;
    } else {
        _state.allow_cmd_retries = false;
    }
}

static component_t* _nudge_label = NULL;

static void _nudge_label_cb(component_t* component)
{
    if (ui_screen_stack_top() == component->parent) {
        _nudge_label = NULL;
        ui_screen_stack_pop();
    }
}

static void _create_nudge_label(void)
{
    if (!_nudge_label) {
        _nudge_label =
            info_centered_create("Initialize with BitBoxApp\nto use U2F", _nudge_label_cb);
    }
    if (ui_screen_stack_top() != _nudge_label) {
        ui_screen_stack_push(_nudge_label);
    }
}

// Returns false if the parent function should return U2F_SW_CONDITIONS_NOT_SATISFIED
static bool _unlock_or_show_refresh_screen(void)
{
    static component_t* refresh_webpage = NULL;
    if (keystore_is_locked()) {
        // Unfortunately unlocking takes more time than U2F is allowed to take. With the current
        // architecture of the firmware we cannot run it concurrently to other requests. Therefore
        // we will call it here, make the user unlock the device and then ask the user to refresh
        // the webpage. (refreshing is only needed for some browsers)
        if (!workflow_unlock_blocking()) {
            _unlock();
            return false;
        }
        refresh_webpage = _create_refresh_webpage();
        ui_screen_stack_push(refresh_webpage);
        return false;
    }
    // Pop the "refresh webpage" screen
    if (ui_screen_stack_top() && ui_screen_stack_top() == refresh_webpage) {
        refresh_webpage = NULL;
        ui_screen_stack_pop();
    }
    return true;
}

static uint32_t _next_cid(void)
{
    do {
        _state.cid = (random_byte_mcu() << 0) + (random_byte_mcu() << 8) +
                     (random_byte_mcu() << 16) + (random_byte_mcu() << 24);
    } while (_state.cid == 0 || _state.cid == U2FHID_CID_BROADCAST);
    return _state.cid;
}

static void _fill_message(const uint8_t* data, const uint32_t len, Packet* out_packet)
{
    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    memcpy(out_packet->data_addr, data, len);
    out_packet->cid = _state.cid;
    out_packet->cmd = U2FHID_MSG;
    out_packet->len = len;
}

static void _error_hid(uint32_t fcid, uint8_t err, Packet* out_packet)
{
    util_zero(out_packet->data_addr, sizeof(out_packet->data_addr));
    out_packet->data_addr[0] = err;
    out_packet->cid = fcid;
    out_packet->cmd = U2FHID_ERROR;
    out_packet->len = 1;
}

static void _error(const uint16_t err, Packet* out_packet)
{
    uint8_t data[2];
    data[0] = err >> 8 & 0xFF;
    data[1] = err & 0xFF;
    _fill_message(data, sizeof(data), out_packet);
}

static void _version(const USB_APDU* a, Packet* out_packet)
{
    if (APDU_LEN(*a) != 0) {
        _error(U2F_SW_WRONG_LENGTH, out_packet);
        return;
    }

    static const uint8_t version_response[] = {'U', '2', 'F', '_', 'V', '2', 0x90, 0x00};
    _fill_message(version_response, sizeof(version_response), out_packet);
}

static int _sig_to_der(const uint8_t* sig, uint8_t* der)
{
    int i;
    uint8_t *p = der, *len, *len1, *len2;
    *p = 0x30;
    p++; // sequence
    *p = 0x00;
    len = p;
    p++; // len(sequence)

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len1 = p;
    p++; // len(integer)

    // process R
    i = 0;
    while (sig[i] == 0 && i < 32) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len1 = *len1 + 1;
    }
    while (i < 32) { // copy bytes to output
        *p = sig[i];
        p++;
        *len1 = *len1 + 1;
        i++;
    }

    *p = 0x02;
    p++; // integer
    *p = 0x00;
    len2 = p;
    p++; // len(integer)

    // process S
    i = 32;
    while (sig[i] == 0 && i < 64) {
        i++; // skip leading zeroes
    }
    if (sig[i] >= 0x80) { // put zero in output if MSB set
        *p = 0x00;
        p++;
        *len2 = *len2 + 1;
    }
    while (i < 64) { // copy bytes to output
        *p = sig[i];
        p++;
        *len2 = *len2 + 1;
        i++;
    }

    *len = *len1 + *len2 + 4;
    return *len + 2;
}

/**
 * Initiates the U2F registration workflow.
 * @param[in] apdu The APDU packet.
 */
static void _register(const USB_APDU* apdu, Packet* out_packet)
{
    uint8_t privkey[U2F_EC_COORD_SIZE] = {0};
    uint8_t nonce[U2F_NONCE_LENGTH] = {0};
    uint8_t mac[HMAC_SHA256_LEN] = {0};
    uint8_t data[sizeof(U2F_REGISTER_RESP) + 2] = {0};
    uint8_t sig[64] = {0};
    U2F_REGISTER_SIG_STR sig_base;
    U2F_REGISTER_RESP* response = (U2F_REGISTER_RESP*)data;
    const U2F_REGISTER_REQ* reg_request = (const U2F_REGISTER_REQ*)apdu->data;

    if (APDU_LEN(*apdu) != sizeof(U2F_REGISTER_REQ)) {
        _unlock();
        _error(U2F_SW_WRONG_LENGTH, out_packet);
        return;
    }

    if (!memory_is_initialized()) {
        _create_nudge_label();
        _unlock();
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    // If it fails to unlock it will call _unlock()
    if (!_unlock_or_show_refresh_screen()) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    // If the authentication fails with the "Bad key handle" the browser will execute bogus
    // registrations to make the device blink.
    bool is_bogus = MEMEQ(reg_request->appId, APPID_BOGUS_CHROMIUM, U2F_APPID_SIZE) ||
                    MEMEQ(reg_request->appId, APPID_BOGUS_FIREFOX, U2F_APPID_SIZE);
    bool result = false;
    if (u2f_app_confirm(is_bogus ? U2F_APP_BOGUS : U2F_APP_REGISTER, reg_request->appId, &result) ==
        WORKFLOW_ASYNC_NOT_READY) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }
    /* No more pending operations for U2F register */
    _unlock();
    if (!result) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    // Generate keys until a valid one is found
    bool key_create_success = u2f_keyhandle_create_key(reg_request->appId, nonce, privkey, mac, (uint8_t*)&response->pubKey.x);
    if (!key_create_success) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    response->pubKey.format = U2F_UNCOMPRESSED_POINT;

    response->registerId = U2F_REGISTER_ID;
    response->keyHandleLen = U2F_KEYHANDLE_LEN;

    memcpy(response->keyHandleCertSig, mac, sizeof(mac));
    memcpy(response->keyHandleCertSig + sizeof(mac), nonce, sizeof(nonce));
    memcpy(response->keyHandleCertSig + response->keyHandleLen, U2F_ATT_CERT, U2F_ATT_CERT_SIZE);

    // Add signature using attestation key
    sig_base.reserved = 0;
    memcpy(sig_base.appId, reg_request->appId, U2F_APPID_SIZE);
    memcpy(sig_base.challenge, reg_request->challenge, U2F_NONCE_LENGTH);
    memcpy(sig_base.keyHandle, &response->keyHandleCertSig, U2F_KEYHANDLE_LEN);
    memcpy(sig_base.pubKey, &response->pubKey, U2F_EC_POINT_SIZE);

    uint8_t hash[SHA256_LEN] = {0};
    wally_sha256((uint8_t*)&sig_base, sizeof(sig_base), hash, SHA256_LEN);

    if (!securechip_ecc_unsafe_sign(U2F_ATT_PRIV_KEY, hash, sig)) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    uint8_t* resp_sig = response->keyHandleCertSig + response->keyHandleLen + U2F_ATT_CERT_SIZE;
    int der_len = _sig_to_der(sig, resp_sig);
    size_t kh_cert_sig_len = response->keyHandleLen + U2F_ATT_CERT_SIZE + der_len;

    // Append success bytes
    memcpy(response->keyHandleCertSig + kh_cert_sig_len, "\x90\x00", 2);

    size_t len =
        1 /* registerId */ + U2F_EC_POINT_SIZE + 1 /* keyhandleLen */ + kh_cert_sig_len + 2;
    _fill_message(data, len, out_packet);
}

static void _authenticate(const USB_APDU* apdu, Packet* out_packet)
{
    uint8_t privkey[U2F_EC_COORD_SIZE];
    uint8_t sig[64] = {0};
    U2F_AUTHENTICATE_SIG_STR sig_base;

    const U2F_AUTHENTICATE_REQ* auth_request = (const U2F_AUTHENTICATE_REQ*)apdu->data;

    if (APDU_LEN(*apdu) < U2F_KEYHANDLE_LEN) { // actual size could vary
        _error(U2F_SW_WRONG_LENGTH, out_packet);
        return;
    }

    if (!memory_is_initialized()) {
        _create_nudge_label();
        _unlock();
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    // If it fails to unlock it will call _unlock()
    if (!_unlock_or_show_refresh_screen()) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    /* Decode the key handle into a private key. */
    bool key_is_valid = u2f_keyhandle_verify(
        auth_request->appId, auth_request->keyHandle, auth_request->keyHandleLength, privkey);
    if (!key_is_valid) {
        _error(U2F_SW_WRONG_DATA, out_packet);
        return;
    }
    if (apdu->p1 == U2F_AUTH_CHECK_ONLY) {
        // success: "error:test-of-user-presense"
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }
    if (apdu->p1 != U2F_AUTH_ENFORCE) {
        _error(U2F_SW_INS_NOT_SUPPORTED, out_packet);
        return;
    }

    bool result = false;
    if (u2f_app_confirm(U2F_APP_AUTHENTICATE, auth_request->appId, &result) ==
        WORKFLOW_ASYNC_NOT_READY) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }
    /* No more blocking operations pending for authentication. */
    _unlock();
    if (!result) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    uint8_t buf[sizeof(U2F_AUTHENTICATE_RESP) + 2] = {0};
    U2F_AUTHENTICATE_RESP* response = (U2F_AUTHENTICATE_RESP*)&buf;

    uint32_t counter;
    if (!securechip_u2f_counter_inc(&counter)) {
        _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
        return;
    }

    response->flags = U2F_AUTH_FLAG_TUP;
    response->ctr[0] = (counter >> 24) & 0xff;
    response->ctr[1] = (counter >> 16) & 0xff;
    response->ctr[2] = (counter >> 8) & 0xff;
    response->ctr[3] = counter & 0xff;

    // Sign
    memset(&sig_base, 0, sizeof(sig_base));
    memcpy(sig_base.appId, auth_request->appId, U2F_APPID_SIZE);
    sig_base.flags = response->flags;
    memcpy(sig_base.ctr, response->ctr, 4);
    memcpy(sig_base.challenge, auth_request->challenge, U2F_NONCE_LENGTH);

    uint8_t hash[SHA256_LEN] = {0};
    wally_sha256((uint8_t*)&sig_base, sizeof(sig_base), hash, SHA256_LEN);

    if (!securechip_ecc_unsafe_sign(privkey, hash, sig)) {
        _error(U2F_SW_WRONG_DATA, out_packet);
        return;
    }

    int der_len = _sig_to_der(sig, response->sig);
    size_t auth_packet_len = sizeof(U2F_AUTHENTICATE_RESP) - U2F_MAX_EC_SIG_SIZE + der_len;

    // Append success bytes
    memcpy(buf + auth_packet_len, "\x90\x00", 2);

    _fill_message(buf, auth_packet_len + 2, out_packet);
}

static void _cmd_ping(const Packet* in_packet)
{
    Packet out_packet;
    prepare_usb_packet(in_packet->cmd, in_packet->cid, &out_packet);

    // 0 and broadcast are reserved
    if (in_packet->cid == U2FHID_CID_BROADCAST || in_packet->cid == 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_CID, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }

    util_zero(out_packet.data_addr, sizeof(out_packet.data_addr));
    size_t max = MIN(in_packet->len, USB_DATA_MAX_LEN);
    memcpy(out_packet.data_addr, in_packet->data_addr, max);
    out_packet.len = in_packet->len;
    out_packet.cmd = U2FHID_PING;
    out_packet.cid = in_packet->cid;
    usb_processing_send_packet(usb_processing_u2f(), &out_packet);
}

static void _cmd_wink(const Packet* in_packet)
{
    Packet out_packet;
    prepare_usb_packet(in_packet->cmd, in_packet->cid, &out_packet);

    // 0 and broadcast are reserved
    if (in_packet->cid == U2FHID_CID_BROADCAST || in_packet->cid == 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_CID, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }

    if (in_packet->len > 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_LEN, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }

    util_zero(out_packet.data_addr, sizeof(out_packet.data_addr));
    out_packet.len = 0;
    out_packet.cmd = U2FHID_WINK;
    out_packet.cid = in_packet->cid;
    usb_processing_send_packet(usb_processing_u2f(), &out_packet);
}

static void _cmd_cancel(const Packet* in_packet)
{
    (void)in_packet;
    //screen_print_debug("CANCEL", 500);
    /*
     * U2FHID_CANCEL messages should abort the current transaction,
     * but no response should be given.
     */
}

/**
 * Synchronize a channel and optionally requests a unique 32-bit channel identifier (CID)
 * that can be used by the requesting application during its lifetime.
 *
 * If the CID is the U2FHID_CID_BROADCAST then the application is requesting a CID from the device.
 * Otherwise the application has chosen the CID.
 */
static void _cmd_init(const Packet* in_packet)
{
    Packet out_packet;
    prepare_usb_packet(in_packet->cmd, in_packet->cid, &out_packet);

    if (U2FHID_INIT_RESP_SIZE >= USB_DATA_MAX_LEN) {
        _error_hid(in_packet->cid, U2FHID_ERR_OTHER, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }

    // Channel 0 is reserved
    if (in_packet->cid == 0) {
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_CID, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }

    const U2FHID_INIT_REQ* init_req = (const U2FHID_INIT_REQ*)&in_packet->data_addr;
    U2FHID_INIT_RESP response;

    out_packet.cid = in_packet->cid;
    out_packet.cmd = U2FHID_INIT;
    out_packet.len = U2FHID_INIT_RESP_SIZE;

    util_zero(&response, sizeof(response));
    memcpy(response.nonce, init_req->nonce, sizeof(init_req->nonce));
    response.cid = in_packet->cid == U2FHID_CID_BROADCAST ? _next_cid() : in_packet->cid;
    response.versionInterface = U2FHID_IF_VERSION;
    response.versionMajor = DIGITAL_BITBOX_VERSION_MAJOR;
    response.versionMinor = DIGITAL_BITBOX_VERSION_MINOR;
    response.versionBuild = DIGITAL_BITBOX_VERSION_PATCH;
    response.capFlags = U2FHID_CAPFLAG_WINK | U2FHID_CAPFLAG_CBOR;
    util_zero(out_packet.data_addr, sizeof(out_packet.data_addr));
    memcpy(out_packet.data_addr, &response, sizeof(response));
    usb_processing_send_packet(usb_processing_u2f(), &out_packet);
}

/**
 * Process a U2F message
 */
static void _cmd_msg(const Packet* in_packet)
{
    Packet out_packet;
    prepare_usb_packet(in_packet->cmd, in_packet->cid, &out_packet);

    // By default always use the recieved cid
    _state.cid = in_packet->cid;

    const USB_APDU* apdu = (const USB_APDU*)in_packet->data_addr;

    if ((APDU_LEN(*apdu) + sizeof(USB_APDU)) > in_packet->len) {
        return;
    }

    if (apdu->cla != 0) {
        _error(U2F_SW_CLA_NOT_SUPPORTED, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }

    switch (apdu->ins) {
    case U2F_REGISTER:
        if (!_state.locked) {
            _lock(apdu);
        }
        _register(apdu, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        break;
    case U2F_AUTHENTICATE:
        if (!_state.locked) {
            _lock(apdu);
        }
        _authenticate(apdu, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        break;
    case U2F_VERSION:
        _version(apdu, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        break;
    default:
        _error(U2F_SW_INS_NOT_SUPPORTED, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
    }
}

static void _cmd_cbor(const Packet* in_packet) {
    Packet out_packet;
    prepare_usb_packet(in_packet->cmd, in_packet->cid, &out_packet);

    if (in_packet->len == 0)
    {
        printf("Error,invalid 0 length field for cbor packet\n");
        _error_hid(in_packet->cid, U2FHID_ERR_INVALID_LEN, &out_packet);
        usb_processing_send_packet(usb_processing_u2f(), &out_packet);
        return;
    }
    in_buffer_t request_buf = {
        .data = in_packet->data_addr,
        .len = in_packet->len
    };
    buffer_t response_buf = {
        .data = out_packet.data_addr + 1,
        .len = 0,
        .max_len = USB_DATA_MAX_LEN
    };
    ctap_request_result_t result = ctap_request(&request_buf, &response_buf);
    if (!result.request_completed) {
        /* Don't send a response yet. */
        return;
    }
    if (result.status != CTAP1_ERR_SUCCESS) {
        _error_hid(in_packet->cid, result.status, &out_packet);
    } else {
        out_packet.data_addr[0] = result.status;
    }
    out_packet.len = response_buf.len + 1;
    usb_processing_send_packet(usb_processing_u2f(), &out_packet);
}

bool u2f_blocking_request_can_go_through(const Packet* in_packet)
{
    if (!_state.locked) {
        Abort("USB stack thinks we're busy, but we're not.");
    }

    /* U2F keepalives should always be let through */
    if (in_packet->cmd == U2FHID_KEEPALIVE || in_packet->cmd == U2FHID_CANCEL) {
        return true;
    }

    if (!_state.allow_cmd_retries) {
        /* We're blocking every command, including retries of the last command. */
        return false;
    }
    /*
     * Check if this request is the same one we're currently operating on.
     * For now, this checks the request type and channel ID only.
     * FUTURE: Maybe check that the key handle is maintained between requests?
     *         so that when we're asking for confirmation, we ask to confirm
     *         "a particular key handle" instead of "a particular tab".
     */
    const USB_APDU* apdu = (const USB_APDU*)in_packet->data_addr;
    return apdu->ins == _state.last_cmd && in_packet->cid == _state.cid;
}

void u2f_blocked_req_error(Packet* out_packet, const Packet* in_packet)
{
    (void)in_packet;
    _error(U2F_SW_CONDITIONS_NOT_SATISFIED, out_packet);
}

void u2f_process(void)
{
    /** Nothing to do here. */
}


/**
 * Set up the U2F commands.
 */
void u2f_device_setup(void)
{
    const CMD_Callback u2f_cmd_callbacks[] = {
        {U2FHID_PING, _cmd_ping},
        {U2FHID_WINK, _cmd_wink},
        {U2FHID_INIT, _cmd_init},
        {U2FHID_MSG, _cmd_msg},
        {U2FHID_CBOR, _cmd_cbor},
        {U2FHID_CANCEL, _cmd_cancel},
    };
    usb_processing_register_cmds(
        usb_processing_u2f(), u2f_cmd_callbacks, sizeof(u2f_cmd_callbacks) / sizeof(CMD_Callback));
}
