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

#include <stdint.h>
#include <string.h>

#include <noise/protocol.h>

#include "noise.h"
#include "util.h"
#include <hardfault.h>
#include <memory/memory.h>
#include <platform_config.h>
#include <random.h>
#include <ui/screen_stack.h>
#include <workflow/pairing.h>

#define CURVE_ID NOISE_DH_CURVE25519

static NoiseHandshakeState* _handshake = NULL;
static NoiseProtocolId _protocol_id;
static NoiseCipherState* _send_cipher = NULL;
static NoiseCipherState* _recv_cipher = NULL;
static uint8_t _handshake_hash[32];
static uint8_t _remote_static_pubkey[NOISE_PUBKEY_SIZE];
static bool _require_pairing_verification = false;

#define OP_I_CAN_HAS_HANDSHAKE ((uint8_t)'h')
#define OP_I_CAN_HAS_PAIRIN_VERIFICASHUN ((uint8_t)'v')
#define OP_HER_COMEZ_TEH_HANDSHAEK ((uint8_t)'H')
#define OP_NOISE_MSG ((uint8_t)'n')

#define OP_STATUS_SUCCESS ((uint8_t)0)
#define OP_STATUS_FAILURE ((uint8_t)1)
#define OP_STATUS_FAILURE_REQUIRE_PAIRING_VERIFICATION ((uint8_t)3)

/**
 * pubkey_out must be NOISE_PUBKEY_SIZE bytes
 */
static bool _get_remote_static_public_key(const NoiseHandshakeState* handshake, uint8_t* pubkey_out)
{
    const NoiseDHState* remote_dh_state = noise_handshakestate_get_remote_public_key_dh(handshake);
    if (remote_dh_state == NULL) {
        // assert - cannot happen
        return false;
    }
    if (noise_dhstate_get_public_key_length(remote_dh_state) != NOISE_PUBKEY_SIZE) {
        // assert - cannot happen
        return false;
    }
    if (noise_dhstate_get_public_key(remote_dh_state, pubkey_out, NOISE_PUBKEY_SIZE) !=
        NOISE_ERROR_NONE) {
        return false;
    }
    return true;
}

// sets up the local noise params, and star the handshake. If there was a
// previous handshake, it will be discarded.
static bool _setup_and_init_handshake(void)
{
    if (_handshake != NULL) {
        noise_handshakestate_free(_handshake);
        _handshake = NULL;
    }
    if (_send_cipher != NULL) {
        noise_cipherstate_free(_send_cipher);
        _send_cipher = NULL;
    }
    if (_recv_cipher != NULL) {
        noise_cipherstate_free(_recv_cipher);
        _recv_cipher = NULL;
    }

    _protocol_id.prefix_id = NOISE_PREFIX_STANDARD;
    _protocol_id.pattern_id = NOISE_PATTERN_XX;
    _protocol_id.cipher_id = NOISE_CIPHER_CHACHAPOLY;
    _protocol_id.dh_id = CURVE_ID;
    _protocol_id.hash_id = NOISE_HASH_SHA256;
    if (noise_init() != NOISE_ERROR_NONE) {
        return false;
    }
    const char protocol_name[] = "Noise_XX_25519_ChaChaPoly_SHA256";
    if (noise_handshakestate_new_by_name(&_handshake, protocol_name, NOISE_ROLE_RESPONDER) !=
        NOISE_ERROR_NONE) {
        return false;
    }
    // protocol name used as prologue.
    if (noise_handshakestate_set_prologue(_handshake, &protocol_name, sizeof(protocol_name) - 1) !=
        NOISE_ERROR_NONE) {
        return false;
    }
    if (!noise_handshakestate_needs_local_keypair(_handshake)) {
        // assert - cannot happen
        return false;
    }
    NoiseDHState* dh = noise_handshakestate_get_local_keypair_dh(_handshake);
    if (noise_dhstate_get_dh_id(dh) != CURVE_ID) {
        // assert - cannot happen
        return false;
    }
    uint8_t static_private_key[32];
    UTIL_CLEANUP_32(static_private_key);
    if (!memory_get_noise_static_private_key(static_private_key)) {
        return false;
    }
    if (noise_dhstate_set_keypair_private(dh, static_private_key, 32) != NOISE_ERROR_NONE) {
        return false;
    }
    if (noise_handshakestate_start(_handshake) != NOISE_ERROR_NONE) {
        return false;
    }
    // After this, the handshake continues in bb_noise_process_msg calls.
    return true;
}

/**
 * @param in_data[in] Handshake process request.
 * @param in_len[in] Length of the data pointed to by in_data.
 * @param out_buf[out] Buffer to fill with the handshake response.
 */
static bool _process_handshake(const in_buffer_t* in_buf, buffer_t* out_buf)
{
    if (!_handshake) {
        /* Handshake has not been started yet. */
        return false;
    }
    NoiseBuffer noise_buffer;
    if (noise_handshakestate_get_action(_handshake) != NOISE_ACTION_READ_MESSAGE) {
        // assert - cannot happen
        return false;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    noise_buffer_set_input(noise_buffer, (uint8_t*)in_buf->data, in_buf->len);
#pragma GCC diagnostic pop
    if (noise_handshakestate_read_message(_handshake, &noise_buffer, NULL) != NOISE_ERROR_NONE) {
        return false;
    }
    switch (noise_handshakestate_get_action(_handshake)) {
    case NOISE_ACTION_WRITE_MESSAGE: // after first read
        noise_buffer_set_output(noise_buffer, out_buf->data, out_buf->max_len);
        if (noise_handshakestate_write_message(_handshake, &noise_buffer, NULL) !=
            NOISE_ERROR_NONE) {
            return false;
        }
        out_buf->len = noise_buffer.size;
        return true;
    case NOISE_ACTION_SPLIT: { // after second read
        if (noise_handshakestate_split(_handshake, &_send_cipher, &_recv_cipher) !=
            NOISE_ERROR_NONE) {
            return false;
        }

        if (noise_handshakestate_get_handshake_hash(_handshake, _handshake_hash, 32) !=
            NOISE_ERROR_NONE) {
            return false;
        }

        if (!_get_remote_static_public_key(_handshake, _remote_static_pubkey)) {
            return false;
        }

        // Response: whether or not we require pairing verification as the next step.
        // If we already know the remote static pubkey, we do not require verification again.
        _require_pairing_verification =
            !memory_check_noise_remote_static_pubkey(_remote_static_pubkey);

        noise_handshakestate_free(_handshake);
        _handshake = NULL;

        // The previous screen was "See the BitBoxApp", waiting for the pairing.
        // We are paired now, so we pop that screen.
        // Pairing is the start of a session, so we clean the screen stack in case
        // we started a new session in the middle of something.
        // In bitboxbase the "background" screen should never be popped.
#if PLATFORM_BITBOX02 == 1
        ui_screen_stack_pop_all();
#endif

        out_buf->len = 1;
        *out_buf->data = _require_pairing_verification;
        return true;
    }
    default:
        return false;
    }
}

static void _free_dh_state(NoiseDHState** dh)
{
    if (dh && *dh) {
        noise_dhstate_free(*dh);
    }
}

// noise_rand_bytes is a symbol declared and used by libnoiseprotocol, but
// implemented here.
void noise_rand_bytes(void* bytes, size_t size);
void noise_rand_bytes(void* bytes, size_t size)
{
    // Our use of noise only needs 32 bytes.
    if (size != RANDOM_NUM_SIZE) {
        Abort("Abort: noise_rand_bytes");
    }
    // Use random_32_bytes_mcu over random_32_bytes as the latter mixes in
    // randomness from the securechip, which is initialized only later (noise
    // static key is set on memory_setup(), which is before securechip_setup()).
    random_32_bytes_mcu(bytes);
}

/**
 * Checks that a request's length is valid for the message type.
 *
 * @param[in] in_req Request to process.
 * @return Whether the request's length is valid.
 */
static bool _check_message_length(const in_buffer_t* in_req)
{
    if (in_req->len == 0) {
        return false;
    }
    switch (in_req->data[0]) {
    case OP_I_CAN_HAS_HANDSHAKE:
    case OP_I_CAN_HAS_PAIRIN_VERIFICASHUN:
        return in_req->len == 1;
    case OP_HER_COMEZ_TEH_HANDSHAEK:
        return in_req->len > 1;
    default:
        return in_req->len > 0;
    }
}

// processes client messages. The first two messages are handshake messages
// (see XX in https://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental).
// After, all incoming messages are decrypted and outgoing messages encrypted.
bool bb_noise_process_msg(
    const in_buffer_t* in_buf,
    // TODO: max_len must be 0xFFFF=65535, max noise packet size, but currently is
    // USB_DATA_MAX_LEN
    buffer_t* out_buf,
    bb_noise_process_msg_callback process_msg)
{
    if (!_check_message_length(in_buf)) {
        out_buf->len = 1;
        out_buf->data[0] = OP_STATUS_FAILURE;
        return false;
    }
    const uint8_t cmd = in_buf->data[0];
    // If this is a handshake init message, start the handshake.
    if (cmd == OP_I_CAN_HAS_HANDSHAKE) {
        bool init_handshake_result = _setup_and_init_handshake();
        out_buf->len = 1;
        out_buf->data[0] = init_handshake_result ? OP_STATUS_SUCCESS : OP_STATUS_FAILURE;
        return init_handshake_result;
    }
    // If the handshake has been started, process the handshake messages.
    if (cmd == OP_HER_COMEZ_TEH_HANDSHAEK) {
        // Expected to be called twice (two client handshake messages), after
        // which handshake is freed.
        in_buffer_t handshake_in = {.data = in_buf->data + 1, .len = in_buf->len - 1};
        buffer_t handshake_out = {
            .data = out_buf->data + 1, .len = 0, .max_len = out_buf->max_len - 1};
        bool handshake_success = _process_handshake(&handshake_in, &handshake_out);
        if (handshake_success) {
            out_buf->data[0] = OP_STATUS_SUCCESS;
            out_buf->len = handshake_out.len + 1;
        } else {
            out_buf->data[0] = OP_STATUS_FAILURE;
            out_buf->len = 1;
        }
        return handshake_success;
    }

    if (!_recv_cipher) {
        // Not paired yet, abort
        out_buf->len = 1;
        out_buf->data[0] = OP_STATUS_FAILURE;
        return true;
    }

    { // After the handshake we can perform the out of band pairing verification, if required by the
      // device or requested by the host app.
        if (cmd == OP_I_CAN_HAS_PAIRIN_VERIFICASHUN) {
#if PLATFORM_BITBOX02 == 1
            bool result = workflow_pairing_create(_handshake_hash);
#elif PLATFORM_BITBOXBASE == 1
            bool result = true;
#endif
            if (result) {
                out_buf->len = 1;
                out_buf->data[0] = OP_STATUS_SUCCESS;
                _require_pairing_verification = false;

                if (!memory_add_noise_remote_static_pubkey(_remote_static_pubkey)) {
                    // If this fails, we continue anyway, as the communication still works (just the
                    // pubkey is not stored and we need to perform the pairing verification again
                    // next time).
                }

                return true;
            }
            noise_cipherstate_free(_recv_cipher);
            _recv_cipher = NULL;
            noise_cipherstate_free(_send_cipher);
            _send_cipher = NULL;
            out_buf->len = 1;
            out_buf->data[0] = OP_STATUS_FAILURE;
            return true;
        }
        if (_require_pairing_verification) {
            // Device requires pairing verification, abort.
            out_buf->len = 1;
            out_buf->data[0] = OP_STATUS_FAILURE_REQUIRE_PAIRING_VERIFICATION;
            return true;
        }
    }
    if (cmd == OP_NOISE_MSG) {
        // Otherwise decrypt, process, encrypt.
        NoiseBuffer noise_buffer;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
        uint8_t* in_data = (uint8_t*)in_buf->data;
#pragma GCC diagnostic pop
        noise_buffer_set_inout(noise_buffer, in_data + 1, in_buf->len - 1, out_buf->max_len);
        if (noise_cipherstate_decrypt(_recv_cipher, &noise_buffer) != NOISE_ERROR_NONE) {
            return false;
        }
        in_buffer_t noise_in = {.data = noise_buffer.data, .len = noise_buffer.size};
        buffer_t noise_out = {.data = out_buf->data + 1, .len = 0, .max_len = out_buf->max_len - 1};
        process_msg(&noise_in, &noise_out);
        noise_buffer_set_inout(noise_buffer, noise_out.data, noise_out.len, noise_out.max_len);
        bool noise_status =
            noise_cipherstate_encrypt(_send_cipher, &noise_buffer) == NOISE_ERROR_NONE;
        if (!noise_status) {
            out_buf->len = 1;
        } else {
            out_buf->len = noise_buffer.size + 1;
        }
        out_buf->data[0] = noise_status ? OP_STATUS_SUCCESS : OP_STATUS_FAILURE;
        return noise_status;
    }
    // Unrecognized request, respond with error.
    out_buf->len = 1;
    out_buf->data[0] = OP_STATUS_FAILURE;
    return true;
}

bool bb_noise_generate_static_private_key(uint8_t* private_key_out)
{
    NoiseDHState* dh __attribute__((__cleanup__(_free_dh_state)));
    if (noise_dhstate_new_by_id(&dh, CURVE_ID) != NOISE_ERROR_NONE) {
        return false;
    }
    if (noise_dhstate_generate_keypair(dh) != NOISE_ERROR_NONE) {
        return false;
    }
    // sanity check
    if (noise_dhstate_get_private_key_length(dh) != 32) {
        return false;
    }
    size_t pk_len = noise_dhstate_get_public_key_length(dh);
    uint8_t pk[pk_len];
    if (noise_dhstate_get_keypair(dh, private_key_out, 32, pk, pk_len) != NOISE_ERROR_NONE) {
        return false;
    }
    return true;
}
