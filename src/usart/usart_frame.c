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

#include "usart_frame.h"

#include "hardfault.h"
#include "leds.h"
#include "screen.h"
#include "usb/usb_processing.h"
#include "util.h"

#include "hal_delay.h"
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>

#define USART_FRAME_FLAG_BYTE ((uint8_t)0x7E)
#define USART_FRAME_ESCAPE_BYTE ((uint8_t)0x7D)
#define USART_FRAME_ESCAPE_MASK ((uint8_t)0x20)

typedef enum {
    USART_FRAME_ERROR_ENDPOINT_UNAVAILABLE = 0x01,
    USART_FRAME_ERROR_ENDPOINT_BUSY = 0x02,
    USART_FRAME_ERROR_INVALID_CMD = 0x03
} usart_frame_error_t;

/** State of the USART frame unpacker state machine. */
typedef enum {
    /**
     * Waiting to synchronize to a packet start (0x7E).
     *
     * This state will be the starting state (to resync on the byte stream).
     * We also enter this state every time we think we've lost
     * track of where the packet start is (e.g. buffer overflow,
     * asked to reset).
     */
    USART_FRAME_PARSE_IDLE,
    /** Reading data. */
    USART_FRAME_PARSE_RX,
    /** Last byte was 0x7D: escape the next one. */
    USART_FRAME_PARSE_ESCAPING
} usart_parse_state_t;

/**
 * Keeps a state for the frame processing of incoming frames.
 */
static struct {
    usart_parse_state_t state;
    size_t packet_size;
    uint8_t buf[USART_FRAME_MAX_DATA_LEN];
} _usart_frame_parser_state;

/**
 * Resets the current state.
 */
static void _usart_frame_reset_state(void)
{
    _usart_frame_parser_state.state = USART_FRAME_PARSE_IDLE;
    util_zero(_usart_frame_parser_state.buf, _usart_frame_parser_state.packet_size);
    _usart_frame_parser_state.packet_size = 0;
}

void usart_frame_init(void)
{
    _usart_frame_parser_state.state = USART_FRAME_PARSE_IDLE;
    _usart_frame_parser_state.packet_size = 0;
    util_zero(_usart_frame_parser_state.buf, sizeof(_usart_frame_parser_state.buf));
}

static inline uint16_t _ones_complement_sum(uint16_t a, uint16_t b)
{
    uint32_t result = a + b;
    if (result & 0x10000) {
        result -= 0xFFFF;
    }
    return result;
}

static uint16_t _compute_checksum(const uint8_t* data, size_t payload_length)
{
    uint16_t cs = 0;
    size_t n_sums = (payload_length) / 2;
    bool round = (payload_length % 2) != 0;
    for (size_t i = 0; i < n_sums; ++i) {
        uint16_t element = ((const uint16_t*)data)[i];
        cs = _ones_complement_sum(cs, element);
    }
    // If we had an odd number of bytes, we
    // want to add the last byte on its own
    // (little endian, so this is equivalent
    // to padding with an additional 0x00 byte.
    if (round) {
        cs = _ones_complement_sum(cs, (uint16_t)(data[payload_length - 1]));
    }
    return cs;
}

/**
 * Computes the checksum of an outgoing packet.
 *
 * This is the same as _compute_checksum run over
 * the whole packet. However, information regarding the
 * metadata of the packet to be sent is not provided to us
 * in a contiguous buffer, so we use a separate function
 * to compute the checksum to send without having to repack
 * the frame first.
 *
 * @param[in] cmd U2F Command field
 * @param[in] src_endpoint Source endpoint field
 * @param[in] data payload
 * @param[in] len len of the payload.
 */
static uint16_t _compute_send_checksum(
    const uint8_t version,
    const uint8_t cmd,
    const uint8_t src_endpoint,
    const uint8_t* data,
    const uint32_t len)
{
    // The packet will contain version information in the first byte.
    uint16_t header_0 = version | (src_endpoint << 8);
    uint16_t header_1 = cmd;
    if (len == 0) {
        return _ones_complement_sum(header_0, header_1);
    }
    /*
     * The first byte of the payload goes together with the last
     * byte of the header.
     */
    header_1 |= (data[0] << 8);
    uint16_t cs = _ones_complement_sum(header_0, header_1);
    cs = _ones_complement_sum(cs, _compute_checksum(data + 1, len - 1));
    return cs;
}

static void _usart_send_frame_error(uint8_t error_code, uint32_t endpoint, struct queue* queue)
{
    uint8_t error_payload = endpoint;
    usart_format_frame(error_code, &error_payload, 1, 0xFF, queue);
}

void usart_invalid_api_command(struct queue* queue, uint32_t src_endpoint)
{
    _usart_send_frame_error(USART_FRAME_ERROR_INVALID_CMD, src_endpoint, queue);
}

static void _usart_manage_full_rx_frame(void)
{
    // Check if this packet is correct
    if (_usart_frame_parser_state.packet_size < 5) {
        // Packet too short.
        return;
    }
    // At the moment we only support version 1.
    uint8_t version = _usart_frame_parser_state.buf[0];
    if (version != 1) {
        /*
         * FUTURE: implement frame errors. For now
         * we just drop bad frames.
         */
        return;
    }
    // Check the checksum, located in the last 2 bytes of the frame.
    size_t payload_length = _usart_frame_parser_state.packet_size - 2;
    printf("Payload len: %u\n", payload_length);
    uint16_t checksum = *((uint16_t*)(_usart_frame_parser_state.buf + payload_length));
    uint16_t exp_checksum = _compute_checksum(_usart_frame_parser_state.buf, payload_length);
    printf("Checksum: 0x%" PRIx16 " exp: 0x%" PRIx16 "\n", checksum, exp_checksum);
    if (exp_checksum != checksum) {
        /*
         * FUTURE: implement frame errors. For now
         * we just drop bad frames.
         */
        return;
    }
    uint8_t dst_endpoint = _usart_frame_parser_state.buf[1];
    uint8_t u2f_command = _usart_frame_parser_state.buf[2];
    if (dst_endpoint != 1) {
    }
    if (!usb_processing_enqueue(
            usb_processing_hww(),
            _usart_frame_parser_state.buf + 3,
            payload_length - 3,
            u2f_command,
            0x42)) {
    }
}

static void _usart_frame_packet_end(void)
{
    if (_usart_frame_parser_state.packet_size > 0) {
        _usart_manage_full_rx_frame();
    }
    _usart_frame_reset_state();
}

static void _usart_frame_append_data_byte(uint8_t b)
{
    if (_usart_frame_parser_state.packet_size == USART_FRAME_MAX_DATA_LEN) {
        // Error. Start looking for a new packet and discard the current one.
        _usart_frame_reset_state();
        return;
    }
    _usart_frame_parser_state.buf[_usart_frame_parser_state.packet_size] = b;
    _usart_frame_parser_state.packet_size++;
}

static void _usart_frame_process_byte(uint8_t b)
{
    switch (_usart_frame_parser_state.state) {
    case USART_FRAME_PARSE_IDLE:
        if (b == USART_FRAME_FLAG_BYTE) {
            // Found it!
            _usart_frame_reset_state();
            _usart_frame_parser_state.state = USART_FRAME_PARSE_RX;
        }
        break;
    case USART_FRAME_PARSE_RX:
        if (b == USART_FRAME_FLAG_BYTE) {
            // End of packet.
            _usart_frame_packet_end();
        } else if (b == USART_FRAME_ESCAPE_BYTE) {
            // Escape sequence.
            _usart_frame_parser_state.state = USART_FRAME_PARSE_ESCAPING;
        } else {
            // Everything else -> Data byte.
            _usart_frame_append_data_byte(b);
        }
        break;
    case USART_FRAME_PARSE_ESCAPING:
        if (b == USART_FRAME_FLAG_BYTE) {
            // Escaped flag: this means "force reset, ignore this packet."
            _usart_frame_reset_state();
        } else {
            // Everything else -> Data byte.
            _usart_frame_append_data_byte(b ^ USART_FRAME_ESCAPE_MASK);
            _usart_frame_parser_state.state = USART_FRAME_PARSE_RX;
        }
        break;
    default:
        Abort("_usart_frame_process_byte\nInvalid state!");
    }
}
static int total_n_rcv_bytes = 0;

void usart_frame_process_rx(uint8_t* buf, size_t size)
{
    for (size_t i = 0; i < size; ++i) {
        _usart_frame_process_byte(buf[i]);
        total_n_rcv_bytes++;
    }
}

static size_t n_pushed = 0;
#define USART_FRAME_PUSH_BYTE(x)                         \
    do {                                                 \
        uint8_t to_push = x;                             \
        queue_error_t res = queue_push(queue, &to_push); \
        if (res != QUEUE_ERR_NONE) {                     \
            return res;                                  \
        }                                                \
        n_pushed++;                                      \
    } while (0)

static queue_error_t _usart_encode_push_byte(uint8_t b, struct queue* queue)
{
    if (b == USART_FRAME_FLAG_BYTE || b == USART_FRAME_ESCAPE_BYTE) {
        // Escape special framing bytes.
        USART_FRAME_PUSH_BYTE(USART_FRAME_ESCAPE_BYTE);
        USART_FRAME_PUSH_BYTE(b ^ USART_FRAME_ESCAPE_MASK);
    } else {
        USART_FRAME_PUSH_BYTE(b);
    }
    return QUEUE_ERR_NONE;
}

#define USART_FRAME_PUSH_ENCODED_BYTE(x)                       \
    do {                                                       \
        queue_error_t res = _usart_encode_push_byte(x, queue); \
        if (res != QUEUE_ERR_NONE) {                           \
            return res;                                        \
        }                                                      \
    } while (0)

queue_error_t usart_format_frame(
    const uint8_t cmd,
    const uint8_t* data,
    const uint32_t len,
    const uint32_t cid,
    struct queue* queue)
{
    printf("Writing D%" PRIu32 " C%u CID%" PRIu32 " NP %u\n", len, cmd, cid, n_pushed);
    (void)cid;
    USART_FRAME_PUSH_BYTE(USART_FRAME_FLAG_BYTE);
    // Version == 0x01
    USART_FRAME_PUSH_ENCODED_BYTE(0x01);
    // Source endpoint == 0x01
    USART_FRAME_PUSH_ENCODED_BYTE(0x01);
    USART_FRAME_PUSH_ENCODED_BYTE(cmd);
    for (uint32_t i = 0; i < len; ++i) {
        USART_FRAME_PUSH_ENCODED_BYTE(data[i]);
    }
    uint16_t cs = _compute_send_checksum(0x01, cmd, 0x01, data, len);
    uint8_t* cs_buf = (uint8_t*)&cs;
    USART_FRAME_PUSH_ENCODED_BYTE(cs_buf[0]);
    USART_FRAME_PUSH_ENCODED_BYTE(cs_buf[1]);
    USART_FRAME_PUSH_BYTE(USART_FRAME_FLAG_BYTE);
    printf("New NP %u\n", n_pushed);
    return QUEUE_ERR_NONE;
}
