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

#ifndef _USART_FRAME_H_
#define _USART_FRAME_H_

#include "queue.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Maximum size that can be transmitted in a single UART frame.
#define USART_FRAME_MAX_DATA_LEN (5000U)

/**
 * One of the available receivers that can be
 * attached to the USART port. The host will
 * distinguish what it is connected to based
 * on whether each of these endpoints is available.
 */
typedef enum { USART_ENDPOINT_BOOTLOADER, USART_ENDPOINT_HWW } usart_endpoint_t;

/**
 * Processes new raw data read from the USART port.
 * @param[in] buf Data that has been read.
 * @param[in] size Number of bytes queued.
 */
void usart_frame_process_rx(uint8_t* buf, size_t size);

/**
 * Initializes the parser.
 */
void usart_frame_init(void);

void usart_invalid_api_command(struct queue* queue, uint32_t src_endpoint);

void usart_endpoint_enable(usart_endpoint_t endpoint);

void usart_endpoint_disable(usart_endpoint_t endpoint);

bool is_usart_endpoint_enabled(usart_endpoint_t endpoint);

#endif
