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

#ifndef __BITBOXBASE_LEDS_H
#define __BITBOXBASE_LEDS_H

#include <stdbool.h>
typedef enum { SMALL_LED, BIG_LED } led_t;

typedef enum { LED_WHITE, LED_RED, LED_GREEN, LED_BLUE, LED_NONE } led_color_t;

void leds_init(void);

void turn_small_led(int led, bool level);

void turn_big_led(int led, led_color_t color);

#endif // __BITBOXBASE_LEDS_H
