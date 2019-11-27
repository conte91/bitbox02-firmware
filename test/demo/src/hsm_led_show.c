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

#include <stdlib.h>

#include "common_main.h"
#include "driver_init.h"
#include "leds.h"
#include "platform_init.h"
#include "qtouch.h"
#include "screen.h"
#include "ui/component.h"
#include "ui/components/show_logo.h"
#include "ui/oled/oled.h"
#include "ui/screen_process.h"
#include "ui/screen_stack.h"

#include "common_main.h"
#include "driver_init.h"
#include "firmware_main_loop.h"
#include "hardfault.h"
#include "hww.h"
#include "platform_init.h"
#include "qtouch.h"
#include "ui/oled/oled.h"
#include "ui/screen_process.h"
#include "usart/usart.h"
#include "usb/usb_processing.h"
#include "util.h"
#include "workflow/workflow.h"
uint32_t __stack_chk_guard = 0;

typedef struct {
    int hole_position;
    led_color_t led_color;
    led_color_t led_color_2;
    int delay;
} led_status_t;

static led_color_t _get_next_color(led_color_t last_color)
{
    return (last_color + 1) % 4;
}

static led_status_t _get_next_status(led_status_t last_status)
{
    led_status_t status = last_status;
    status.hole_position = (status.hole_position + 1) % 7;
    // If the hole was in one of the big LEDs, change that LED color.
    if (status.hole_position == 5) {
        status.led_color = _get_next_color(status.led_color);
    }
    if (status.hole_position == 6) {
        status.led_color_2 = _get_next_color(status.led_color_2);
    }
    if (last_status.hole_position == 0) {
        status.delay = rand() % 500;
    }
    return status;
}

static void _apply_led_status(led_status_t status)
{
    for (int i = 0; i < 5; ++i) {
        // Turn on all small leds but the "hole"
        leds_turn_small_led(i, i != status.hole_position);
    }
    for (int i = 0; i < 2; ++i) {
        leds_turn_big_led(i, LED_COLOR_NONE);
    }
    if (status.hole_position != 5) {
        leds_turn_big_led(0, status.led_color);
    }
    if (status.hole_position != 6) {
        leds_turn_big_led(1, status.led_color_2);
    }
}

int main(void)
{
    init_mcu();
    system_init();
    platform_init();
    __stack_chk_guard = common_stack_chk_guard();
    screen_init();
    screen_splash();
    component_t* show_logo = show_logo_create(workflow_start, 200);
    ui_screen_stack_switch(show_logo);
    for (int i = 0; i < 100; ++i) {
        screen_process();
    }
    led_status_t status = { 0, LED_COLOR_WHITE, LED_COLOR_WHITE, 200 };
    while (1) {
        _apply_led_status(status);
        status = _get_next_status(status);
        delay_ms(status.delay);
    }
    return 0;
}
