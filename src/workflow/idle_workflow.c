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

#include "idle_workflow.h"

#include <stdlib.h>
#include <string.h>

#include <hardfault.h>
#include <hww.h>
#include <platform_config.h>
#include <ui/components/confirm.h>
#include <ui/components/info_centered.h>
#include <ui/components/show_logo.h>
#include <ui/screen_process.h>
#include <ui/screen_stack.h>
#if PLATFORM_BITBOXBASE == 1
#include <usart/usart.h>
#elif PLATFORM_BITBOX02 == 1
#include <usb/usb.h>
#endif
#include <util.h>

typedef struct {
    int delay_counter;
    bool initialized;
} orientation_screen_data_t;

#define IDLE_WORKFLOW_LOGO_DELAY (200 * SCREEN_FRAME_RATE)

static void _idle_workflow_init_communication(void)
{
#if PLATFORM_BITBOXBASE == 1
    usart_start();
    hww_setup();
#elif PLATFORM_BITBOX02 == 1
    usb_start(hww_setup);
#endif
    ui_screen_stack_pop();
    ui_screen_stack_cleanup();
    ui_screen_stack_push(info_centered_create("See the BitBoxApp", NULL));
}

static void _idle_workflow_spin(workflow_t* self)
{
    orientation_screen_data_t* data = self->data;
    if (!data->initialized) {
        data->delay_counter++;
        if (data->delay_counter == IDLE_WORKFLOW_LOGO_DELAY) {
            _idle_workflow_init_communication();
            data->initialized = true;
        }
    }
}

static void _idle_workflow_init(workflow_t* self)
{
    orientation_screen_data_t* data = malloc(sizeof(*data));
    if (!data) {
        Abort("malloc failed in _idle_workflow_init()");
    }
    data->delay_counter = 0;
    data->initialized = 0;
    self->data = data;
    ui_screen_stack_push(show_logo_create());
}

static void _idle_workflow_cleanup(workflow_t* self)
{
    ui_screen_stack_pop();
    free(self->data);
    free(self);
}

workflow_t* idle_workflow(void)
{
    return workflow_allocate(_idle_workflow_init, _idle_workflow_cleanup, _idle_workflow_spin);
}
