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

#include "confirm_impl.h"

#include <hardfault.h>
#include <ui/components/confirm.h>
#include <ui/screen_stack.h>
#include <ui/workflow_stack.h>
#include <util.h>

#include <stddef.h>
#include <stdlib.h>

#define NO_TIMEOUT ((uint32_t)-1)

static void _confirm(void* param)
{
    workflow_t* self = (workflow_t*)param;
    workflow_confirm_data_t* data = (workflow_confirm_data_t*)self->data;
    data->result = true;
    data->done = true;
}

static void _reject(void* param)
{
    workflow_t* self = (workflow_t*)param;
    workflow_confirm_data_t* data = (workflow_confirm_data_t*)self->data;
    data->result = false;
    data->done = true;
}

void workflow_confirm_impl_spin(workflow_t* self)
{
    workflow_confirm_data_t* data = (workflow_confirm_data_t*)self->data;
    if (data->done) {
        /* Publish our result. */
        data->callback(data->result, data->callback_param);
        /* Time to go, goodbye. */
        workflow_stack_stop_workflow();
    } else if (data->timeout != NO_TIMEOUT) {
        if (data->timeout_counter == data->timeout) {
            /* Timeout has expired. Report a failure. */
            data->callback(false, data->callback_param);
            workflow_stack_stop_workflow();
        } else {
            data->timeout_counter++;
        }
    }
}

void workflow_confirm_impl_init(workflow_t* self)
{
    workflow_confirm_data_t* data = (workflow_confirm_data_t*)self->data;
    component_t* comp;
    if (data->scrollable) {
        comp = confirm_create_scrollable(
            data->title,
            data->body,
            data->font,
            false,
            _confirm,
            self,
            data->accept_only ? NULL : _reject,
            self);
    } else {
        comp = confirm_create(
            data->title,
            data->body,
            data->font,
            data->longtouch,
            _confirm,
            self,
            data->accept_only ? NULL : _reject,
            self);
    }
    ui_screen_stack_push(comp);
}

void workflow_confirm_impl_cleanup(workflow_t* self)
{
    ui_screen_stack_pop();
    ui_screen_stack_cleanup();
    util_zero(self->data, sizeof(workflow_confirm_data_t));
    free(self->data);
    util_zero(self, sizeof(*self));
    free(self);
}
