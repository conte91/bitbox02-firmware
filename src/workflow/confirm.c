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

#include "confirm.h"

#include "async.h"
#include "blocking.h"
#include "hardfault.h"

#include <hardfault.h>
#include <ui/components/confirm.h>
#include <ui/screen_stack.h>
#include <ui/workflow_stack.h>
#include <util.h>

#include <stddef.h>
#include <stdlib.h>

#define NO_TIMEOUT ((uint32_t)-1)

typedef struct {
    bool result;
    bool done;
    uint32_t timeout_counter;
    uint32_t timeout;
    const char* title;
    const char* body;
    bool scrollable;
    bool longtouch;
    bool accept_only;
    void (*callback)(bool, void*);
    void* callback_param;
    const UG_FONT* font;
} data_t;

static void _confirm(void* param)
{
    workflow_t* self = (workflow_t*)param;
    data_t* data = (data_t*)self->data;
    data->result = true;
    data->done = true;
}

static void _reject(void* param)
{
    workflow_t* self = (workflow_t*)param;
    data_t* data = (data_t*)self->data;
    data->result = false;
    data->done = true;
}

/**
 * Checks if the user has confirmed the choice,
 * or if the timeout (optional) has expired.
 */
static void _workflow_confirm_spin(workflow_t* self)
{
    data_t* data = (data_t*)self->data;
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

/**
 * Starts this workflow.
 */
static void _workflow_confirm_init(workflow_t* self)
{
    data_t* data = (data_t*)self->data;
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

/**
 * Destroys this workflow.
 */
static void _workflow_confirm_cleanup(workflow_t* self)
{
    ui_screen_stack_pop();
    ui_screen_stack_cleanup();
    util_zero(self->data, sizeof(data_t));
    free(self->data);
    util_zero(self, sizeof(*self));
    free(self);
}

static workflow_t* _workflow_confirm_common(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool longtouch,
    bool scrollable,
    bool accept_only,
    uint32_t timeout,
    void (*callback)(bool, void*),
    void* callback_param)
{
    workflow_t* result = workflow_allocate(
        _workflow_confirm_init, _workflow_confirm_cleanup, _workflow_confirm_spin);
    data_t* data = malloc(sizeof(*data));
    if (!data) {
        Abort("workflow_confirm\ndata malloc");
    }
    data->done = false;
    data->longtouch = longtouch;
    data->accept_only = accept_only;
    data->scrollable = scrollable;
    data->timeout = timeout;
    data->title = title;
    data->body = body;
    data->callback = callback;
    data->callback_param = callback_param;
    data->font = font;
    result->data = data;
    return result;
}

workflow_t* workflow_confirm(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool longtouch,
    bool accept_only,
    void (*callback)(bool, void*),
    void* callback_param)
{
    return _workflow_confirm_common(
        title, body, font, longtouch, false, accept_only, NO_TIMEOUT, callback, callback_param);
}

workflow_t* workflow_confirm_scrollable(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool accept_only,
    void (*callback)(bool, void*),
    void* callback_param)
{
    return _workflow_confirm_common(
        title, body, font, false, true, accept_only, NO_TIMEOUT, callback, callback_param);
}

workflow_t* workflow_confirm_scrollable_longtouch(
    const char* title,
    const char* body,
    const UG_FONT* font,
    void (*callback)(bool, void*),
    void* callback_param)
{
    return _workflow_confirm_common(
        title, body, font, true, true, false, NO_TIMEOUT, callback, callback_param);
}

static bool _async_result = false;
static bool _have_async_result = false;

static void _confirm_complete_async(bool result, void* param)
{
    (void)param;
    _async_result = result;
    _have_async_result = true;
}

static enum _confirm_async_state {
    CONFIRM_IDLE,
    CONFIRM_WAIT,
} _confirm_async_state = CONFIRM_IDLE;

enum workflow_async_ready workflow_confirm_async(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool accept_only,
    bool* result)
{
    switch (_confirm_async_state) {
    case CONFIRM_IDLE:
        _async_result = false;
        workflow_stack_start_workflow(
            workflow_confirm(title, body, font, false, accept_only, _confirm_complete_async, NULL));
        _confirm_async_state = CONFIRM_WAIT;
        /* FALLTHRU */
    case CONFIRM_WAIT:
        if (!_have_async_result) {
            return WORKFLOW_ASYNC_NOT_READY;
        }
        _have_async_result = false;
        _confirm_async_state = CONFIRM_IDLE;
        *result = _async_result;
        return WORKFLOW_ASYNC_READY;
    default:
        Abort("workflow_confirm: Internal error");
    }
}

static void _confirm_blocking_cb(bool status, void* param)
{
    bool* result = param;
    *result = status;
    workflow_blocking_unblock();
}

bool workflow_confirm_blocking(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool longtouch,
    bool accept_only)
{
    bool _result;
    workflow_t* confirm_wf =
        workflow_confirm(title, body, font, longtouch, accept_only, _confirm_blocking_cb, &_result);
    workflow_stack_start_workflow(confirm_wf);
    bool blocking_result = workflow_blocking_block();
    if (!blocking_result) {
        return false;
    }
    return _result;
}

bool workflow_confirm_scrollable_blocking(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool accept_only)
{
    bool _result;
    workflow_t* confirm_wf =
        workflow_confirm_scrollable(title, body, font, accept_only, _confirm_blocking_cb, &_result);
    workflow_stack_start_workflow(confirm_wf);
    bool blocking_result = workflow_blocking_block();
    if (!blocking_result) {
        return false;
    }
    return _result;
}

bool workflow_confirm_scrollable_longtouch_blocking(
    const char* title,
    const char* body,
    const UG_FONT* font,
    bool* cancel_forced_out)
{
    bool _result = false;
    workflow_t* confirm_wf =
        workflow_confirm_scrollable_longtouch(title, body, font, _confirm_blocking_cb, &_result);
    workflow_stack_start_workflow(confirm_wf);
    bool blocking_result = workflow_blocking_block();
    *cancel_forced_out = !blocking_result;
    if (*cancel_forced_out) {
        return false;
    }
    return _result;
}
