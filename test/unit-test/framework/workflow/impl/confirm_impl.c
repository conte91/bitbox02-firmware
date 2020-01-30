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

#include <workflow/impl/confirm_impl.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <ui/workflow_stack.h>
#include <util.h>

/**
 * Checks if the user has confirmed the choice,
 * or if the timeout (optional) has expired.
 */
void workflow_confirm_impl_spin(workflow_t* self)
{
    workflow_confirm_data_t* data = (workflow_confirm_data_t*)self->data;
    bool finish = mock();
    if (finish) {
        data->result = mock();
        /* Publish our result. */
        data->callback(data->result, data->callback_param);
        /* Time to go, goodbye. */
        workflow_stack_stop_workflow();
    }
}

/**
 * Starts this workflow.
 */
void workflow_confirm_impl_init(workflow_t* self) {}

/**
 * Destroys this workflow.
 */
void workflow_confirm_impl_cleanup(workflow_t* self)
{
    util_zero(self->data, sizeof(workflow_confirm_data_t));
    free(self->data);
    util_zero(self, sizeof(*self));
    free(self);
}
