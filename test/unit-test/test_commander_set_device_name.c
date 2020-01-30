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

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include <test_commander.h>
#include <ui/workflow_stack.h>
#include <workflow/workflow.h>

static void _run_set_device_name(
    bool memory_success,
    bool user_accepts,
    commander_error_t expected_result)
{
    static SetDeviceNameRequest request = {
        .name = "Mia",
    };
    /* Start the first request. */
    assert_int_equal(COMMANDER_STARTED, commander_api_set_device_name(&request));

    /* Now make something happen in the UI */
    if (user_accepts) {
        will_return(__wrap_memory_set_device_name, memory_success);
    }
    will_return(workflow_confirm_impl_spin, true);
    will_return(workflow_confirm_impl_spin, user_accepts);

    workflow_t* workflow = workflow_stack_top();
    assert_non_null(workflow);
    workflow->spin(workflow);

    /* Repeat the request. This time it should yield a result. */
    assert_int_equal(expected_result, commander_api_set_device_name(&request));
}

static void _test_api_set_device_name(void** state)
{
    // All A-Okay.
    _run_set_device_name(true, true, COMMANDER_OK);

    // User rejects.
    _run_set_device_name(true, false, COMMANDER_ERR_USER_ABORT);

    // Setting name fails.
    _run_set_device_name(false, true, COMMANDER_ERR_MEMORY);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(_test_api_set_device_name),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
