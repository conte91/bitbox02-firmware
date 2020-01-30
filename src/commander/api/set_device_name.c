#include "set_device_name.h"

#include <stdlib.h>

#include <memory/memory.h>
#include <ui/workflow_stack.h>
#include <workflow/confirm.h>

#include "../commander_timeout.h"
#include "api_state.h"

static void _commander_cleanup_set_dev_name(void)
{
    free(get_commander_api_state()->data.dev_name.name);
    get_commander_api_state()->status = COMMANDER_STATUS_IDLE;
}

#define SET_DEVICE_NAME_TIMEOUT (50)

static void _set_device_name_done(bool result, void* param)
{
    (void)param;

    device_name_data_t* data = &get_commander_api_state()->data.dev_name;
    if (result) {
        data->state = COMMANDER_SET_DEV_NAME_CONFIRMED;
    } else {
        data->state = COMMANDER_SET_DEV_NAME_ABORTED;
    }
}

void abort_set_device_name(void)
{
    /* Destroy this workflow. */
    workflow_stack_stop_workflow();
    _commander_cleanup_set_dev_name();
}

/**
 * Called at every loop, when we are asking the user to confirm
 * the device name.
 */
void process_set_device_name(void)
{
    if (commander_timeout_get_timer() > SET_DEVICE_NAME_TIMEOUT) {
        abort_set_device_name();
    }
}

commander_error_t api_set_device_name(const SetDeviceNameRequest* request)
{
    commander_api_state_t* state = get_commander_api_state();
    if (state->status == COMMANDER_STATUS_SET_NAME) {
        device_name_data_t* data = &state->data.dev_name;
        commander_error_t result = COMMANDER_STARTED;
        if (data->state == COMMANDER_SET_DEV_NAME_CONFIRMED) {
            if (!memory_set_device_name(data->name)) {
                result = COMMANDER_ERR_MEMORY;
            } else {
                result = COMMANDER_OK;
            }
            _commander_cleanup_set_dev_name();
        } else if (data->state == COMMANDER_SET_DEV_NAME_ABORTED) {
            _commander_cleanup_set_dev_name();
            result = COMMANDER_ERR_USER_ABORT;
        }
        return result;
    } else if (state->status == COMMANDER_STATUS_IDLE) {
        state->status = COMMANDER_STATUS_SET_NAME;
        state->data.dev_name.name = strdup(request->name);
        if (!state->data.dev_name.name) {
            return COMMANDER_ERR_MEMORY;
        }
        state->data.dev_name.state = COMMANDER_SET_DEV_NAME_STARTED;
        const confirm_params_t params = {
            .title = "Name",
            .body = state->data.dev_name.name,
            .scrollable = true,
        };
        workflow_stack_start_workflow(workflow_confirm(
            &params, _set_device_name_done, NULL));
        return COMMANDER_STARTED;
    }
    /* We're doing something already... */
    return COMMANDER_ERR_INVALID_STATE;
}
