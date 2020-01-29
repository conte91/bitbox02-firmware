#include "set_device_name.h"

#include <stdlib.h>

#include <memory/memory.h>
#include <workflow/confirm.h>
#include <ui/workflow_stack.h>

#include "api_state.h"
#include "../commander_timeout.h"

static void _commander_cleanup_set_dev_name(void) {
    free(get_commander_api_state()->data.dev_name.name);
    get_commander_api_state()->status = COMMANDER_STATUS_IDLE;
}

#define SET_DEVICE_NAME_TIMEOUT (50)

static void _set_device_name_done(workflow_confirm_result_t result, void* param)
{
    (void)param;
    if (result == WORKFLOW_CONFIRM_ABORTED) {
        /* Kill everything. Don't expect another response in the future. */
        /* TODO ??? */
        _commander_cleanup_set_dev_name();
        return;
    }
    get_commander_api_state()->data.dev_name.state = COMMANDER_SET_DEV_NAME_CONFIRMED;
    get_commander_api_state()->data.dev_name.result = (result == WORKFLOW_CONFIRM_CONFIRMED);
    free(get_commander_api_state()->data.dev_name.name);
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
    device_name_data_t* data = &get_commander_api_state()->data.dev_name;
    if (data->state == COMMANDER_SET_DEV_NAME_CONFIRMED) {
        if (data->result) {
            if (!memory_set_device_name(data->name)) {
                data->reply = COMMANDER_ERR_MEMORY;
            } else {
                data->reply = COMMANDER_OK;
            }
        } else {
            data->reply = COMMANDER_ERR_USER_ABORT;
        }
        data->state = COMMANDER_SET_DEV_NAME_REPLY_READY;
    }
    if (commander_timeout_get_timer() > SET_DEVICE_NAME_TIMEOUT) {
        abort_set_device_name();
    }
}

commander_error_t api_set_device_name(const SetDeviceNameRequest* request)
{
    if (get_commander_api_state()->status == COMMANDER_STATUS_SET_NAME) {
        if (get_commander_api_state()->data.dev_name.state == COMMANDER_SET_DEV_NAME_REPLY_READY) {
            _commander_cleanup_set_dev_name();
            return get_commander_api_state()->data.dev_name.reply;
        }
        return COMMANDER_STARTED;
    } else if (get_commander_api_state()->status == COMMANDER_STATUS_IDLE) {
        get_commander_api_state()->status = COMMANDER_STATUS_SET_NAME;
        get_commander_api_state()->data.dev_name.name = strdup(request->name);
        if (!get_commander_api_state()->data.dev_name.name) {
            return COMMANDER_ERR_MEMORY;
        }
        get_commander_api_state()->data.dev_name.state = COMMANDER_SET_DEV_NAME_STARTED;
        const confirm_params_t params = {
            .title = "Name",
            .body = get_commander_api_state()->data.dev_name.name,
            .scrollable = true,
        };
        workflow_stack_start_workflow(
            workflow_confirm(&params, _set_device_name_done, NULL)
        );
        return COMMANDER_STARTED;
    } 
    /* We're doing something already... */
    return COMMANDER_ERR_INVALID_STATE;
}
