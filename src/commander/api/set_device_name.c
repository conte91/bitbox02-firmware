#include "set_device_name.h"

#include <stdlib.h>

#include <hardfault.h>
#include <memory/memory.h>
#include <ui/workflow_stack.h>
#include <workflow/confirm.h>

#include "../commander_timeout.h"
#include "api_state.h"

/**
 * Data needed for the "set device name" API.
 */
typedef struct {
    char* name;
    enum {
        COMMANDER_SET_DEV_NAME_STARTED,
        COMMANDER_SET_DEV_NAME_CONFIRMED,
        COMMANDER_SET_DEV_NAME_ABORTED
    } state;
} data_t;

static void _set_dev_name_cleanup(void)
{
    commander_api_state_t* api_state = get_commander_api_state();
    data_t* data = (data_t*)api_state->data;
    if (!data) {
        /* Behave like free(), don't do anything if free()ing a NULL pointer. */
        return;
    }
    free(data->name);
    free(data);
    api_state->data = NULL;
}

/**
 * @return True on success, false on allocation error.
 */
static bool _set_dev_name_init(const char* name)
{
    commander_api_state_t* state = get_commander_api_state();
    /*
     * Make sure there is no leftover data from previous operations.
     * This would mean that another operation is in progress,
     * so the scheduling of requests is broken.
     */
    if (state->data) {
        Abort("Non-null state data in _set_dev_name_init.");
    }
    state->data = malloc(sizeof(data_t));
    if (!state->data) {
        return false;
    }
    data_t* data = (data_t*)state->data;
    data->name = strdup(name);
    if (!data->name) {
        free(state->data);
        state->data = NULL;
        return false;
    }
    data->state = COMMANDER_SET_DEV_NAME_STARTED;
    return true;
}

static void _set_device_name_done(bool result, void* param)
{
    (void)param;

    data_t* data = (data_t*)get_commander_api_state()->data;
    if (!data) {
        Abort("NULL device_name API data.");
    }
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
    _set_dev_name_cleanup();
}

commander_error_t api_set_device_name(const SetDeviceNameRequest* request)
{
    commander_api_state_t* state = get_commander_api_state();
    if (state->request_outstanding) {
        /* Continue the current request. */
        data_t* data = (data_t*)state->data;
        if (!data) {
            Abort("NULL device_name API data.");
        }
        commander_error_t result = COMMANDER_STARTED;
        switch (data->state) {
        case COMMANDER_SET_DEV_NAME_CONFIRMED:
            if (!memory_set_device_name(data->name)) {
                result = COMMANDER_ERR_MEMORY;
            } else {
                result = COMMANDER_OK;
            }
            _set_dev_name_cleanup();
            break;
        case COMMANDER_SET_DEV_NAME_ABORTED:
            _set_dev_name_cleanup();
            result = COMMANDER_ERR_USER_ABORT;
            break;
        case COMMANDER_SET_DEV_NAME_STARTED:
            break;
        default:
            Abort("Invalid device_name API status.");
            break;
        }
        return result;
    }
    if (!_set_dev_name_init(request->name)) {
        return COMMANDER_ERR_GENERIC;
    }
    const confirm_params_t params = {
        .title = "Name",
        .body = ((data_t*)state->data)->name,
        .scrollable = true,
    };
    workflow_stack_start_workflow(workflow_confirm(
        &params, _set_device_name_done, NULL));
    return COMMANDER_STARTED;
}
