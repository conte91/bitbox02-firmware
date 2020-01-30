#ifndef _API_SET_DEVICE_NAME_H
#define _API_SET_DEVICE_NAME_H

#include "../commander.h"

/**
 * Called at every loop, when we are asking the user to confirm
 * the device name.
 */
void process_set_device_name(void);

void abort_set_device_name(void);

commander_error_t api_set_device_name(const SetDeviceNameRequest* request);

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
} device_name_data_t;

#endif // _API_SET_DEVICE_NAME_H
