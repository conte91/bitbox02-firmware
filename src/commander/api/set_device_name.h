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

#endif // _API_SET_DEVICE_NAME_H
