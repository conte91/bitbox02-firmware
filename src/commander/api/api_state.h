#ifndef _API_STATE_H
#define _API_STATE_H

#include "../commander.h"
#include "set_device_name.h"

typedef enum {
    /** No operation is in progress */
    COMMANDER_STATUS_IDLE,
    /** We're asking for confirmation for setting the device name. */
    COMMANDER_STATUS_SET_NAME
} commander_api_status_t;

typedef struct {
    union {
        device_name_data_t dev_name;
    } data;
    commander_api_status_t status;
} commander_api_state_t;

commander_api_state_t* get_commander_api_state(void);

uint16_t commander_api_ticks_since_last_packet(void);

#endif
