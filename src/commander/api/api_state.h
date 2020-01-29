#ifndef _API_STATE_H
#define _API_STATE_H

#include "../commander.h"
#include "btc_pub.h"
#include "set_device_name.h"

#include <crypto/sha2/sha256.h>

typedef struct {
    /**
     * This pointer will be allocated by each blocking API
     * when it starts. It allows that API endpoint to store
     * status data between requests.
     */
    void* data;
    /**
     * Last API request that blocked.
     */
    pb_size_t last_request;
    /**
     * Whether we have an outstanding request.
     */
    bool request_outstanding;
    /**
     * Hash of the last request that got blocked
     * with a COMMANDER_STARTED response. This will
     * be checked against future incoming requests to
     * make sure that no other request can be processed until
     * the original one is finished or cancelled.
     */
    uint8_t outstanding_request_hash[32];
} commander_api_state_t;

/**
 * Gets a pointer to the global state.
 */
commander_api_state_t* get_commander_api_state(void);

#endif
