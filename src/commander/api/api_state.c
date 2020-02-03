#include "api_state.h"

commander_api_state_t* get_commander_api_state(void)
{
    static commander_api_state_t state = {0};
    return &state;
}
