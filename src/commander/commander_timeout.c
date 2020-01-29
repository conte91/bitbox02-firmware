#include "commander_timeout.h"

#define COMMANDER_TIMER_MAX ((uint16_t)-1)

/**
 * Contains the timer ticks elapsed
 * since the last time a valid USB packet was received.
 */
static uint16_t _ticks_since_last_packet = 0;

void commander_timeout_tick(void)
{
    if (_ticks_since_last_packet != COMMANDER_TIMER_MAX) {
        _ticks_since_last_packet++;
    }
}

uint16_t commander_timeout_get_timer(void)
{
    return _ticks_since_last_packet;
}

void commander_timeout_reset_timer(void)
{
    _ticks_since_last_packet = 0;
}
