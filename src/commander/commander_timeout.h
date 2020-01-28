#ifndef _COMMANDER_TIMEOUT_H
#define _COMMANDER_TIMEOUT_H

#include <stdint.h>

void commander_timeout_tick(void);

uint16_t commander_timeout_get_timer(void);

void commander_timeout_reset_timer(void);

#endif // _COMMANDER_TIMEOUT_H
