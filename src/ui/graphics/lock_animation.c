// Copyright 2020 Shift Cryptosecurity AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "lock_animation.h"

#include <stdint.h>

#include <hardfault.h>

#include "graphics.h"
#include <screen.h>
#include <ui/ugui/ugui.h>

#ifndef TESTING
#include <hal_timer.h>
#include <platform/driver_init.h>
#endif

#define LOCK_ANIMATION_ACTUAL_N_FRAMES (10)
/**
 * Use less frames than ticks for the animation.
 *
 * Split the remaining animation time into long frame times
 * for the closed lock, open lock, and turned lock.
 */
#define LOCK_ANIMATION_FRAMES_STOP_TIME \
    ((LOCK_ANIMATION_N_FRAMES - LOCK_ANIMATION_ACTUAL_N_FRAMES) / 3)

/**
 * At frame 4, the animation will pause for a second.
 */
#define LOCK_ANIMATION_PAUSE_FRAME (2)

#ifndef TESTING
static const uint8_t LOCK_ANIMATION[LOCK_ANIMATION_ACTUAL_N_FRAMES][LOCK_ANIMATION_FRAME_SIZE] = {
    // Frame 0 - Closed lock
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x03, 0xe0, 0x00, 0x00, 0xff, 0x80, 0x00, 0x1c, 0x1c, 0x00, 0x03,
     0x80, 0xe0, 0x00, 0x30, 0x06, 0x00, 0x06, 0x00, 0x30, 0x00, 0x60, 0x03, 0x00, 0x06, 0x00,
     0x30, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 1
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xe0, 0x00,
     0x00, 0xff, 0x80, 0x00, 0x1c, 0x1c, 0x00, 0x03, 0x80, 0xe0, 0x00, 0x30, 0x06, 0x00, 0x06,
     0x00, 0x30, 0x00, 0x60, 0x03, 0x00, 0x06, 0x00, 0x30, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 2 - Open lock
    {0x00, 0x00, 0x3e, 0x00, 0x00, 0x0f, 0xf8, 0x00, 0x01, 0xc1, 0xc0, 0x00, 0x38, 0x0e, 0x00,
     0x03, 0x00, 0x60, 0x00, 0x60, 0x03, 0x00, 0x06, 0x00, 0x30, 0x00, 0x60, 0x03, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 3
    {0x00, 0x00, 0x38, 0x00, 0x00, 0x0f, 0xe0, 0x00, 0x01, 0xc7, 0x00, 0x00, 0x38, 0x38, 0x00,
     0x03, 0x01, 0x80, 0x00, 0x60, 0x0c, 0x00, 0x06, 0x00, 0xc0, 0x00, 0x60, 0x0c, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 4
    {0x00, 0x00, 0xe0, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0xb0, 0x00, 0x00, 0x31, 0x80, 0x00,
     0x03, 0x18, 0x00, 0x00, 0x61, 0x80, 0x00, 0x06, 0x18, 0x00, 0x00, 0x61, 0x80, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 5
    {0x00, 0x01, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x03, 0x80, 0x00, 0x00, 0x38, 0x00, 0x00,
     0x03, 0x80, 0x00, 0x00, 0x68, 0x00, 0x00, 0x06, 0x80, 0x00, 0x00, 0x68, 0x00, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 6
    {0x00, 0x08, 0x00, 0x00, 0x01, 0xc0, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x01, 0xc0, 0x00, 0x00,
     0x1c, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x16, 0x00, 0x00, 0x01, 0x60, 0x00, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 7
    {0x00, 0x70, 0x00, 0x00, 0x0d, 0x80, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x18, 0xc0, 0x00, 0x01,
     0x8c, 0x00, 0x00, 0x18, 0x60, 0x00, 0x01, 0x86, 0x00, 0x00, 0x18, 0x60, 0x00, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 8
    {0x01, 0xc0, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x0e, 0x38, 0x00, 0x01, 0xc1, 0xc0, 0x00, 0x18,
     0x0c, 0x00, 0x03, 0x00, 0x60, 0x00, 0x30, 0x06, 0x00, 0x03, 0x00, 0x60, 0x00, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0},
    // Frame 9 - Turned lock
    {0x07, 0xc0, 0x00, 0x01, 0xff, 0x00, 0x00, 0x38, 0x38, 0x00, 0x07, 0x01, 0xc0, 0x00, 0x60,
     0x0c, 0x00, 0x0c, 0x00, 0x60, 0x00, 0xc0, 0x06, 0x00, 0x0c, 0x00, 0x60, 0x00, 0x00, 0x06,
     0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x06, 0x00,
     0x00, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0,
     0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00,
     0x7f, 0xff, 0x00, 0x07, 0xff, 0xf0, 0x00, 0x7f, 0xff, 0x00, 0x03, 0xff, 0xe0}};

/**
 * Gets a frame of the lock animation.
 */
static const uint8_t* _get_frame(int frame_idx)
{
    if (frame_idx >= LOCK_ANIMATION_N_FRAMES) {
        Abort("Invalid lock animation frame requested.");
    }
    /* First part of the animation: Closed lock for LOCK_ANIMATION_FRAMES_STOP_TIME frames. */
    if (frame_idx < LOCK_ANIMATION_FRAMES_STOP_TIME) {
        return LOCK_ANIMATION[0];
    }
    /* Second part: show the lock opening */
    int actual_frame_idx = frame_idx - LOCK_ANIMATION_FRAMES_STOP_TIME;
    if (actual_frame_idx < LOCK_ANIMATION_PAUSE_FRAME) {
        return LOCK_ANIMATION[actual_frame_idx];
    }
    /* Third part: keep the lock open for a while. */
    if (actual_frame_idx < LOCK_ANIMATION_FRAMES_STOP_TIME + LOCK_ANIMATION_PAUSE_FRAME) {
        return LOCK_ANIMATION[LOCK_ANIMATION_PAUSE_FRAME];
    }
    /* Fourth/fifth part: Spin the lock, then keep it open for a while. */
    actual_frame_idx -= LOCK_ANIMATION_FRAMES_STOP_TIME;
    if (actual_frame_idx >= LOCK_ANIMATION_ACTUAL_N_FRAMES) {
        return LOCK_ANIMATION[LOCK_ANIMATION_ACTUAL_N_FRAMES - 1];
    }
    return LOCK_ANIMATION[actual_frame_idx];
}
#endif

#define TIMEOUT_TICK_PERIOD_MS 100

#ifndef TESTING
static struct timer_task _animation_timer_task = {0};
static int _animation_current_frame = 0;

/**
 * Displays frames of the lock animation
 * at a regular rate until it's finished.
 * Leaves the last frame on the screen.
 */
static void _animation_timer_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    if (_animation_current_frame == LOCK_ANIMATION_N_FRAMES) {
        /* End of the animation */
        return;
    }

    /* Draw the frame. */
    UG_ClearBuffer();
    position_t pos = {.left = (SCREEN_WIDTH - LOCK_ANIMATION_FRAME_WIDTH) / 2,
                      .top = (SCREEN_HEIGHT - LOCK_ANIMATION_FRAME_HEIGHT) / 2};
    dimension_t dim = {.width = LOCK_ANIMATION_FRAME_WIDTH, .height = LOCK_ANIMATION_FRAME_HEIGHT};
    in_buffer_t image = {.data = _get_frame(_animation_current_frame),
                         .len = LOCK_ANIMATION_FRAME_SIZE};
    graphics_draw_image(&pos, &dim, &image);
    UG_SendBuffer();
    _animation_current_frame++;
}
#endif

/**
 * Sets up a timer animating a lock icon every 100ms
 */
void lock_animation_start(void)
{
#ifndef TESTING
    _animation_timer_task.interval = TIMEOUT_TICK_PERIOD_MS;
    _animation_timer_task.cb = _animation_timer_cb;
    _animation_timer_task.mode = TIMER_TASK_REPEAT;
    timer_stop(&TIMER_0);
    timer_add_task(&TIMER_0, &_animation_timer_task);
    _animation_current_frame = 0;
    timer_start(&TIMER_0);
#endif
}

void lock_animation_stop(void)
{
#ifndef TESTING
    timer_stop(&TIMER_0);
    timer_remove_task(&TIMER_0, &_animation_timer_task);
    timer_start(&TIMER_0);
#endif
}