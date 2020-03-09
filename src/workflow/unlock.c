// Copyright 2019 Shift Cryptosecurity AG
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

#include "unlock.h"
#include "confirm.h"
#include "password_enter.h"
#include "status.h"
#include "workflow.h"
#include <hardfault.h>
#include <keystore.h>
#include <memory/memory.h>
#include <screen.h>
#include <string.h>
#include <ui/components/ui_images.h>
#include <ui/fonts/password_11X12.h>
#include <ui/screen_stack.h>
#include <ui/ugui/ugui.h>
#include <util.h>
#ifndef TESTING
#include <hal_timer.h>
extern struct timer_descriptor TIMER_0;
#endif

#define TIMEOUT_TICK_PERIOD_MS 100

#if !defined(TESTING)
static struct timer_task _animation_timer_task = {0};
static int _animation_timer_count = 0;

/** ~3800ms unlock time, measured using this timer. */
#define UNLOCK_TIME_TICKS (38)

/**
 * Displays a closed lock at start (0ms),
 * followed by an open lock after 600ms.
 */
static void _animation_timer_cb(const struct timer_task* const timer_task)
{
    (void)timer_task;
    if (_animation_timer_count == UNLOCK_TIME_TICKS ) {
        /* End of the animation */
        return;
    }

    UG_ClearBuffer();
    if (_animation_timer_count < (UNLOCK_TIME_TICKS / 2)) {
        image_lock(SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 - 1, IMAGE_DEFAULT_LOCK_RADIUS);
    } else {
        image_unlock(SCREEN_WIDTH / 2, SCREEN_HEIGHT / 2 - 1, IMAGE_DEFAULT_LOCK_RADIUS);
    }

    /* Progress bar */
    const uint16_t bar_height = 5;
    UG_FillFrame(0, SCREEN_HEIGHT - bar_height, (SCREEN_WIDTH * _animation_timer_count / UNLOCK_TIME_TICKS), SCREEN_HEIGHT, C_WHITE);
    UG_SendBuffer();
    _animation_timer_count++;
}

/**
 * Sets up a timer animating a lock icon every 100ms
 */
static void _start_animation_timer(void)
{
    _animation_timer_task.interval = TIMEOUT_TICK_PERIOD_MS;
    _animation_timer_task.cb = _animation_timer_cb;
    _animation_timer_task.mode = TIMER_TASK_REPEAT;
    timer_stop(&TIMER_0);
    timer_add_task(&TIMER_0, &_animation_timer_task);
    _animation_timer_count = 0;
    timer_start(&TIMER_0);
}

static void _stop_animation_timer(void)
{
    timer_stop(&TIMER_0);
    timer_remove_task(&TIMER_0, &_animation_timer_task);
    timer_start(&TIMER_0);
}
#endif

static bool _get_mnemonic_passphrase(char* passphrase_out)
{
    if (passphrase_out == NULL) {
        Abort("_get_mnemonic_passphrase");
    }
    while (true) {
        if (!password_enter("Enter\noptional passphrase", true, passphrase_out)) {
            return false;
        }
        if (strlen(passphrase_out) == 0) {
            // No need to confirm the empty passphrase.
            break;
        }
        const confirm_params_t params = {
            .title = "",
            .body = "You will be asked to\nvisually confirm your\npassphrase now.",
            .accept_only = true,
        };
        if (!workflow_confirm_blocking(&params)) {
            return false;
        }
        if (workflow_confirm_scrollable_longtouch_blocking(
                "Confirm", passphrase_out, &font_password_11X12)) {
            break;
        }
        workflow_status_create("Please try again", false);
    }
    return true;
}

bool workflow_unlock_bip39(void)
{
    // Empty passphrase by default.
    char mnemonic_passphrase[SET_PASSWORD_MAX_PASSWORD_LENGTH] = {0};
    UTIL_CLEANUP_STR(mnemonic_passphrase);
    if (memory_is_mnemonic_passphrase_enabled()) {
        if (!_get_mnemonic_passphrase(mnemonic_passphrase)) {
            return false;
        }
    }

    // animation
    // Cannot render screens during unlocking (unlocking blocks)
    // Therefore hardcode a status screen
#ifndef TESTING
    _start_animation_timer();
#endif
    bool unlock_result = keystore_unlock_bip39(mnemonic_passphrase);
#ifndef TESTING
    _stop_animation_timer();
#endif

    if (!unlock_result) {
        Abort("bip39 unlock failed");
    }
    return true;
}

keystore_error_t workflow_unlock_and_handle_error(const char* password)
{
    uint8_t remaining_attempts = 0;
    keystore_error_t unlock_result = keystore_unlock(password, &remaining_attempts);
    switch (unlock_result) {
    case KEYSTORE_OK:
    case KEYSTORE_ERR_MAX_ATTEMPTS_EXCEEDED:
        break;
    case KEYSTORE_ERR_INCORRECT_PASSWORD: {
        char msg[100] = {0};
        if (remaining_attempts == 1) {
            snprintf(msg, sizeof(msg), "Wrong password\n1 try remains");
        } else {
            snprintf(msg, sizeof(msg), "Wrong password\n%d tries remain", remaining_attempts);
        }
        workflow_status_create(msg, false);
        break;
    }
    default:
        Abort("keystore unlock failed");
    }
    return unlock_result;
}

bool workflow_unlock(void)
{
    if (!memory_is_initialized()) {
        return false;
    }
    if (!keystore_is_locked()) {
        return true;
    }

    ui_screen_stack_pop_all();

    // Repeat attempting to unlock until success or device reset.
    while (true) {
        char password[SET_PASSWORD_MAX_PASSWORD_LENGTH] = {0};
        UTIL_CLEANUP_STR(password);
        if (!password_enter("Enter password", false, password)) {
            return false;
        }

        keystore_error_t unlock_result = workflow_unlock_and_handle_error(password);
        if (unlock_result == KEYSTORE_OK) {
            // Keystore unlocked, now unlock bip39 seed.
            if (!workflow_unlock_bip39()) {
                return false;
            }
            break;
        }
        if (unlock_result == KEYSTORE_ERR_MAX_ATTEMPTS_EXCEEDED) {
            // Device reset
            break;
        }
    }
    return true;
}
