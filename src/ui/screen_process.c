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

#include "screen_process.h"
#include "screen_stack.h"
#include <hardfault.h>
#include <touch/gestures.h>
#include <ui/components/waiting.h>
#include <ui/screen_process.h>
#include <ui/ugui/ugui.h>
#include <inttypes.h>

#include <string.h>
static uint8_t screen_frame_cnt = 0;

#if defined(SAVE_READINGS) || defined(DISPLAY_READINGS)
extern FILE* _dump_file;
const char* last_event  = "none";
//  Buffer 32 samples
//uint16_t reading_buf[8 * 32] = {0};
//uint16_t *last_reading = reading_buf;
uint16_t last_reading[4];
//uint16_t *read_buf_ptr = reading_buf;
uint16_t max_reading[2] = {0};
uint16_t adj_reading[2] = {0};
uint16_t glob_x[2] = {0};
uint16_t glob_y[2] = {0};
#endif

void ui_screen_render_component(component_t* component)
{
    UG_ClearBuffer();
    component->position.left = 0;
    component->position.top = 0;
    component->f->render(component);
#ifdef DISPLAY_READINGS
    char evtstring[100];
    //snprintf(evtstring, 100, "%s\nL: %"PRIu16" M: %"PRIu16" A:%"PRIu16" X: %"PRIu16" Y: %"PRIu16"\nL2: %"PRIu16" M2: %"PRIu16" A:%"PRIu16" X: %"PRIu16" Y: %"PRIu16, last_event, last_reading[0], max_reading[0], adj_reading[0], glob_x[0], glob_y[0], last_reading[1], max_reading[1], adj_reading[1], glob_x[1], glob_y[1]);
    //snprintf(evtstring, 100, "%s\nL: %"PRIu16" A:%"PRIu16" X: %"PRIu16" Y: %"PRIu16"\nL2: %"PRIu16" A:%"PRIu16" X: %"PRIu16" Y: %"PRIu16, last_event, last_reading[0], adj_reading[0], glob_x[0], glob_y[0], last_reading[1], adj_reading[1], glob_x[1], glob_y[1]);
    snprintf(evtstring, 100, "%s\nL: %"PRIu16" A:%"PRIu16, last_event, last_reading[0], adj_reading[0]);
    if (last_event) {
        UG_PutString(0, 30, evtstring, false);
    }
#endif
    UG_SendBuffer();
}

/**
 * Detects if the screen component being displayed has changed
 * since the last time this function was called.
 * This stores the last observed component into a global.
 *
 * @param[in] current_component Current on-screen component.
 */
static bool _screen_has_changed(const component_t* current_component)
{
    static const component_t* last_observed_comp = NULL;
    if (last_observed_comp != current_component) {
        last_observed_comp = current_component;
        return true;
    }
    return false;
}

static component_t* _get_waiting_screen(void)
{
    static component_t* waiting_screen = NULL;
    if (waiting_screen == NULL) {
        waiting_screen = waiting_create();
        if (waiting_screen == NULL) {
            Abort("Could not create\nwaiting screen");
        }
    }
    return waiting_screen;
}

/**
 * Renders the provided component on the display.
 *
 * @param[in] component Screen to draw.
 */
static void _screen_draw(component_t* component)
{
    if (screen_frame_cnt == SCREEN_FRAME_RATE) {
        screen_frame_cnt = 0;
        ui_screen_render_component(component);
    }
    screen_frame_cnt++;
}

/*
 * Select which activity we should draw next
 * (or fallback to the idle screen).
 */
static component_t* _get_ui_top_component(void)
{
    component_t* result = ui_screen_stack_top();
    if (!result) {
        return _get_waiting_screen();
    }
    return result;
}

//static int write_count = 0;
void screen_process(void)
{
    component_t* component = _get_ui_top_component();
    _screen_draw(component);

    /*
     * If we have changed activity, the gestures
     * detection must start over.
     */
    bool screen_new = _screen_has_changed(component);
    gestures_detect(screen_new, component->emit_without_release);
#ifdef SAVE_READINGS
    //fprintf(_dump_file, "%s,%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16",%"PRIu16"\n", last_event, last_reading[0], last_reading[1], max_reading[0], max_reading[1], adj_reading[0], adj_reading[1], glob_x[0], glob_x[1], glob_y[0], glob_y[1]);
    //fprintf(_dump_file, "%"PRIu16",%"PRIu16"\n", last_reading[0], adj_reading[0]);
    fwrite(last_reading, 2, 4, _dump_file);
    //write_count++;
    //memcpy(read_buf_ptr, last_reading, 8 * sizeof(*reading_buf));
    //read_buf_ptr+=8;
    //if (write_count == 32) {
        //fwrite(reading_buf, 2, 32 * 8, _dump_file);
        //write_count = 0;
        //read_buf_ptr = reading_buf;
    //}
#endif
    ui_screen_stack_cleanup();
}
