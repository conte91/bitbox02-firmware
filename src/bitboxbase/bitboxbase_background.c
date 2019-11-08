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

#include "bitboxbase_background.h"
#include <ui/component.h>
#include <ui/components/image.h>
#include <ui/components/ui_images.h>
#include <ui/components/label.h>
#include <ui/ui_util.h>
#include <hardfault.h>
#include <ui/screen_stack.h>
#include <string.h>
#include <rust/bitbox02_rust.h>

static void _render(component_t* component);

static component_functions_t _component_functions = {
    .cleanup = ui_util_component_cleanup,
    .render = _render,
    .on_event = ui_util_on_event_noop,
};

void _render(component_t* component) {
    component_t* label = component->sub_components.sub_components[1];
    if (bitboxbase_config_started()) {
        char buf[100] = "IP: ";
        bitboxbase_config_ip_get(&buf[4], sizeof(buf)-4);
        label_update(label, buf);
    }
    ui_util_component_render_subcomponents(component);
}

static component_t* _create(void) {
    component_t* show_logo = malloc(sizeof(component_t));
    if (!show_logo) {
        Abort("Error: malloc show_logo");
    }
    memset(show_logo, 0, sizeof(component_t));
    show_logo->f = &_component_functions;
    show_logo->dimension.width = 128;
    show_logo->dimension.height = 64;
    component_t* bb2_logo = image_create(
        IMAGE_BB2_LOGO,
        sizeof(IMAGE_BB2_LOGO),
        IMAGE_BB2_LOGO_W,
        IMAGE_BB2_LOGO_H,
        CENTER,
        show_logo);
    component_t* loading_label = label_create(
        "Booting...", NULL, RIGHT_BOTTOM, show_logo
        );
    ui_util_add_sub_component(show_logo, bb2_logo);
    ui_util_add_sub_component(show_logo, loading_label);
    return show_logo;
}

void bitboxbase_background(void) {
    component_t* b = _create();
    ui_screen_stack_push(b);
}
