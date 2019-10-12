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

#![no_std]
use bitbox02_sys::{self, delay_ms, delay_us};
use core::alloc::{GlobalAlloc, Layout};
use core::time::Duration;

//use once_cell::unsync::{Lazy, OnceCell};

// Since we don't have a complete stdlib but have a heap we implement a global allocator using
// malloc and free.
extern "C" {
    fn malloc(size: usize) -> *mut u8;
    fn free(ptr: *mut u8);
}

pub struct Allocator;

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        malloc(layout.size())
    }
    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr)
    }
}

/// Safe wrapper for UG_PutString
pub fn ug_put_string(x: i16, y: i16, input: &str, inverted: bool) {
    // rust strings (&str) are not null-terminated, ensure that there always is a \0 byte.
    let len = core::cmp::min(127, input.len());
    let mut buf = [0u8; 128];
    buf[0..len].copy_from_slice(&input.as_bytes()[0..len]);
    unsafe { bitbox02_sys::UG_PutString(x, y, buf.as_ptr() as *const _, inverted) }
}

pub fn ug_clear_buffer() {
    unsafe { bitbox02_sys::UG_ClearBuffer() }
}

pub fn ug_send_buffer() {
    unsafe { bitbox02_sys::UG_SendBuffer() }
}

pub fn ug_font_select() {
    unsafe { bitbox02_sys::UG_FontSelect(&bitbox02_sys::font_font_a_9X9) }
}

/// Safe wrapper for delay_us / delay_ms
pub fn delay(duration: Duration) {
    if duration < Duration::from_micros(1) {
        unsafe {
            // Sleep the smallest unit of sleep we support
            delay_us(1)
        }
    } else if duration < Duration::from_millis(1) {
        unsafe {
            delay_us(duration.as_micros() as u16);
        }
    } else {
        unsafe {
            delay_ms(duration.as_millis() as u16);
        }
    }
}

/// Safe wrapper for workflow_confirm
pub fn workflow_confirm(title: &str, body: &str, longtouch: bool, accept_only: bool) -> bool {
    // Ensure valid nullterminated C-str
    let title_cstr = {
        const TITLE_LEN: usize = 20;
        let len = core::cmp::min(TITLE_LEN, title.len());
        let mut buf = [0u8; TITLE_LEN + 1];
        buf[0..len].copy_from_slice(&title.as_bytes()[0..len]);
        buf
    };
    // Ensure valid nullterminated C-str
    let body_cstr = {
        const BODY_LEN: usize = 100;
        let len = core::cmp::min(BODY_LEN, body.len());
        let mut buf = [0u8; BODY_LEN + 1];
        buf[0..len].copy_from_slice(&body.as_bytes()[0..len]);
        buf
    };

    unsafe {
        bitbox02_sys::workflow_confirm(
            title_cstr.as_ptr() as *const _,
            body_cstr.as_ptr() as *const _,
            longtouch,
            accept_only,
        )
    }
}

//unsafe extern "C" fn bbb_cleanup(_component: *mut bitbox02_sys::component_t) {
//}
//unsafe extern "C" fn bbb_render(component: *mut bitbox02_sys::component_t) {
//    let comp: &mut BgComponent = ((*component).data as *mut BgComponent).as_mut().unwrap();
//    comp.render();
//}
//unsafe extern "C" fn bbb_on_event(_event: *const bitbox02_sys::event_t, _component: *mut bitbox02_sys::component_t) {
//}
//
//pub struct BgComponent {
//    counter: u32,
//}
//
//static mut BG_COMPONENT: Option<Component<BgComponent>> = None;
//
//pub fn bitboxbase_loading_screen_push() {
//    use bitbox02_sys::{component_t, component_functions_t, dimension_t, position_t, sub_components_t};
//
//    unsafe {
//        BG_COMPONENT = Some(
//            Component {
//                component_c: component_t {
//                    f: core::ptr::null_mut(),
//                    dimension: dimension_t {width: 128, height: 64},
//                    position: position_t {left: 0, top: 0},
//                    data: core::ptr::null_mut(),
//                    sub_components: sub_components_t {amount: 0, sub_components: [core::ptr::null_mut(); 35]},
//                    parent: core::ptr::null_mut(),
//                    emit_without_release: false,
//                },
//                functions: component_functions_t {
//                    cleanup: Some(bbb_cleanup),
//                    render: Some(bbb_render),
//                    on_event: Some(bbb_on_event),
//                },
//                component: BgComponent {counter: 0},
//            });
//        let bg_comp = BG_COMPONENT.as_mut().unwrap();
//        bg_comp.component_c.f = &mut bg_comp.functions;
//        let ptr: *mut BgComponent = &mut bg_comp.component;
//        bg_comp.component_c.data = ptr as _;
//
//        bitbox02_sys::ui_screen_stack_push(&(bg_comp.component_c) as *const _);
//    }
//}
//
//trait Renderable {
//    fn render(&mut self);
//}
//
//struct Component<T:Renderable> {
//    component_c: bitbox02_sys::component_t,
//    functions: bitbox02_sys::component_functions_t,
//    component: T
//}
//
//impl Renderable for BgComponent {
//    fn render(&mut self) {
//        unsafe {
//        ug_put_string(0, 0, "hejhej", false);
//        delay_ms(1500);
//
//        }
//    }
//}
