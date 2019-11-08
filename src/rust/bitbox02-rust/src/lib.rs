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

// Since we are targeting embedded we exclude the standard library by default
#![no_std]
// When compiling for testing we allow certain warnings.
#![cfg_attr(test, allow(unused_imports, dead_code))]

use core::fmt::Write;
use core::panic::PanicInfo;
use core::time::Duration;

// Enable standard library for testing
#[cfg(test)]
extern crate std;
#[cfg(test)]
use std::prelude::v1::*;

mod platform;
mod error;
mod general;
mod util;

use util::Ipv4Addr;
use platform::bitboxbase::status::{AlarmState, AlarmSeverity, Status};

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    print_debug!(0, "Internal error: {}", info);
    loop {}
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn trivial_test() {
        let a = String::from("abc");
        assert!(&a == "abc");
    }
}

// We need to have all external functions in this module (lib.rs) until support for rust 2018
// module system is added to cbindgen. We don't want to use the 2015 module system.
// * https://github.com/eqrion/cbindgen/issues/254

#[no_mangle]
pub extern "C" fn bitboxbase_workflow_confirm_pairing(bytes: *const u8, bytes_len: usize) -> bool {
    assert!(!bytes.is_null());
    assert!(bytes_len > 0 && bytes_len <= 32);
    let bytes = unsafe { core::slice::from_raw_parts(bytes, bytes_len) };
    platform::bitboxbase::workflow::confirm_pairing(bytes)
}

static mut CONFIG: platform::bitboxbase::config::Config = platform::bitboxbase::config::Config::new();

// A trick to convince cbindgen that this is a char.
#[allow(non_camel_case_types)]
type c_char = u8;

/// This function is not multithread safe since it modifies a static global.
#[no_mangle]
pub extern "C" fn bitboxbase_config_set(
    status_led_mode: u8,
    status_screen_mode: u8,
    default_display_duration: u64,
    ip: *const u8,
    hostname: *const c_char,
    hostname_len: usize,
) -> bool {
    assert!(!hostname.is_null());
    let hostname = unsafe { core::slice::from_raw_parts(hostname, hostname_len) };
    let hostname = core::str::from_utf8(hostname).expect("Invalid utf-8");
    assert!(!ip.is_null());
    let ip = Ipv4Addr::from(unsafe {[*ip.offset(0), *ip.offset(1), *ip.offset(2), *ip.offset(3)]});
    // It is not safe to call any functions that also touch CONFIG at the same time
    let config = unsafe { &mut CONFIG };
    match config.set_hostname(hostname) {
        Err(_) => return false,
        _ => (),
    }
    let status_led_mode = match status_led_mode {
        0 => platform::bitboxbase::config::StatusLedMode::Always,
        1 => platform::bitboxbase::config::StatusLedMode::OnWarning,
        2 => platform::bitboxbase::config::StatusLedMode::OnError,
        _ => return false,
    };
    config.set_status_led_mode(status_led_mode);
    let status_screen_mode = match status_screen_mode {
        0 => platform::bitboxbase::config::StatusScreenMode::OnWarning,
        1 => platform::bitboxbase::config::StatusScreenMode::OnError,
        _ => return false,
    };
    config.set_status_screen_mode(status_screen_mode);
    match config.set_default_display_duration(Duration::from_millis(default_display_duration)) {
        Err(_) => return false,
        _ => (),
    }
    config.set_ip(ip);
    true
}

#[no_mangle]
pub extern "C" fn bitboxbase_display_status(duration: u64) {
    // It is not safe to call any functions that also touch CONFIG at the same time
    let config = unsafe { &CONFIG };
    let duration = if duration > 0 {
        Some(Duration::from_millis(duration))
    } else {
        None
    };
    platform::bitboxbase::display::display_status(config, duration);
}

static mut STATUS: Status = Status::new();

#[no_mangle]
pub extern "C" fn bitboxbase_heartbeat(status_code: u32) -> bool {
    // It is not safe to call any functions that also touch STATUS at the same time
    let status = unsafe {&mut STATUS};
    status.update(status_code);

    true
}

//#[no_mangle]
//pub extern "C" fn bitboxbase_loading_screen() {
//    bitbox02::bitboxbase_loading_screen_push();
//}

#[no_mangle]
pub extern "C" fn bitboxbase_config_started() -> bool {
    // It is not safe to call any functions that also touch CONFIG at the same time
    let config = unsafe { &CONFIG };
    return config.ip.is_some()
}

#[no_mangle]
pub extern "C" fn bitboxbase_config_ip_get(res: *mut c_char, res_len: usize) {
    // It is not safe to call any functions that also touch CONFIG at the same time
    let config = unsafe { &CONFIG };
    let buf = unsafe {core::slice::from_raw_parts_mut(res, res_len)};
    let mut astr: arrayvec::ArrayString<[u8; 64]> = arrayvec::ArrayString::new();
    if let Some(ip) = &config.ip {
        let _ = write!(astr, "{}", ip);
    } else {
        let _ = write!(astr, "unknown");
    }
    buf[0..astr.len()].copy_from_slice(&astr.as_bytes()[0..astr.len()]);
}

#[no_mangle]
pub extern "C" fn bitboxbase_status_get_alarm_state() -> u32 {
    let status = unsafe {&STATUS};
    if let Some(state) = status.get_alarm_state() {
        match state {
            AlarmState::Communication => 1,
            AlarmState::Offline => 2,
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn bitboxbase_status_get_alarm_severity() -> u32 {
    let status = unsafe {&STATUS};
    if let Some(severity) = status.get_alarm_severity() {
        match severity {
            AlarmSeverity::Notice => 1,
            AlarmSeverity::Warning => 2,
            AlarmSeverity::Error => 3,
        }
    } else {
        0
    }
}
