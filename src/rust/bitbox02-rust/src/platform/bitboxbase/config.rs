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

use core::time::Duration;

use arrayvec::ArrayString;

use crate::error::Error;
use crate::util::Ipv4Addr;

#[derive(Debug)]
pub enum StatusLedMode {
    Always,
    OnWarning,
    OnError,
}

#[derive(Debug)]
pub enum StatusScreenMode {
    OnWarning,
    OnError,
}

pub struct Config {
    pub(crate) status_led_mode: StatusLedMode,
    pub(crate) status_screen_mode: StatusScreenMode,
    pub(crate) default_display_duration: Duration,
    pub(crate) hostname: Option<ArrayString<[u8; 64]>>,
    pub(crate) ip: Option<Ipv4Addr>,
    pub(crate) error_code: Option<ArrayString<[u8; 64]>>,
}

impl Config {
    pub const fn new() -> Config {
        Config {
            status_led_mode: StatusLedMode::Always,
            status_screen_mode: StatusScreenMode::OnWarning,
            default_display_duration: Duration::from_secs(10),
            hostname: None,
            ip: None,
            error_code: None,
        }
    }

    pub fn set_status_led_mode(&mut self, mode: StatusLedMode) {
        self.status_led_mode = mode;
    }

    pub fn set_status_screen_mode(&mut self, mode: StatusScreenMode) {
        self.status_screen_mode = mode;
    }

    pub fn set_hostname(&mut self, hostname: &str) -> Result<(), Error> {
        if hostname.chars().any(|c| !c.is_alphanumeric()) {
            return Err(Error::InvalidHostname);
        }
        self.hostname = Some(ArrayString::from(hostname).expect("Buffer to short"));
        Ok(())
    }
    pub fn set_default_display_duration(&mut self, duration: Duration) -> Result<(), Error> {
        if duration > Duration::from_secs(60) {
            return Err(Error::TooLongScrenOnDuration);
        }
        self.default_display_duration = duration;
        Ok(())
    }
    pub fn set_ip(&mut self, ip: Ipv4Addr) {
        self.ip = Some(ip);
    }
    pub fn set_error_code(&mut self, error_code: &str) {
        self.error_code = Some(ArrayString::from(error_code).expect("Buffer to short"));
    }
}
