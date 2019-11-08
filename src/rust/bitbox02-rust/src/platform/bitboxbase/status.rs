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

pub enum AlarmState {
    Communication,
    Offline,
}

pub enum AlarmSeverity {
    Notice,
    Warning,
    Error,
}

struct Alarm {
    state: AlarmState,
    severity: AlarmSeverity,
}

impl Alarm {
    pub fn new(state: AlarmState, severity: AlarmSeverity) -> Self {
        Alarm {state, severity}
    }
}

pub struct Status {
    alarm: Option<Alarm>,
}

impl Status {
    pub const fn new() -> Status {
        Status {
            alarm: None,
        }
    }
    /// Update the status, 0 means everything is OK, for other values see implementation.
    pub fn update(&mut self, value: u32) {
        use AlarmState::*;
        use AlarmSeverity::*;
        match value {
            0 => self.alarm = None,
            1 => self.alarm = Some(Alarm::new(Offline, Warning)),
            _ => self.alarm = Some(Alarm::new(Communication,Error)),
        }
    }

    pub fn get_alarm_state(&self) -> Option<&AlarmState> {
        if let Some(alarm) = &self.alarm {
            Some(&alarm.state)
        } else {
            None
        }
    }

    pub fn get_alarm_severity(&self) -> Option<&AlarmSeverity> {
        if let Some(alarm) = &self.alarm {
            Some(&alarm.severity)
        } else {
            None
        }
    }
}
