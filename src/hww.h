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

#ifndef _HWW_H_
#define _HWW_H_

#define HWW_MSG (HID_VENDOR_FIRST + 0x01) // Hardware wallet command

/**
 * Set up the HWW command.
 */
void hww_setup(void);

/**
 * Processes the async operations on the HWW USB stack.
 * This is not doing anything at the moment, as all user operations
 * are handled with blocking operations upon packet reception.
 */
void hww_process(void);

/**
 * Function that will be invoked periodically
 * from the timer ISR.
 * It will keep track of how much time has passed
 * since the last HWW packet was received.
 */
void hww_timeout_tick(void);

#endif
