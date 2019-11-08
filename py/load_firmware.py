#!/usr/bin/env python3
# Copyright 2019 Shift Cryptosecurity AG
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""TODO: document"""

import argparse
import hid
import serial
import sys
import pprint
from typing import Any
from time import sleep

from bitbox02 import devices
from bitbox02 import Bootloader, BitBox02
from bitbox02 import TooManyFoundException, NoneFoundException
from communication import TransportLayer
from communication import u2fhid
from communication import usart


def eprint(*args: Any, **kwargs: Any) -> None:
    """
    Like print, but defaults to stderr.
    """
    kwargs.setdefault("file", sys.stderr)
    print(*args, **kwargs)


def get_bitbox_and_reboot() -> devices.DeviceInfo:
    """Search for a bitbox and then reboot it into bootloader"""
    device = devices.get_any_bitbox02()

    # bitbox02 detected -> send command to reboot into bootloader to upgrade.
    def _show_pairing(code: str) -> None:
        print("Please compare and confirm the pairing code on your BitBox02:")
        print(code)

    hid_device = hid.device()
    hid_device.open_path(device["path"])
    bitbox = BitBox02(
        device=u2fhid.U2FHid(hid_device), device_info=device, show_pairing_callback=_show_pairing
    )
    bitbox.reboot()

    # wait for it to reboot
    while True:
        try:
            bootloader_device = devices.get_any_bitbox02_bootloader()
        except NoneFoundException:
            sys.stdout.write(".")
            sys.stdout.flush()
            sleep(1)
            continue
        return bootloader_device


def find_and_open_usb_bitbox() -> (dict, TransportLayer):
    bootloader_device = None
    try:
        bootloader_device = devices.get_any_bitbox02_bootloader()
    except TooManyFoundException:
        eprint("Found multiple bb02 bootloader standard editions. Only one supported.")
        sys.exit(1)
    except NoneFoundException:
        pass

    if bootloader_device is None:
        try:
            bootloader_device = get_bitbox_and_reboot()
        except TooManyFoundException:
            eprint("Found multiple bitboxes. Only one supported.")
            sys.exit(1)
        except NoneFoundException:
            eprint("Neither bootloader nor bitbox found.")
            sys.exit(1)

    pprint.pprint(bootloader_device)

    hid_dev = hid.device()
    hid_dev.open_path(bootloader_device["path"])
    return bootloader_device, u2fhid.U2FHid(hid_dev)


def try_usart_bootloader_connection(serial_port, bootloader_device) -> str:
    transport = usart.U2FUsart(serial_port)
    try:
        bootloader_attempt = Bootloader(transport, bootloader_device)
        bootloader_attempt.versions()
        success = "Connected"
    except usart.U2FUsartErrorResponse as e:
        if e.error_code != usart.U2FUsartErrorResponse.ErrorCode.USART_FRAME_ERROR_ENDPOINT_UNAVAILABLE:
            raise
        else:
            success = "NotAvailable"
    except usart.U2FUsartTimeoutError:
        success = "Timeout"
    finally:
        bootloader_attempt.close()
    return success


def find_and_open_usart_bitbox(serial_port) -> (dict, TransportLayer):
    print("Connecting to BitBox bootloader over UART.")
    bootloader_device = {"serial_number": "v4.2.0", "product_string": "bb02-base"}
    # First, try to connect to the bootloader directly.
    bootloader_status = try_usart_bootloader_connection(serial_port, bootloader_device)
    if bootloader_status == "Connected":
        return bootloader_device
    elif bootloader_status == "Timeout":
        print("No reponse from BitBox. Maybe it's not connected properly?")
        sys.exit(1)

    # The bootloader wasn't valid, try to connect to the firmware instead.
    print("BitBox bootloader not available.")
    print("Trying to connect to BitBox firmware instead...")

    def _show_pairing(code: str) -> None:
        print("Accept the pairing request on your device...")

    try:
        transport = usart.U2FUsart(serial_port)
        bitbox_attempt = BitBox02(transport, bootloader_device, show_pairing_callback=_show_pairing)
        print("Connected. Rebooting.")
        bitbox_attempt.reboot()
    except usart.U2FUsartTimeoutError:
        pass
    finally:
        bitbox_attempt.close()
    print("Reboot completed.")

    # wait for it to reboot
    while True:
        bootloader_status = try_usart_bootloader_connection(serial_port, bootloader_device)
        if bootloader_status == "Connected":
            return bootloader_device
        elif bootloader_status == "Timeout":
            print("Waiting for the BitBox bootloader to show up...")
            sleep(1)
        else:
            print("Stuck in bitbox mode -  didn't reboot properly!")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Tool for flashing a new firmware on BitBox devices."
    )
    parser.add_argument("--debug", action="store_true", help="Flash a debug (unsigned) firmware.")
    parser.add_argument(
        "--usart",
        action="store",
        help="Flash firmware using U2F-over-UART (BitBoxBase), with the specified serial port.",
    )
    parser.add_argument("firmware", nargs=1, help="Firmware to flash.")
    args = parser.parse_args()

    if not args.debug and ".signed.bin" not in args.firmware[0]:
        eprint("Expecting firmware to end with '.signed.bin'")
        return 1

    if args.usart is not None:
        serial_port = serial.Serial(args.usart, 115200, timeout=3)
        bootloader_device = find_and_open_usart_bitbox(serial_port)
        transport = usart.U2FUsart(serial_port)
        bootloader = Bootloader(transport, bootloader_device)
    else:
        bootloader_device, transport = find_and_open_usb_bitbox()
    bootloader = Bootloader(transport, bootloader_device)

    with open(args.firmware[0], "rb") as file:
        firmware = file.read()

    def progress(perc: float) -> None:
        sys.stdout.write(f"{perc*100:.02f}%\r")

    if bootloader.erased():
        print("device contains NO firmware")
    else:
        print("firmware version: %d\nsigning pubkeys version: %d" % bootloader.versions())
        firmware_hash, signing_keydata_hash = bootloader.get_hashes()
        print("firmware hash:", firmware_hash.hex())
        print("signing keydata hash:", signing_keydata_hash.hex())

    if args.debug:
        bootloader.flash_unsigned_firmware(firmware, progress)
    else:
        bootloader.flash_signed_firmware(firmware, progress)
    print()  # print a newline

    sleep(1)  # Pause to show the upgrade finished at 100%
    bootloader.reboot()
    return 0


if __name__ == "__main__":
    sys.exit(main())
