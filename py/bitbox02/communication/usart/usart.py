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

"""Implementations"""

import struct
import random
import time
from typing_extensions import Protocol

PING = 0x80 | 0x01
MSG = 0x80 | 0x03
LOCK = 0x80 | 0x04
INIT = 0x80 | 0x06
WINK = 0x80 | 0x08
SYNC = 0x80 | 0x3C
ERROR = 0x80 | 0x3F

class SupportsReadWrite(Protocol):
    # pylint: disable=unused-argument,no-self-use

    def write(self, msg: bytes) -> None:
        ...

    def read(self, size: int) -> bytes:
        ...


def generate_cid() -> int:
    """Generate a valid CID"""
    # Exclude 0 and u32_max (0xffff_ffff)
    return random.randrange(1, 0xFFFFFFFF)


def encodeUsartFrame(msg):
    return b'\x7E' + msg.replace(b'\x7D', b'\x7D\x5D').replace(b'\x7E', b'\x7D\x5E') + b'\x7E'

def readUsartFrame(device: SupportsReadWrite) -> bytes:
    all_read = bytes()
    while True:
        r = device.read(1)
        if len(r) == 0:
            return bytes(), all_read
        #print("Read {:02X}".format(r[0]))
        all_read += r
        if r == b'\x7E':
            break
    stuff = bytes()
    while True:
        r = device.read(1)
        if len(r) == 0:
            return stuff, all_read
        #print("Read {:02X}".format(r[0]))
        all_read += r
        if r == b'\x7D':
            r = device.read(1)
            stuff += bytes([r[0] ^ 0x20])
        elif r == b'\x7E':
            return stuff, all_read
        else:
            stuff += r

def bytes2hex(data):
    return " ".join(["{:02X}".format(c) for c in data])

def write(usart_device: SupportsReadWrite, data: bytes, cmd: int, dst_endpoint: int, dump_file) -> None:
    """
    Send data to the device.

    Args:
        usart_device: An object that implements read/write functions
        data: Data to send
        cmd: U2F HID command
        cid: U2F HID channel ID (will be ignored)
    Throws:
        ValueError: In case any value is out of range
    """
    if cmd < 0 or cmd > 0xFF:
        raise ValueError("Channel command is out of range '0 < cmd <= 0xFF'")
    if dst_endpoint < 0 or dst_endpoint > 0xFFFFFFFF:
        raise ValueError("Channel id is out of range '0 < dst_endpoint <= 0xFFFFFFFF'")
    to_write = bytes([1, dst_endpoint, cmd]) + bytearray(data)
    checksum = compute_checksum(to_write)
    checksum_bytes = struct.pack('<H', checksum)
    to_write = to_write + checksum_bytes
    #print("Checksum: {} ({})".format(checksum, checksum_bytes))
    data_len = len(to_write)
    if data_len > 5000:
        raise ValueError("Data is too large 'size <= 5000'")

    to_write = encodeUsartFrame(to_write)
    #print("Writing length {}: {}".format(len(data), bytes2hex(data)))
    #print("Writing encoded length {}: {}".format(len(to_write), bytes2hex(to_write)))

    print("Host -> Base (unpacked): cmd {:02X}, endpoint {:02X}, data (len {}): ".format(cmd, dst_endpoint, len(data)) + bytes2hex(data), file=dump_file)
    print("Host -> Base (raw): " + bytes2hex(to_write), file=dump_file)
    for w in to_write:
        while True:
          ww = bytes([w])
          res = usart_device.write(ww)
          if res == 1:
              break

def compute_checksum(data):
    if (len(data) % 2) != 0:
        data = data + b'\x00'
    n_sums = int(len(data) / 2)
    cs = 0
    for i in range(n_sums):
        cs += struct.unpack('<H', data[2 * i:2 * i + 2])[0]
        if cs > 0xFFFF:
            cs -= 0xFFFF
            assert cs > 0 and cs <= 0xFFFF
    return cs

def read(usart_device: SupportsReadWrite, cmd: int, srcEndpoint: int, dump_file) -> bytes:
    """
    Receive data from the device.

    Args:
        usart_device: An object that implements read/write functions
        cmd: The expected returned U2F HID command
        srcEndpoint: The expected returned USART endpoint ID (will be ignored).
    Returns:
        The read message combined from the u2fhid packets
    Throws:
        ValueError: In case any value is out of range
        Exception: In case of USART communication issues
    """
    if cmd < 0 or cmd > 0xFF:
        raise ValueError("Channel command is out of range '0 < cmd <= 0xFF'")
    if srcEndpoint < 0 or srcEndpoint > 0xFF:
        raise ValueError("Source endpoint id is out of range '0 < srcEndpoint <= 0xFF'")
    buf, raw_dump = readUsartFrame(usart_device)
    print("Base -> Host: " + bytes2hex(raw_dump), file=dump_file)
    #print("Response ({} bytes): {}".format(len(buf), bytes2hex(buf)))
    if len(buf) < 5:
        raise Exception("Packet of {} bytes is too short.".format(len(buf)))
    version = buf[0]
    src_endpoint = buf[1]
    reply_cmd = buf[2]
    reply_checksum = struct.unpack('<H', buf[-2:])[0]
    data_len = len(buf) - 5
    data = buf[:-2]
    idx = len(buf) - 7
    if reply_cmd == ERROR:
        _throw_error(data[0])
    expected_checksum = compute_checksum(data)
    if expected_checksum != reply_checksum:
        raise Exception(f"- USART checksum incorrect! {reply_checksum:x} != {expected_checksum:x}")
    if src_endpoint != srcEndpoint:
        raise Exception(f"- USART source endpoint mismatch {srcEndpoint:x} != {src_endpoint:x}")
    if reply_cmd != cmd:
        raise Exception(f"- USART command mismatch {reply_cmd:x} != {cmd:x}")
    data = data[3:]
    print("Base -> Host (unpacked): cmd {:02X}, endpoint {:02X}, data (len {}): ".format(reply_cmd, src_endpoint, len(data)) + bytes2hex(data), file=dump_file)
    return data
