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
from communication import PhysicalLayer, TransportLayer
from typing_extensions import Protocol

PING = 0x80 | 0x01
MSG = 0x80 | 0x03
LOCK = 0x80 | 0x04
INIT = 0x80 | 0x06
WINK = 0x80 | 0x08
SYNC = 0x80 | 0x3C
ERROR = 0xFF

class U2FUsartError(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)

class U2FUsartTimeoutError(U2FUsartError):
    def __init__(self):
        U2FUsartError.__init__(self, "Connection timed out.")

class U2FUsartErrorResponse(U2FUsartError):
    class ErrorCode:
        USART_FRAME_ERROR_ENDPOINT_UNAVAILABLE = 0x01
        USART_FRAME_ERROR_ENDPOINT_BUSY = 0x02
        USART_FRAME_ERROR_INVALID_CMD = 0x03

    def __init__(self, error_code, src_endpoint):
        U2FUsartError.__init__(
            self,
            "Error response from the UART port, endpoint {}, error code {}.".format(
                src_endpoint, error_code
            ),
        )
        self.error_code = error_code
        self.src_endpoint = src_endpoint


class U2FUsart(TransportLayer):
    def generate_cid(self) -> int:
        """Generate a valid CID"""
        return 0x42

    def _encodeUsartFrame(self, msg):
        return b"\x7E" + msg.replace(b"\x7D", b"\x7D\x5D").replace(b"\x7E", b"\x7D\x5E") + b"\x7E"

    def _readUsartFrame(self) -> bytes:
        all_read = bytes()
        while True:
            r = self._device.read(1)
            if len(r) == 0:
                return bytes(), all_read
            # print("Read {:02X}".format(r[0]))
            all_read += r
            if r == b"\x7E":
                break
        stuff = bytes()
        while True:
            r = self._device.read(1)
            if len(r) == 0:
                return stuff, all_read
            # print("Read {:02X}".format(r[0]))
            all_read += r
            if r == b"\x7D":
                r = self._device.read(1)
                stuff += bytes([r[0] ^ 0x20])
            elif r == b"\x7E":
                return stuff, all_read
            else:
                stuff += r

    def bytes2hex(self, data):
        return " ".join(["{:02X}".format(c) for c in data])

    def write(self, data: bytes, dst_endpoint: int, cid: int) -> None:
        """
        Send data to the device.

        Args:
            data: Data to send
            dst_endpoint: U2F HID command/Destination endpoint
            cid: U2F HID channel ID (will be ignored)
        Throws:
            ValueError: In case any value is out of range
        """
        if dst_endpoint < 0 or dst_endpoint > 0xFF:
            raise ValueError("Channel command is out of range '0 < dst_endpoint <= 0xFF'")
        if dst_endpoint < 0 or dst_endpoint > 0xFFFFFFFF:
            raise ValueError("Channel id is out of range '0 < dst_endpoint <= 0xFFFFFFFF'")
        to_write = bytes([1, dst_endpoint]) + bytearray(data)
        checksum = self.compute_checksum(to_write)
        checksum_bytes = struct.pack("<H", checksum)
        to_write = to_write + checksum_bytes
        # print("Checksum: {} ({})".format(checksum, checksum_bytes))
        data_len = len(to_write)
        if data_len > 5000:
            raise ValueError("Data is too large 'size <= 5000'")

        to_write = self._encodeUsartFrame(to_write)
        # print("Writing length {}: {}".format(len(data), self.bytes2hex(data)))
        # print("Writing encoded length {}: {}".format(len(to_write), self.bytes2hex(to_write)))

        # print("Host -> Base (unpacked): endpoint {:02X}, data (len {}): ".format(dst_endpoint, len(data)) + self.bytes2hex(data))
        # print("Host -> Base (raw): " + self.bytes2hex(to_write))
        for w in to_write:
            while True:
                ww = bytes([w])
                res = self._device.write(ww)
                if res == 1:
                    break

    def compute_checksum(self, data):
        if (len(data) % 2) != 0:
            data = data + b"\x00"
        n_sums = int(len(data) / 2)
        cs = 0
        for i in range(n_sums):
            cs += struct.unpack("<H", data[2 * i : 2 * i + 2])[0]
            if cs > 0xFFFF:
                cs -= 0xFFFF
                assert cs > 0 and cs <= 0xFFFF
        return cs

    def read(self, endpoint: int, cid: int) -> bytes:
        """
        Receive data from the device.

        Args:
            endpoint: The expected returned U2F HID command (endpoint)
            cid: The expected returned U2F CID (will be ignored).
        Returns:
            The contents of the read message.
        Throws:
            ValueError: In case any value is out of range
            Exception: In case of USART communication issues
        """
        if endpoint < 0 or endpoint > 0xFF:
            raise ValueError("Source endpoint id is out of range '0 < endpoint <= 0xFF'")
        buf, raw_dump = self._readUsartFrame()
        # print("Base -> Host: " + bytes2hex(raw_dump), file=dump_file)
        # print("Response ({} bytes): {}".format(len(buf), bytes2hex(buf)))
        if len(buf) < 4:
            raise U2FUsartTimeoutError()
        version = buf[0]
        src_endpoint = buf[1]
        reply_checksum = struct.unpack("<H", buf[-2:])[0]
        data_len = len(buf) - 4
        data = buf[:-2]
        idx = len(buf) - 7
        if src_endpoint == ERROR:
            raise U2FUsartErrorResponse(data[0], data[1])
        expected_checksum = self.compute_checksum(data)
        if expected_checksum != reply_checksum:
            raise Exception(
                f"- USART checksum incorrect! {reply_checksum:x} != {expected_checksum:x}"
            )
        if src_endpoint != endpoint:
            raise Exception(f"- USART source endpoint mismatch {endpoint:x} != {src_endpoint:x}")
        data = data[2:]
        # print("Base -> Host (unpacked): cmd {:02X}, endpoint {:02X}, data (len {}): ".format(reply_cmd, src_endpoint, len(data)) + bytes2hex(data), file=dump_file)
        return data

    def __init__(self, device: PhysicalLayer):
        self._device = device
