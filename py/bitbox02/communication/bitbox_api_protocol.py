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
"""BitBox02"""


import os
import enum
import sys
import time
import base64
import binascii
from datetime import datetime
import hashlib
from typing import Optional, Callable, List, Dict, Tuple, Any, Generator, Union
from typing_extensions import TypedDict

import ecdsa
from noise.connection import NoiseConnection, Keypair
import hid
import semver

import u2fhid
import communication
import bitbox02
from bitbox02.devices import parse_device_version, DeviceInfo

try:
    from bitbox02.generated import hww_pb2 as hww
    from bitbox02.generated import eth_pb2 as eth
    from bitbox02.generated import btc_pb2 as btc
    from bitbox02.generated import mnemonic_pb2 as mnemonic
    from bitbox02.generated import bitbox02_system_pb2 as bitbox02_system
    from bitbox02.generated import random_number_pb2 as random_number
    from bitbox02.generated import backup_commands_pb2 as backup
    from bitbox02.generated import system_pb2 as system
except ModuleNotFoundError:
    print("Run `make py` to generate the protobuf messages")
    sys.exit()

try:
    # Optional rlp dependency only needed to sign ethereum transactions.
    # pylint: disable=import-error
    import rlp
except ModuleNotFoundError:
    pass


HWW_CMD = 0x80 + 0x40 + 0x01

ERR_GENERIC = 103
ERR_USER_ABORT = 104

HARDENED = 0x80000000

# values: uncompressed secp256k1 pubkey serialization.
ATTESTATION_PUBKEYS: List[bytes] = [
    binascii.unhexlify(
        "04074ff1273b36c24e80fe3d59e0e897a81732d3f8e9cd07e17e9fc06319cd16b"
        "25cf74255674477b3ac9cbac2d12f0dc27a662681fcbc12955b0bccdcbbdcfd01"
    ),
    binascii.unhexlify(
        "044c53a84f41fa7301b378bb3c260fc9b2ff1cbea7a78181279a8566797a736f1"
        "2cea25fa2b1c27a844392fe9b37547dc6fbd00a2676b816e7d2d3562be2a0cbbd"
    ),
    binascii.unhexlify(
        "04e9c8dc929796aac65af5084eb54dc1ee482d5e0b5c58e2c93f243c5b70b2152"
        "3324bdb78d7395317da165ef1138826c3ca3c91ca95e6f490c340cf5508a4a3ec"
    ),
    binascii.unhexlify(
        "04c2fb05889b9dff5a9fb22a59ee1d16bfc2863f0400ddcb69566e2abe8a15fa0"
        "ba1240254ca45aa310d170e724e1310ce5f611cada76c12e3c24a926a390ca4be"
    ),
    binascii.unhexlify(
        "04c4e82d6d1b91e7853eba96a871ad31fc62620b826b0b8acf815c03de31b792a"
        "98e05bb34d3b9e0df1040eac485f03ff8bbbf7a857ef1cf2a49a60ac084efb88f"
    ),
]

ATTESTATION_PUBKEYS_MAP: Dict[bytes, bytes] = {
    hashlib.sha256(val).digest(): val for val in ATTESTATION_PUBKEYS
}

OP_ATTESTATION = b"a"
OP_UNLOCK = b"u"
OP_INFO = b"i"
OP_I_CAN_HAS_HANDSHAEK = b"h"
OP_I_CAN_HAS_PAIRIN_VERIFICASHUN = b"v"
OP_NOISE_MSG = b"n"

RESPONSE_SUCCESS = b"\x00"
RESPONSE_FAILURE = b"\x01"

Backup = Tuple[str, str, datetime]


class BTCInputType(TypedDict):
    prev_out_hash: bytes
    prev_out_index: int
    prev_out_value: int
    sequence: int
    keypath: List[int]


class BTCOutputInternal:
    # pylint: disable=too-few-public-methods
    # TODO: Use NamedTuple, but not playing well with protobuf types.

    def __init__(self, keypath: List[int], value: int):
        """
        keypath: keypath to the change output.
        """
        self.keypath = keypath
        self.value = value


class BTCOutputExternal:
    # pylint: disable=too-few-public-methods

    # TODO: Use NamedTuple, but not playing well with protobuf types.

    def __init__(self, output_type: btc.BTCOutputType, output_hash: bytes, value: int):
        self.type = output_type
        self.hash = output_hash
        self.value = value


BTCOutputType = Union[BTCOutputInternal, BTCOutputExternal]


class Platform(enum.Enum):
    """ Available hardware platforms """

    BITBOX02 = "bitbox02"
    BITBOXBASE = "bitboxbase"


class BitBox02Edition(enum.Enum):
    """ Editions for the BitBox02 platform """

    MULTI = "multi"
    BTCONLY = "btconly"


class BitBoxBaseEdition(enum.Enum):
    """ Editions for the BitBoxBase platform """

    STANDARD = "standard"


class Bitbox02Exception(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__()

    def __str__(self) -> str:
        return f"error code: {self.code}, message: {self.message}"


class UserAbortException(Bitbox02Exception):
    pass


class AttestationException(Exception):
    pass


class BitBoxAPIExchanger:
    """Class to communicate with a BitBox device"""

    # pylint: disable=too-many-public-methods
    def __init__(
        self,
        device: communication.TransportLayer,
        device_info: DeviceInfo,
        show_pairing_callback: Callable[[str], None],
        attestation_check_callback: Optional[Callable[[bool], None]] = None,
    ):
        self.debug = False
        serial_number = device_info["serial_number"]
        self.device = device

        self.version = parse_device_version(serial_number)
        if self.version is None:
            raise ValueError(f"Could not parse version from {serial_number}")
        # Delete the prelease part, as it messes with the comparison (e.g. 3.0.0-pre < 3.0.0 is
        # True, but the 3.0.0-pre has already the same API breaking changes like 3.0.0...).
        self.version = semver.VersionInfo(
            self.version.major, self.version.minor, self.version.patch, build=self.version.build
        )

        if self.version >= semver.VersionInfo(2, 0, 0):
            if attestation_check_callback is not None:
                # Perform attestation
                attestation_check_callback(self._perform_attestation())

            # Invoke unlock workflow on the device.
            # In version <2.0.0, the device did this automatically.
            unlock_result = self._query(OP_UNLOCK)
            if self.version < semver.VersionInfo(3, 0, 0):
                assert unlock_result == b""
            else:
                # since 3.0.0, unlock can fail if cancelled
                if unlock_result == RESPONSE_FAILURE:
                    raise Exception("Unlock process aborted")

        if self._query(OP_I_CAN_HAS_HANDSHAEK) != RESPONSE_SUCCESS:
            raise Exception("Couldn't kick off handshake")

        # init noise channel
        noise = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
        noise.set_as_initiator()
        dummy_private_key = os.urandom(32)
        noise.set_keypair_from_private_bytes(Keypair.STATIC, dummy_private_key)
        noise.set_prologue(b"Noise_XX_25519_ChaChaPoly_SHA256")
        noise.start_handshake()
        noise.read_message(self._query(noise.write_message()))
        assert not noise.handshake_finished
        send_msg = noise.write_message()
        assert noise.handshake_finished
        pairing_code = base64.b32encode(noise.get_handshake_hash()).decode("ascii")
        show_pairing_callback(
            "{} {}\n{} {}".format(
                pairing_code[:5], pairing_code[5:10], pairing_code[10:15], pairing_code[15:20]
            )
        )
        response = self._query(send_msg)

        # Can be set to False if the remote static pubkey was previously confirmed.
        pairing_verification_required_by_host = True

        pairing_verification_required_by_device = response == b"\x01"
        if pairing_verification_required_by_host or pairing_verification_required_by_device:
            pairing_response = self._query(OP_I_CAN_HAS_PAIRIN_VERIFICASHUN)
            if pairing_response == RESPONSE_SUCCESS:
                pass
            elif pairing_response == RESPONSE_FAILURE:
                raise Exception("pairing rejected by the user")
            else:
                raise Exception("unexpected response")
        self.noise = noise

    def close(self) -> None:
        self.device.close()

    def _perform_attestation(self) -> bool:
        """Sends a random challenge and verifies that the response can be verified with
        Shift's root attestation pubkeys. Returns True if the verification is successful."""

        challenge = os.urandom(32)
        response = self._query(OP_ATTESTATION + challenge)
        if response[:1] != RESPONSE_SUCCESS:
            return False

        # parse data
        response = response[1:]
        bootloader_hash, response = response[:32], response[32:]
        device_pubkey_bytes, response = response[:64], response[64:]
        certificate, response = response[:64], response[64:]
        root_pubkey_identifier, response = response[:32], response[32:]
        challenge_signature, response = response[:64], response[64:]

        # check attestation
        if root_pubkey_identifier not in ATTESTATION_PUBKEYS_MAP:
            # root pubkey could not be identified.
            return False

        root_pubkey_bytes_uncompressed = ATTESTATION_PUBKEYS_MAP[root_pubkey_identifier]
        root_pubkey = ecdsa.VerifyingKey.from_string(
            root_pubkey_bytes_uncompressed[1:], ecdsa.curves.SECP256k1
        )

        device_pubkey = ecdsa.VerifyingKey.from_string(device_pubkey_bytes, ecdsa.curves.NIST256p)

        try:
            # Verify certificate
            if not root_pubkey.verify(
                certificate, bootloader_hash + device_pubkey_bytes, hashfunc=hashlib.sha256
            ):
                return False

            # Verify challenge
            if not device_pubkey.verify(challenge_signature, challenge, hashfunc=hashlib.sha256):
                return False
        except ecdsa.BadSignatureError:
            return False
        return True

    def _query(self, msg: bytes) -> bytes:
        """
        Sends msg bytes and retrieves response bytes.
        """
        cid = self.device.generate_cid()
        return self.device.query(msg, HWW_CMD, cid)

    def _encrypted_query(self, msg: bytes) -> bytes:
        """
        Sends msg bytes and reads response bytes over an encrypted channel.
        """
        encrypted_msg = self.noise.encrypt(msg)
        if self.version >= semver.VersionInfo(4, 0, 0):
            encrypted_msg = OP_NOISE_MSG + encrypted_msg

        result = self.noise.decrypt(self._query(encrypted_msg))
        assert isinstance(result, bytes)
        return result

    def _msg_query(
        self, request: hww.Request, expected_response: Optional[str] = None
    ) -> hww.Response:
        """
        Sends protobuf msg and retrieves protobuf response over an encrypted
        channel.
        """
        # pylint: disable=no-member
        if self.debug:
            print(request)
        response_bytes = self._encrypted_query(request.SerializeToString())
        response = hww.Response()
        response.ParseFromString(response_bytes)
        if response.WhichOneof("response") == "error":
            if response.error.code == ERR_USER_ABORT:
                raise UserAbortException(response.error.code, response.error.message)
            raise Bitbox02Exception(response.error.code, response.error.message)
        if expected_response is not None and response.WhichOneof("response") != expected_response:
            raise Exception(
                "Unexpected response: {}, expected: {}".format(
                    response.WhichOneof("response"), expected_response
                )
            )
        if self.debug:
            print(response)
        return response


class BitBoxCommonAPI:
    def __init__(self):
        pass

    def random_number(self) -> bytes:
        # pylint: disable=no-member
        request = hww.Request()
        request.random_number.CopyFrom(random_number.RandomNumberRequest())
        response = self._msg_query(request, expected_response="random_number")
        return response.random_number.number

    def reboot(self) -> bool:
        """TODO: Document"""
        # pylint: disable=no-member
        request = hww.Request()
        request.reboot.CopyFrom(system.RebootRequest())
        try:
            self._msg_query(request)
        except OSError:
            # In case of reboot we can't read the response.
            return True
        except Bitbox02Exception:
            return False
        return True

    def get_info(self) -> Tuple[str, Platform, Union[BitBox02Edition, BitBoxBaseEdition], bool]:
        """
        Returns (version, platform, edition, unlocked).
        """
        response = self._query(OP_INFO)

        version_str_len, response = int(response[0]), response[1:]
        version, response = response[:version_str_len], response[version_str_len:]
        version_str = version.rstrip(b"\0").decode("ascii")

        platform_byte, response = response[0], response[1:]
        platform = {0x00: Platform.BITBOX02}[platform_byte]

        edition_byte, response = response[0], response[1:]
        edition: Union[BitBox02Edition, BitBoxBaseEdition]
        if platform == Platform.BITBOX02:
            edition = {0x00: BitBox02Edition.MULTI, 0x01: BitBox02Edition.BTCONLY}[edition_byte]
        else:
            edition = {0x00: BitBoxBaseEdition.STANDARD}[edition_byte]

        unlocked_byte = response[0]
        unlocked = {0x00: False, 0x01: True}[unlocked_byte]
        return (version_str, platform, edition, unlocked)
