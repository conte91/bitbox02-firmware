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
import semver

import communication
from communication import TransportLayer
from .devices import parse_device_version, DeviceInfo

try:
    from .generated import hww_pb2 as hww
    from .generated import eth_pb2 as eth
    from .generated import btc_pb2 as btc
    from .generated import mnemonic_pb2 as mnemonic
    from .generated import bitbox02_system_pb2 as bitbox02_system
    from .generated import random_number_pb2 as random_number
    from .generated import backup_commands_pb2 as backup
    from .generated import system_pb2 as system
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


class BitBox02(communication.BitBoxAPIExchanger, communication.BitBoxCommonAPI):
    """Class to communicate with a BitBox02"""

    # pylint: disable=too-many-public-methods

    def __init__(
        self,
        device: TransportLayer,
        device_info: DeviceInfo,
        show_pairing_callback: Callable[[str], None],
        attestation_check_callback: Optional[Callable[[bool], None]] = None,
    ):
        communication.BitBoxAPIExchanger.__init__(
            self, device, device_info, show_pairing_callback, attestation_check_callback
        )
        communication.BitBoxCommonAPI.__init__(self)

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

    def random_number(self) -> bytes:
        # pylint: disable=no-member
        request = hww.Request()
        request.random_number.CopyFrom(random_number.RandomNumberRequest())
        response = self._msg_query(request, expected_response="random_number")
        return response.random_number.number

    def device_info(self) -> Dict[str, Any]:
        # pylint: disable=no-member
        request = hww.Request()
        device_info_request = bitbox02_system.DeviceInfoRequest()
        request.device_info.CopyFrom(device_info_request)
        response = self._msg_query(request, expected_response="device_info")
        return {
            "name": response.device_info.name,
            "version": response.device_info.version,
            "initialized": response.device_info.initialized,
            "mnemonic_passphrase_enabled": response.device_info.mnemonic_passphrase_enabled,
            "monotonic_increments_remaining": response.device_info.monotonic_increments_remaining,
        }

    def set_device_name(self, device_name: str) -> None:
        # pylint: disable=no-member
        request = hww.Request()
        request.device_name.name = device_name
        self._msg_query(request, expected_response="success")

    def set_password(self) -> bool:
        """
        Returns True if the user entered the password correctly (passwords match).
        Returns False otherwise.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.set_password.entropy = os.urandom(32)
        try:
            self._msg_query(request, expected_response="success")
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return False
            raise
        return True

    def create_backup(self) -> bool:
        """
        Returns True if the backup was created successfully.
        Returns False otherwise.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.create_backup.timestamp = int(time.time())
        request.create_backup.timezone_offset = time.localtime().tm_gmtoff
        try:
            self._msg_query(request, expected_response="success")
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return False
            raise
        return True

    def list_backups(self) -> Generator[Backup, None, None]:
        """
        Returns a pair of id and timestamp's strings that identify the backups.
        """
        # pylint: disable=no-member
        self.insert_sdcard()
        request = hww.Request()
        request.list_backups.CopyFrom(backup.ListBackupsRequest())
        response = self._msg_query(request, expected_response="list_backups")
        for info in response.list_backups.info:
            utcdate = datetime.utcfromtimestamp(info.timestamp)
            yield (info.id, info.name, utcdate)

    def restore_backup(self, backup_id: str) -> bool:
        """
        Sends a restore API call to the BitBox.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.restore_backup.id = backup_id
        request.restore_backup.timestamp = int(time.time())
        request.restore_backup.timezone_offset = time.localtime().tm_gmtoff
        try:
            self._msg_query(request, expected_response="success")
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return False
            raise
        return True

    def check_backup(self, silent: bool = False) -> Optional[str]:
        """
        Sends a check backup API call to the BitBox.
        Returns the backup ID if the backup was found and can be restored.
        Otherwise, returns None. If silent is True, the result won't be shown on the device screen.
        """
        # pylint: disable=no-member
        self.insert_sdcard()
        request = hww.Request()
        request.check_backup.CopyFrom(backup.CheckBackupRequest(silent=silent))
        try:
            response = self._msg_query(request, expected_response="check_backup")
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return None
            raise
        return response.check_backup.id

    def show_mnemonic(self) -> bool:
        """
        Returns True if mnemonic was successfully shown and confirmed.
        Returns False otherwise.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.show_mnemonic.CopyFrom(mnemonic.ShowMnemonicRequest())
        try:
            self._msg_query(request, expected_response="success")
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return False
            raise
        return True

    def btc_pub(
        self,
        keypath: List[int],
        coin: btc.BTCCoin = btc.BTC,
        output_type: btc.BTCPubRequest.OutputType = btc.BTCPubRequest.XPUB,
        script_type: btc.BTCScriptType = btc.SCRIPT_UNKNOWN,
        display: bool = True,
    ) -> str:
        """
        keypath is a list of child derivation numbers.
        e.g. m/44'/0'/1'/5 corresponds to [44+HARDENED, 0+HARDENED, 1+HARDENED, 5].
        """
        # pylint: disable=no-member,too-many-arguments
        request = hww.Request()
        request.btc_pub.CopyFrom(
            btc.BTCPubRequest(
                coin=coin,
                keypath=keypath,
                output_type=output_type,
                script_type=script_type,
                display=display,
            )
        )
        return self._msg_query(request).pub.pub

    # pylint: disable=too-many-arguments
    def btc_sign(
        self,
        coin: btc.BTCCoin,
        script_type: btc.BTCScriptType,
        bip44_account: int,
        inputs: List[BTCInputType],
        outputs: List[BTCOutputType],
        version: int = 1,
        locktime: int = 0,
    ) -> List[Tuple[int, bytes]]:
        """
        coin: the first element of all provided keypaths must match the coin:
        - BTC: 0 + HARDENED
        - Testnets: 1 + HARDENED
        - LTC: 2 + HARDENED
        script_type: type of all inputs and change outputs. The first element of all provided
        keypaths must match this type:
        - SCRIPT_P2PKH: 44 + HARDENED
        - SCRIPT_P2WPKH_P2SH: 49 + HARDENED
        - SCRIPT_P2WPKH: 84 + HARDENED
        bip44_account: Starting at (0 + HARDENED), must be the third element of all provided
        keypaths.
        inputs: transaction inputs.
        outputs: transaction outputs. Can be an external output
        (BTCOutputExternal) or an internal output for change (BTCOutputInternal).
        version, locktime: reserved for future use.
        Returns: list of (input index, signature) tuples.
        Raises Bitbox02Exception with ERR_USER_ABORT on user abort.
        """
        # pylint: disable=too-many-locals,no-member

        # Reserved for future use.
        assert version == 1 and locktime == 0

        sigs: List[Tuple[int, bytes]] = []

        # Init request
        request = hww.Request()
        request.btc_sign_init.CopyFrom(
            btc.BTCSignInitRequest(
                coin=coin,
                script_type=script_type,
                bip44_account=bip44_account,
                version=version,
                num_inputs=len(inputs),
                num_outputs=len(outputs),
                locktime=locktime,
            )
        )
        next_response = self._msg_query(request, expected_response="btc_sign_next").btc_sign_next
        while True:
            if next_response.type == btc.BTCSignNextResponse.INPUT:
                input_index = next_response.index
                tx_input = inputs[input_index]

                request = hww.Request()
                request.btc_sign_input.CopyFrom(
                    btc.BTCSignInputRequest(
                        prevOutHash=tx_input["prev_out_hash"],
                        prevOutIndex=tx_input["prev_out_index"],
                        prevOutValue=tx_input["prev_out_value"],
                        sequence=tx_input["sequence"],
                        keypath=tx_input["keypath"],
                    )
                )
                next_response = self._msg_query(
                    request, expected_response="btc_sign_next"
                ).btc_sign_next
                if next_response.has_signature:
                    sigs.append((input_index, next_response.signature))
            elif next_response.type == btc.BTCSignNextResponse.OUTPUT:
                output_index = next_response.index
                tx_output = outputs[output_index]

                request = hww.Request()
                if isinstance(tx_output, BTCOutputInternal):
                    request.btc_sign_output.CopyFrom(
                        btc.BTCSignOutputRequest(
                            ours=True, value=tx_output.value, keypath=tx_output.keypath
                        )
                    )
                elif isinstance(tx_output, BTCOutputExternal):
                    request.btc_sign_output.CopyFrom(
                        btc.BTCSignOutputRequest(
                            ours=False,
                            type=tx_output.type,
                            hash=tx_output.hash,
                            value=tx_output.value,
                        )
                    )
                next_response = self._msg_query(
                    request, expected_response="btc_sign_next"
                ).btc_sign_next
            elif next_response.type == btc.BTCSignNextResponse.DONE:
                break
            else:
                raise Exception("unexpected response")
        return sigs

    def check_sdcard(self) -> bool:
        # pylint: disable=no-member
        request = hww.Request()
        request.check_sdcard.CopyFrom(backup.CheckSDCardRequest())
        response = self._msg_query(request, expected_response="check_sdcard")
        return response.check_sdcard.inserted

    def insert_sdcard(self) -> None:
        # pylint: disable=no-member
        request = hww.Request()
        request.insert_remove_sdcard.CopyFrom(
            bitbox02_system.InsertRemoveSDCardRequest(
                action=bitbox02_system.InsertRemoveSDCardRequest.INSERT_CARD
            )
        )
        self._msg_query(request, expected_response="success")

    def remove_sdcard(self) -> None:
        # pylint: disable=no-member
        request = hww.Request()
        request.insert_remove_sdcard.CopyFrom(
            bitbox02_system.InsertRemoveSDCardRequest(
                action=bitbox02_system.InsertRemoveSDCardRequest.REMOVE_CARD
            )
        )
        self._msg_query(request, expected_response="success")

    def enable_mnemonic_passphrase(self) -> None:
        """
        Enable the bip39 passphrase.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.set_mnemonic_passphrase_enabled.enabled = True
        self._msg_query(request, expected_response="success")

    def disable_mnemonic_passphrase(self) -> None:
        """
        Disable the bip39 passphrase.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.set_mnemonic_passphrase_enabled.enabled = False
        self._msg_query(request, expected_response="success")

    def _eth_msg_query(
        self, eth_request: eth.ETHRequest, expected_response: Optional[str] = None
    ) -> eth.ETHResponse:
        """
        Same as _msg_query, but one nesting deeper for ethereum messages.
        """
        # pylint: disable=no-member
        request = hww.Request()
        request.eth.CopyFrom(eth_request)
        eth_response = self._msg_query(request, expected_response="eth").eth
        if (
            expected_response is not None
            and eth_response.WhichOneof("response") != expected_response
        ):
            raise Exception(
                "Unexpected response: {}, expected: {}".format(
                    eth_response.WhichOneof("response"), expected_response
                )
            )
        return eth_response

    def eth_pub(
        self,
        keypath: List[int],
        coin: eth.ETHCoin = eth.ETH,
        output_type: eth.ETHPubRequest.OutputType = eth.ETHPubRequest.ADDRESS,
        display: bool = True,
        contract_address: bytes = b"",
    ) -> str:
        """
        keypath is a list of child derivation numbers.
        e.g. m/44'/60'/0'/0/5 corresponds to [44+HARDENED, 60+HARDENED, 0+HARDENED, 0, 5].
        """
        # pylint: disable=no-member
        request = eth.ETHRequest()
        request.pub.CopyFrom(
            eth.ETHPubRequest(
                coin=coin,
                keypath=keypath,
                output_type=output_type,
                display=display,
                contract_address=contract_address,
            )
        )
        return self._eth_msg_query(request, expected_response="pub").pub.pub

    def eth_sign(
        self, transaction: bytes, keypath: List[int], coin: eth.ETHCoin = eth.ETH
    ) -> bytes:
        """
        transaction should be given as a full rlp encoded eth transaction.
        """
        nonce, gas_price, gas_limit, recipient, value, data, _, _, _ = rlp.decode(transaction)
        request = eth.ETHRequest()
        # pylint: disable=no-member
        request.sign.CopyFrom(
            eth.ETHSignRequest(
                coin=coin,
                keypath=keypath,
                nonce=nonce,
                gas_price=gas_price,
                gas_limit=gas_limit,
                recipient=recipient,
                value=value,
                data=data,
            )
        )
        return self._eth_msg_query(request, expected_response="sign").sign.signature

    def reset(self) -> bool:
        """
        Factory reset the device. Returns True on success.
        """
        request = hww.Request()
        # pylint: disable=no-member
        request.reset.CopyFrom(bitbox02_system.ResetRequest())
        try:
            self._msg_query(request)
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return False
            raise
        return True

    def restore_from_mnemonic(self) -> bool:
        """
        Restore from mnemonic. Returns True on success, False on failure or user abort.
        """
        request = hww.Request()
        # pylint: disable=no-member
        request.restore_from_mnemonic.CopyFrom(
            mnemonic.RestoreFromMnemonicRequest(
                timestamp=int(time.time()), timezone_offset=time.localtime().tm_gmtoff
            )
        )
        try:
            self._msg_query(request)
        except Bitbox02Exception as err:
            if err.code == ERR_GENERIC:
                return False
            raise
        return True
