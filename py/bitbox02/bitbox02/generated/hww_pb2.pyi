# @generated by generate_proto_mypy_stubs.py.  Do not edit!
import sys
from .backup_commands_pb2 import (
    CheckBackupRequest as backup_commands_pb2___CheckBackupRequest,
    CheckBackupResponse as backup_commands_pb2___CheckBackupResponse,
    CreateBackupRequest as backup_commands_pb2___CreateBackupRequest,
    ListBackupsRequest as backup_commands_pb2___ListBackupsRequest,
    ListBackupsResponse as backup_commands_pb2___ListBackupsResponse,
    RestoreBackupRequest as backup_commands_pb2___RestoreBackupRequest,
)

from .bitbox02_system_pb2 import (
    CheckSDCardRequest as bitbox02_system_pb2___CheckSDCardRequest,
    CheckSDCardResponse as bitbox02_system_pb2___CheckSDCardResponse,
    DeviceInfoRequest as bitbox02_system_pb2___DeviceInfoRequest,
    DeviceInfoResponse as bitbox02_system_pb2___DeviceInfoResponse,
    InsertRemoveSDCardRequest as bitbox02_system_pb2___InsertRemoveSDCardRequest,
    ResetRequest as bitbox02_system_pb2___ResetRequest,
    SetDeviceLanguageRequest as bitbox02_system_pb2___SetDeviceLanguageRequest,
    SetDeviceNameRequest as bitbox02_system_pb2___SetDeviceNameRequest,
    SetPasswordRequest as bitbox02_system_pb2___SetPasswordRequest,
)

from .bitboxbase_pb2 import (
    BitBoxBaseRequest as bitboxbase_pb2___BitBoxBaseRequest,
)

from .btc_pb2 import (
    BTCPubRequest as btc_pb2___BTCPubRequest,
    BTCSignInitRequest as btc_pb2___BTCSignInitRequest,
    BTCSignInputRequest as btc_pb2___BTCSignInputRequest,
    BTCSignNextResponse as btc_pb2___BTCSignNextResponse,
    BTCSignOutputRequest as btc_pb2___BTCSignOutputRequest,
)

from .common_pb2 import (
    PubResponse as common_pb2___PubResponse,
)

from .eth_pb2 import (
    ETHRequest as eth_pb2___ETHRequest,
    ETHResponse as eth_pb2___ETHResponse,
)

from google.protobuf.message import (
    Message as google___protobuf___message___Message,
)

from .mnemonic_pb2 import (
    RestoreFromMnemonicRequest as mnemonic_pb2___RestoreFromMnemonicRequest,
    SetMnemonicPassphraseEnabledRequest as mnemonic_pb2___SetMnemonicPassphraseEnabledRequest,
    ShowMnemonicRequest as mnemonic_pb2___ShowMnemonicRequest,
)

from .perform_attestation_pb2 import (
    PerformAttestationRequest as perform_attestation_pb2___PerformAttestationRequest,
    PerformAttestationResponse as perform_attestation_pb2___PerformAttestationResponse,
)

from .random_number_pb2 import (
    RandomNumberRequest as random_number_pb2___RandomNumberRequest,
    RandomNumberResponse as random_number_pb2___RandomNumberResponse,
)

from .system_pb2 import (
    RebootRequest as system_pb2___RebootRequest,
)

from typing import (
    Optional as typing___Optional,
    Text as typing___Text,
)

from typing_extensions import (
    Literal as typing_extensions___Literal,
)


class Error(google___protobuf___message___Message):
    code = ... # type: int
    message = ... # type: typing___Text

    def __init__(self,
        *,
        code : typing___Optional[int] = None,
        message : typing___Optional[typing___Text] = None,
        ) -> None: ...
    @classmethod
    def FromString(cls, s: bytes) -> Error: ...
    def MergeFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    def CopyFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    if sys.version_info >= (3,):
        def ClearField(self, field_name: typing_extensions___Literal[u"code",u"message"]) -> None: ...
    else:
        def ClearField(self, field_name: typing_extensions___Literal[u"code",b"code",u"message",b"message"]) -> None: ...

class Success(google___protobuf___message___Message):

    def __init__(self,
        ) -> None: ...
    @classmethod
    def FromString(cls, s: bytes) -> Success: ...
    def MergeFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    def CopyFrom(self, other_msg: google___protobuf___message___Message) -> None: ...

class Request(google___protobuf___message___Message):

    @property
    def random_number(self) -> random_number_pb2___RandomNumberRequest: ...

    @property
    def device_name(self) -> bitbox02_system_pb2___SetDeviceNameRequest: ...

    @property
    def device_language(self) -> bitbox02_system_pb2___SetDeviceLanguageRequest: ...

    @property
    def device_info(self) -> bitbox02_system_pb2___DeviceInfoRequest: ...

    @property
    def set_password(self) -> bitbox02_system_pb2___SetPasswordRequest: ...

    @property
    def create_backup(self) -> backup_commands_pb2___CreateBackupRequest: ...

    @property
    def show_mnemonic(self) -> mnemonic_pb2___ShowMnemonicRequest: ...

    @property
    def btc_pub(self) -> btc_pb2___BTCPubRequest: ...

    @property
    def btc_sign_init(self) -> btc_pb2___BTCSignInitRequest: ...

    @property
    def btc_sign_input(self) -> btc_pb2___BTCSignInputRequest: ...

    @property
    def btc_sign_output(self) -> btc_pb2___BTCSignOutputRequest: ...

    @property
    def insert_remove_sdcard(self) -> bitbox02_system_pb2___InsertRemoveSDCardRequest: ...

    @property
    def check_sdcard(self) -> bitbox02_system_pb2___CheckSDCardRequest: ...

    @property
    def set_mnemonic_passphrase_enabled(self) -> mnemonic_pb2___SetMnemonicPassphraseEnabledRequest: ...

    @property
    def list_backups(self) -> backup_commands_pb2___ListBackupsRequest: ...

    @property
    def restore_backup(self) -> backup_commands_pb2___RestoreBackupRequest: ...

    @property
    def perform_attestation(self) -> perform_attestation_pb2___PerformAttestationRequest: ...

    @property
    def reboot(self) -> system_pb2___RebootRequest: ...

    @property
    def check_backup(self) -> backup_commands_pb2___CheckBackupRequest: ...

    @property
    def eth(self) -> eth_pb2___ETHRequest: ...

    @property
    def reset(self) -> bitbox02_system_pb2___ResetRequest: ...

    @property
    def restore_from_mnemonic(self) -> mnemonic_pb2___RestoreFromMnemonicRequest: ...

    @property
    def bitboxbase(self) -> bitboxbase_pb2___BitBoxBaseRequest: ...

    def __init__(self,
        *,
        random_number : typing___Optional[random_number_pb2___RandomNumberRequest] = None,
        device_name : typing___Optional[bitbox02_system_pb2___SetDeviceNameRequest] = None,
        device_language : typing___Optional[bitbox02_system_pb2___SetDeviceLanguageRequest] = None,
        device_info : typing___Optional[bitbox02_system_pb2___DeviceInfoRequest] = None,
        set_password : typing___Optional[bitbox02_system_pb2___SetPasswordRequest] = None,
        create_backup : typing___Optional[backup_commands_pb2___CreateBackupRequest] = None,
        show_mnemonic : typing___Optional[mnemonic_pb2___ShowMnemonicRequest] = None,
        btc_pub : typing___Optional[btc_pb2___BTCPubRequest] = None,
        btc_sign_init : typing___Optional[btc_pb2___BTCSignInitRequest] = None,
        btc_sign_input : typing___Optional[btc_pb2___BTCSignInputRequest] = None,
        btc_sign_output : typing___Optional[btc_pb2___BTCSignOutputRequest] = None,
        insert_remove_sdcard : typing___Optional[bitbox02_system_pb2___InsertRemoveSDCardRequest] = None,
        check_sdcard : typing___Optional[bitbox02_system_pb2___CheckSDCardRequest] = None,
        set_mnemonic_passphrase_enabled : typing___Optional[mnemonic_pb2___SetMnemonicPassphraseEnabledRequest] = None,
        list_backups : typing___Optional[backup_commands_pb2___ListBackupsRequest] = None,
        restore_backup : typing___Optional[backup_commands_pb2___RestoreBackupRequest] = None,
        perform_attestation : typing___Optional[perform_attestation_pb2___PerformAttestationRequest] = None,
        reboot : typing___Optional[system_pb2___RebootRequest] = None,
        check_backup : typing___Optional[backup_commands_pb2___CheckBackupRequest] = None,
        eth : typing___Optional[eth_pb2___ETHRequest] = None,
        reset : typing___Optional[bitbox02_system_pb2___ResetRequest] = None,
        restore_from_mnemonic : typing___Optional[mnemonic_pb2___RestoreFromMnemonicRequest] = None,
        bitboxbase : typing___Optional[bitboxbase_pb2___BitBoxBaseRequest] = None,
        ) -> None: ...
    @classmethod
    def FromString(cls, s: bytes) -> Request: ...
    def MergeFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    def CopyFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    if sys.version_info >= (3,):
        def HasField(self, field_name: typing_extensions___Literal[u"bitboxbase",u"btc_pub",u"btc_sign_init",u"btc_sign_input",u"btc_sign_output",u"check_backup",u"check_sdcard",u"create_backup",u"device_info",u"device_language",u"device_name",u"eth",u"insert_remove_sdcard",u"list_backups",u"perform_attestation",u"random_number",u"reboot",u"request",u"reset",u"restore_backup",u"restore_from_mnemonic",u"set_mnemonic_passphrase_enabled",u"set_password",u"show_mnemonic"]) -> bool: ...
        def ClearField(self, field_name: typing_extensions___Literal[u"bitboxbase",u"btc_pub",u"btc_sign_init",u"btc_sign_input",u"btc_sign_output",u"check_backup",u"check_sdcard",u"create_backup",u"device_info",u"device_language",u"device_name",u"eth",u"insert_remove_sdcard",u"list_backups",u"perform_attestation",u"random_number",u"reboot",u"request",u"reset",u"restore_backup",u"restore_from_mnemonic",u"set_mnemonic_passphrase_enabled",u"set_password",u"show_mnemonic"]) -> None: ...
    else:
        def HasField(self, field_name: typing_extensions___Literal[u"bitboxbase",b"bitboxbase",u"btc_pub",b"btc_pub",u"btc_sign_init",b"btc_sign_init",u"btc_sign_input",b"btc_sign_input",u"btc_sign_output",b"btc_sign_output",u"check_backup",b"check_backup",u"check_sdcard",b"check_sdcard",u"create_backup",b"create_backup",u"device_info",b"device_info",u"device_language",b"device_language",u"device_name",b"device_name",u"eth",b"eth",u"insert_remove_sdcard",b"insert_remove_sdcard",u"list_backups",b"list_backups",u"perform_attestation",b"perform_attestation",u"random_number",b"random_number",u"reboot",b"reboot",u"request",b"request",u"reset",b"reset",u"restore_backup",b"restore_backup",u"restore_from_mnemonic",b"restore_from_mnemonic",u"set_mnemonic_passphrase_enabled",b"set_mnemonic_passphrase_enabled",u"set_password",b"set_password",u"show_mnemonic",b"show_mnemonic"]) -> bool: ...
        def ClearField(self, field_name: typing_extensions___Literal[u"bitboxbase",b"bitboxbase",u"btc_pub",b"btc_pub",u"btc_sign_init",b"btc_sign_init",u"btc_sign_input",b"btc_sign_input",u"btc_sign_output",b"btc_sign_output",u"check_backup",b"check_backup",u"check_sdcard",b"check_sdcard",u"create_backup",b"create_backup",u"device_info",b"device_info",u"device_language",b"device_language",u"device_name",b"device_name",u"eth",b"eth",u"insert_remove_sdcard",b"insert_remove_sdcard",u"list_backups",b"list_backups",u"perform_attestation",b"perform_attestation",u"random_number",b"random_number",u"reboot",b"reboot",u"request",b"request",u"reset",b"reset",u"restore_backup",b"restore_backup",u"restore_from_mnemonic",b"restore_from_mnemonic",u"set_mnemonic_passphrase_enabled",b"set_mnemonic_passphrase_enabled",u"set_password",b"set_password",u"show_mnemonic",b"show_mnemonic"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions___Literal[u"request",b"request"]) -> typing_extensions___Literal["random_number","device_name","device_language","device_info","set_password","create_backup","show_mnemonic","btc_pub","btc_sign_init","btc_sign_input","btc_sign_output","insert_remove_sdcard","check_sdcard","set_mnemonic_passphrase_enabled","list_backups","restore_backup","perform_attestation","reboot","check_backup","eth","reset","restore_from_mnemonic","bitboxbase"]: ...

class Response(google___protobuf___message___Message):

    @property
    def success(self) -> Success: ...

    @property
    def error(self) -> Error: ...

    @property
    def random_number(self) -> random_number_pb2___RandomNumberResponse: ...

    @property
    def device_info(self) -> bitbox02_system_pb2___DeviceInfoResponse: ...

    @property
    def pub(self) -> common_pb2___PubResponse: ...

    @property
    def btc_sign_next(self) -> btc_pb2___BTCSignNextResponse: ...

    @property
    def list_backups(self) -> backup_commands_pb2___ListBackupsResponse: ...

    @property
    def check_backup(self) -> backup_commands_pb2___CheckBackupResponse: ...

    @property
    def perform_attestation(self) -> perform_attestation_pb2___PerformAttestationResponse: ...

    @property
    def check_sdcard(self) -> bitbox02_system_pb2___CheckSDCardResponse: ...

    @property
    def eth(self) -> eth_pb2___ETHResponse: ...

    def __init__(self,
        *,
        success : typing___Optional[Success] = None,
        error : typing___Optional[Error] = None,
        random_number : typing___Optional[random_number_pb2___RandomNumberResponse] = None,
        device_info : typing___Optional[bitbox02_system_pb2___DeviceInfoResponse] = None,
        pub : typing___Optional[common_pb2___PubResponse] = None,
        btc_sign_next : typing___Optional[btc_pb2___BTCSignNextResponse] = None,
        list_backups : typing___Optional[backup_commands_pb2___ListBackupsResponse] = None,
        check_backup : typing___Optional[backup_commands_pb2___CheckBackupResponse] = None,
        perform_attestation : typing___Optional[perform_attestation_pb2___PerformAttestationResponse] = None,
        check_sdcard : typing___Optional[bitbox02_system_pb2___CheckSDCardResponse] = None,
        eth : typing___Optional[eth_pb2___ETHResponse] = None,
        ) -> None: ...
    @classmethod
    def FromString(cls, s: bytes) -> Response: ...
    def MergeFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    def CopyFrom(self, other_msg: google___protobuf___message___Message) -> None: ...
    if sys.version_info >= (3,):
        def HasField(self, field_name: typing_extensions___Literal[u"btc_sign_next",u"check_backup",u"check_sdcard",u"device_info",u"error",u"eth",u"list_backups",u"perform_attestation",u"pub",u"random_number",u"response",u"success"]) -> bool: ...
        def ClearField(self, field_name: typing_extensions___Literal[u"btc_sign_next",u"check_backup",u"check_sdcard",u"device_info",u"error",u"eth",u"list_backups",u"perform_attestation",u"pub",u"random_number",u"response",u"success"]) -> None: ...
    else:
        def HasField(self, field_name: typing_extensions___Literal[u"btc_sign_next",b"btc_sign_next",u"check_backup",b"check_backup",u"check_sdcard",b"check_sdcard",u"device_info",b"device_info",u"error",b"error",u"eth",b"eth",u"list_backups",b"list_backups",u"perform_attestation",b"perform_attestation",u"pub",b"pub",u"random_number",b"random_number",u"response",b"response",u"success",b"success"]) -> bool: ...
        def ClearField(self, field_name: typing_extensions___Literal[u"btc_sign_next",b"btc_sign_next",u"check_backup",b"check_backup",u"check_sdcard",b"check_sdcard",u"device_info",b"device_info",u"error",b"error",u"eth",b"eth",u"list_backups",b"list_backups",u"perform_attestation",b"perform_attestation",u"pub",b"pub",u"random_number",b"random_number",u"response",b"response",u"success",b"success"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions___Literal[u"response",b"response"]) -> typing_extensions___Literal["success","error","random_number","device_info","pub","btc_sign_next","list_backups","check_backup","perform_attestation","check_sdcard","eth"]: ...
