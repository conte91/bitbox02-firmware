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
"""BitBoxBase"""

from bitbox02.devices import parse_device_version, DeviceInfo
from typing import Optional, Callable
import communication

class BitBoxBase(communication.BitBoxAPIExchanger, communication.BitBoxCommonAPI):
    """Class to communicate with a BitBox02"""

    # pylint: disable=too-many-public-methods

    def __init__(
        self,
        device: communication.TransportLayer,
        device_info: DeviceInfo,
        show_pairing_callback: Callable[[str], None],
        attestation_check_callback: Optional[Callable[[bool], None]] = None,
    ):
        communication.BitBoxAPIExchanger.__init__(self, device, device_info, show_pairing_callback, attestation_check_callback)
        communication.BitBoxCommonAPI.__init__(self)

