# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import re
import dataclasses
import traceback
from enum import Flag, auto
from typing import Tuple, List

__cdp_entry_delimiter__ = "-------------------------"
__cdp_device_id__ = re.compile(r"Device ID: (.*?)\n", re.DOTALL)
__cdp_ip_addr__ = re.compile(r"IP address: (.*?)\n", re.DOTALL)
__cdp_platform__ = re.compile(r"Platform: (.*?),", re.DOTALL)
__cdp_capabilities__ = re.compile(r"Capabilities: (.*?)\n", re.DOTALL)
__cdp_local_int__ = re.compile(r"Interface: (.*?),", re.DOTALL)
__cdp_remote_int__ = re.compile(r"Port ID \(outgoing port\): (.*?)\n", re.DOTALL)
__cdp_holdtime__ = re.compile(r"Holdtime : (.*?)\n", re.DOTALL)
__cdp_version__ = re.compile(r"Version :(.*?)advertisement version:", re.DOTALL | re.MULTILINE)
__cdp_advertisement_ver__ = re.compile(r"advertisement version: (.*?)\n", re.DOTALL)
__cdp_vtp_domain__ = re.compile(r"VTP Management Domain: (.*?)\n")
__cdp_native_vlan__ = re.compile(r"Native VLAN: (.*?)\n", re.DOTALL)
__cdp_duplex__ = re.compile(r"Duplex: (.*?)\n", re.DOTALL)
__cdp_unidirectional_mode__ = re.compile(r"Unidirectional Mode: (.*?)\n", re.DOTALL)


class CDPCapabilities(Flag):
    NONE = auto()
    ROUTER = auto()
    TRANS_BRIDGE = auto()
    SOURCE_ROUTE_BRIDGE = auto()
    SWITCH = auto()
    HOST = auto()
    IGMP = auto()
    REPEATER = auto()
    PHONE = auto()
    REMOTE = auto()
    CVTA = auto()
    TWO_PORT_MAC_RELAY = auto()


__cdp_str_to_capability__ = {
    "Switch": CDPCapabilities.SWITCH,
    "IGMP": CDPCapabilities.IGMP,
    "Router": CDPCapabilities.ROUTER,
    "Source-Route-Bridge": CDPCapabilities.SOURCE_ROUTE_BRIDGE,
    "Host": CDPCapabilities.HOST,
    "Trans-Bridge": CDPCapabilities.TRANS_BRIDGE,
    "Phone": CDPCapabilities.PHONE,
    "Two-port": CDPCapabilities.TWO_PORT_MAC_RELAY,  # shhhh
    "Mac": CDPCapabilities.TWO_PORT_MAC_RELAY,
    "Relay": CDPCapabilities.TWO_PORT_MAC_RELAY,
}


@dataclasses.dataclass(order=True, frozen=True)
class CDPTableEntry:
    device_id: str
    platform: str
    local_interface: str
    remote_interface: str
    holdtime: str
    version: str
    advertisement_version: str
    vtp_domain: str
    native_vlan: str
    duplex: str
    unidirectional_mode: str
    capabilities: CDPCapabilities
    entry_addresses: Tuple[str]
    mgmt_addresses: Tuple[str]

    def __post_init__(self):
        if not isinstance(self.capabilities, CDPCapabilities):
            raise TypeError("CDPTableEntry.capabilities is not a CDPCapabilities type")
        if not isinstance(self.entry_addresses, tuple):
            raise TypeError("CDPTableEntry.entry_addresses is not a tuple type")
        if not isinstance(self.mgmt_addresses, tuple):
            raise TypeError("CDPTableEntry.mgmt_addresses is not a tuple type")
        for idx, maybe_entry_addr in enumerate(self.entry_addresses):
            if not isinstance(maybe_entry_addr, str):
                raise TypeError(f"CDPTableEntry.entry_addreses[{idx}] is not a str type")
        for idx, maybe_mgmt_addr in enumerate(self.mgmt_addresses):
            if not isinstance(maybe_mgmt_addr, str):
                raise TypeError(f"CDPTableEntry.mgmt_addreses[{idx}] is not a str type")


def parse_single_cdp_entry(entry: str) -> CDPTableEntry:
    if match := __cdp_device_id__.search(entry):
        device_id = match.group(1)
    else:
        raise RuntimeError("No device ID")
    # The "IP Address" match will find both entry addresses and management address, they will probably be equal in our cases
    # But we want to do it right just in case.
    # Find the Platform next, that will give us a maximum index for entry address (which comes first)
    # And IP address match before the index is an entry address, any after is a management address.
    if match := __cdp_platform__.search(entry):
        platform = match.group(1)
        platform_idx = match.start()
    else:
        raise RuntimeError("No CDP Platform")
    entry_addrs = list()
    mgmt_addrs = list()
    for ip_match in __cdp_ip_addr__.finditer(entry):
        if ip_match.start() < platform_idx:
            entry_addrs.append(ip_match.group(1))
        else:
            mgmt_addrs.append(ip_match.group(1))
    capabilities = CDPCapabilities(CDPCapabilities.NONE)
    if match := __cdp_capabilities__.search(entry):
        for capability in match.group(1).split():
            try:
                capabilities |= __cdp_str_to_capability__[capability]
            except KeyError:
                pass
        capabilities ^= CDPCapabilities.NONE
    if match := __cdp_local_int__.search(entry):
        local_interface = match.group(1)
    else:
        raise RuntimeError("No local interface")
    if match := __cdp_remote_int__.search(entry):
        remote_interface = match.group(1)
    else:
        raise RuntimeError("No remote interface")
    if match := __cdp_holdtime__.search(entry):
        holdtime = match.group(1)
    else:
        holdtime = "Unknown"
    if match := __cdp_version__.search(entry):
        version = match.group(1)
    else:
        raise RuntimeError("No version string")
    if match := __cdp_advertisement_ver__.search(entry):
        advertisement_ver = match.group(1)
    else:
        advertisement_ver = "Unknown"
    if match := __cdp_vtp_domain__.search(entry):
        vtp_domain = match.group(1)
    else:
        vtp_domain = "Unknown"
    if match := __cdp_native_vlan__.search(entry):
        native_vlan = match.group(1)
    else:
        native_vlan = "Unknown"
    if match := __cdp_duplex__.search(entry):
        duplex = match.group(1)
    else:
        duplex = "Unknown"
    if match := __cdp_unidirectional_mode__.search(entry):
        unidirectional_mode = match.group(1)
    else:
        unidirectional_mode = "Unknown"
    return CDPTableEntry(
        device_id,
        platform,
        local_interface,
        remote_interface,
        holdtime,
        version,
        advertisement_ver,
        vtp_domain,
        native_vlan,
        duplex,
        unidirectional_mode,
        capabilities,
        tuple(entry_addrs),
        tuple(mgmt_addrs),
    )


def parse_full_cdp_table(cdp_table: str) -> List[CDPTableEntry]:
    all_entries = list()
    cdp_table_lines = cdp_table.splitlines()
    table_maxlen = len(cdp_table_lines) - 1  # Zero index
    current_entry = list()
    in_entry = False
    for idx, line in enumerate(cdp_table_lines):
        if not in_entry:
            if __cdp_entry_delimiter__ in line:
                current_entry = list()
                in_entry = True
            continue
        if __cdp_entry_delimiter__ in line or idx == table_maxlen:
            try:
                entry_result = parse_single_cdp_entry("\n".join(current_entry))
                if isinstance(entry_result, CDPTableEntry):
                    all_entries.append(entry_result)
            except Exception as e:
                traceback.print_exc()
            current_entry = list()
        current_entry.append(line)
    return all_entries
