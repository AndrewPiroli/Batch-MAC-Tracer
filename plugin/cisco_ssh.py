# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023
try:
    from netmiko import ConnectHandler  # type: ignore
except ImportError:
    pass
from typing import Callable, Dict, List, Optional
from enum import Enum, auto

from . import Plugin, PluginArgs, PluginArgDescription
from core import *
from core.etherchannel import (
    EtherChannelEntry,
    EtherChannelStates,
    EtherChannelPort,
    parse_etherchannel_summary,
)
from core.cdp import CDPCapabilities, parse_full_cdp_table
from core.mactable import MACTableEntry, parse_full_mac_addr_table

etherchannel_cache_current_device_id: str = ""
etherchannel_parse_cache: Dict[str, List[EtherChannelEntry]] = {}


class Status(Enum):
    ERROR = auto()
    RECURSE = auto()
    EDGE = auto()


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class _MACHelper:
    mac: str
    original_style: MACFormatStyle

    @classmethod
    def from_mac(cls, mac: str):
        return cls(mac=CISCO_STYLE.to_style(mac), original_style=MACFormatStyle.recognize_style(mac))

    def __repr__(self) -> str:
        return self.mac.lower()

    def __str__(self) -> str:
        return self.original_style.to_style(self.mac).__str__()

    def mac_eq(self, other: "_MACHelper") -> bool:
        return self.mac.lower() == other.mac.lower()


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class TraceProgress:
    status: Status
    mac: _MACHelper
    iface: str
    device: str


def handle_portchan(device_id: str, etherchannel_summary: str, chan_id: str) -> Optional[str]:
    """
    Takes a etherchannel table and parses it to find an appropriate physical link to follow
    """
    global etherchannel_cache_current_device_id
    if "Po" in chan_id:
        chan_id = "".join([char for char in chan_id if char.isnumeric()])
    else:
        return None
    try:
        if device_id == etherchannel_cache_current_device_id:
            parsed_etherchannel = etherchannel_parse_cache[etherchannel_summary]
        else:
            etherchannel_parse_cache.clear()
            etherchannel_cache_current_device_id = device_id
            raise KeyError
    except KeyError:
        parsed_etherchannel = parse_etherchannel_summary(etherchannel_summary)
        etherchannel_parse_cache.update({etherchannel_summary: parsed_etherchannel})
    if len(parsed_etherchannel):
        for chan in parsed_etherchannel:
            if chan.group == int(chan_id):
                if len(chan.ports):
                    found: Optional[EtherChannelPort] = None
                    for port in chan.ports:
                        if EtherChannelStates.BUNDLED in port.state:
                            found = port
                            break
                    else:
                        return None
                    return expand_portname(found.name)
                else:
                    return None
    return None


def trace_macs(connection_details: Dict[str, str], mac_list: List[_MACHelper]) -> List[TraceProgress]:
    result = []
    with ConnectHandler(**connection_details) as conn:  # pyright: ignore reportUnboundVariable
        switch_hostname = str(conn.find_prompt()[:-1])
        mac_table = str(conn.send_command("sh mac address-table"))
        full_cdp_table = str(conn.send_command("show cdp neighbor detail"))
        full_etherchannel_summary = str(conn.send_command("show etherchannel summary"))
    mac_to_local_iface = {}
    parsed_mac_table = parse_full_mac_addr_table(mac_table)
    parsed_cdp_table = parse_full_cdp_table(full_cdp_table)
    for mac in mac_list:
        if not len(parsed_mac_table):
            result.append(TraceProgress(Status.ERROR, mac, "Failed to parse mac table", switch_hostname))
            break
        found: Optional[MACTableEntry] = None
        for mac_entry in parsed_mac_table:
            if not isinstance(mac_entry, MACTableEntry):
                continue
            current_mac_addr = _MACHelper.from_mac(mac_entry.mac_address)
            if current_mac_addr.mac_eq(mac):
                found = mac_entry
                break
        if not found:
            result.append(
                TraceProgress(Status.ERROR, mac, "MAC not found in mac address table", switch_hostname)
            )
            continue
        iface = expand_portname(found.port.strip())
        if not iface:
            continue
        if "Port-channel" in iface:
            iface = handle_portchan(switch_hostname, full_etherchannel_summary, iface)
            if not iface:
                continue
        mac_to_local_iface.update({mac: iface})
    for mac, iface in mac_to_local_iface.items():
        our_cdp = None
        for cdp_entry in parsed_cdp_table:
            if cdp_entry.local_interface == iface:
                our_cdp = cdp_entry
                break
        else:
            result.append(TraceProgress(Status.EDGE, mac, iface, switch_hostname))
            continue
        if CDPCapabilities.SWITCH in our_cdp.capabilities:
            result.append(TraceProgress(Status.RECURSE, mac, iface, cdp_entry.mgmt_addresses[0]))
        else:
            result.append(TraceProgress(Status.EDGE, mac, iface, switch_hostname))
    return result


def start_mac_trace(
    connection_details: Dict[str, str],
    macs: List[_MACHelper],
    progress_callback: Optional[Callable[[TraceResult], None]],
) -> List[TraceResult]:
    if not callable(progress_callback):
        # No callback, assign a lambda that will swallow anything.
        progress_callback = lambda *args: None
    current_node = str(connection_details["host"])
    initial_node_to_mac: Dict[str, List[_MACHelper]] = {connection_details["host"]: macs}
    next_node_to_mac: Dict[str, List[_MACHelper]] = {}
    results = list()
    while len(initial_node_to_mac) != 0:
        for current_node, mac_list in initial_node_to_mac.items():
            status = None
            interface = None
            next_connection_deetails = connection_details
            next_connection_deetails.update({"host": current_node})
            for tmr in trace_macs(next_connection_deetails, mac_list):
                status = tmr.status
                mac = tmr.mac
                interface = tmr.iface
                current_node = tmr.device
                if status == Status.EDGE:
                    result_interface = str(shrink_portname(interface))
                    res = TraceResult("ok", str(mac), current_node, result_interface)
                    if callable(progress_callback):
                        progress_callback(res)
                    results.append(res)
                elif status == Status.RECURSE:
                    if current_node in next_node_to_mac:
                        next_node_to_mac[current_node].append(mac)
                    else:
                        next_node_to_mac.update(
                            {
                                current_node: [
                                    mac,
                                ]
                            }
                        )
                else:  # status == Status.ERROR
                    result_interface = str(shrink_portname(interface))
                    res = TraceResult("err-unknown", str(mac), current_node, result_interface)
                    if callable(progress_callback):
                        progress_callback(res)
                    results.append(res)
        initial_node_to_mac = next_node_to_mac
        next_node_to_mac = {}
    return results


class CiscoSSHPlugin(Plugin):
    def start(self, args: PluginArgs) -> List[TraceResult]:
        macs = [_MACHelper.from_mac(m) for m in resolve_macs(args.details["macs"])]  # type: ignore
        if macs is None:
            eprint("Failed to resolve MACs")
            return []
        args.details["netmiko"].update(
            {
                "device_type": "cisco_ios",
                "password": args.details["password"],
            }
        )
        return start_mac_trace(args.details["netmiko"], macs, args.progress_callback)

    @staticmethod
    def args() -> List[PluginArgDescription]:
        return [
            PluginArgDescription(
                name="netmiko", description="Netmiko connection details", can_fill_interactively=False
            ),
            PluginArgDescription(
                name="password",
                description="Password for netmiko connection",
                can_fill_interactively=True,
                secret=True,
            ),
            PluginArgDescription(
                name="macs",
                description="Path to file containing MACs to trace OR a single MAC address",
                can_fill_interactively=True,
            ),
        ]
