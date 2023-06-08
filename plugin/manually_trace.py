# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

from getpass import getpass
from netmiko import ConnectHandler
from pathlib import Path
from abc import abstractmethod
from typing import Any, Callable, Dict, List, Optional, Union

from . import Plugin, PluginArgs, PluginArgDescription
from core import *
from core.etherchannel import EtherChannelEntry, EtherChannelStates, parse_etherchannel_summary
from core.cdp import CDPCapabilities, parse_full_cdp_table
from core.mactable import MACTableEntry, parse_full_mac_addr_table

etherchannel_cache_current_device_id: str = ""
etherchannel_parse_cache: Dict[str, List[EtherChannelEntry]] = {}


def handle_portchan(device_id: str, etherchannel_summary: str, chan_id: str) -> Optional[str]:
    """
    Takes a etherchannel table and parses it to find an appropriate physical link to follow
    """
    global etherchannel_cache_current_device_id
    if "Po" in chan_id:
        chan_id = int("".join([char for char in chan_id if char.isnumeric()]))
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
            if chan.group == chan_id:
                if len(chan.ports):
                    found = False
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


def trace_macs(connection_details: Dict[str, str], mac_list: List[str]) -> List[List[str]]:
    result = []
    with ConnectHandler(**connection_details) as conn:
        switch_hostname = conn.find_prompt()[:-1]
        mac_table = conn.send_command("sh mac address-table")
        full_cdp_table = conn.send_command("show cdp neighbor detail")
        full_etherchannel_summary = conn.send_command("show etherchannel summary")
    mac_to_local_iface = {}
    parsed_mac_table = parse_full_mac_addr_table(mac_table)
    parsed_cdp_table = parse_full_cdp_table(full_cdp_table)
    for mac in mac_list:
        if not len(parsed_mac_table):
            result.append(["err", mac, "Failed to parse mac table", switch_hostname])
            break
        found = False
        for mac_entry in parsed_mac_table:
            if not isinstance(mac_entry, MACTableEntry):
                continue
            if mac_entry.mac_address == mac:
                found = mac_entry
                break
        if not found:
            result.append(["err", mac, "MAC not found in mac address table", switch_hostname])
            continue
        iface = expand_portname(found.port.strip())
        if not iface:
            continue
        if "Port-channel" in iface:
            iface = handle_portchan(switch_hostname, full_etherchannel_summary, iface)
        mac_to_local_iface.update({mac: iface})
    for mac, iface in mac_to_local_iface.items():
        our_cdp = None
        for cdp_entry in parsed_cdp_table:
            if cdp_entry.local_interface == iface:
                our_cdp = cdp_entry
                break
        else:
            result.append(["edge", mac, iface, switch_hostname])
            continue
        if CDPCapabilities.SWITCH in our_cdp.capabilities:
            result.append(["recurse", mac, iface, cdp_entry.mgmt_addresses[0]])
        else:
            result.append(["edge", mac, iface, switch_hostname])
    return result


def start_mac_trace(
    connection_details: Dict[str, str],
    mac_file_or_single: Union[Path, str],
    progress_callback: Optional[Callable[[TraceResult], None]],
) -> List[TraceResult]:
    if not callable(progress_callback):
        # No callback, assign a lambda that will swallow anything.
        progress_callback: Callable[[TraceResult], None] = lambda *args: None
    current_node = str(connection_details["host"])
    initial_node_to_mac: Dict[str, List[str]] = {}
    try:
        with open(mac_file_or_single) as mac_f:
            for mac in mac_f:
                formatted_mac = fmac_cisco(mac.strip())
                if not formatted_mac:
                    continue
                if current_node in initial_node_to_mac:
                    initial_node_to_mac[current_node].append(formatted_mac)
                else:
                    initial_node_to_mac.update(
                        {
                            current_node: [
                                formatted_mac,
                            ]
                        }
                    )
    except FileNotFoundError:
        formatted_mac = fmac_cisco(mac_file_or_single.strip())
        if formatted_mac is None:
            raise RuntimeError("MAC is not a path and is not a valid MAC.")
    next_node_to_mac: Dict[str, List[str]] = {}
    results = list()
    while len(initial_node_to_mac) != 0:
        for current_node, mac_list in initial_node_to_mac.items():
            status = None
            interface = None
            next_connection_deetails = connection_details
            next_connection_deetails.update({"host": current_node})
            for status, mac, interface, current_node in trace_macs(next_connection_deetails, mac_list):
                if status == "edge":
                    result_interface = shrink_portname(interface)
                    res = TraceResult("ok", mac, current_node, result_interface)
                    progress_callback(res)
                    results.append(res)
                elif status == "recurse":
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
                else:
                    result_interface = shrink_portname(interface)
                    res = TraceResult("err-unknown", mac, current_node, result_interface)
                    progress_callback(res)
                    results.append(res)
        initial_node_to_mac = next_node_to_mac
        next_node_to_mac = {}
    return results


class ManuallyTracePlugin(Plugin):
    def start(self, args: PluginArgs) -> List[TraceResult]:
        args.details["netmiko"].update(
            {
                "device_type": "cisco_ios",
                "password": args.details["password"],
            }
        )
        start_mac_trace(args.details["netmiko"], args.details["macs"], args.progress_callback)

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
