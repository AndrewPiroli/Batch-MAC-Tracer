# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2022
import argparse
import time
import tracemac_parser
from getpass import getpass
from netmiko import ConnectHandler
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

etherchannel_cache_current_device_id: str = ""
etherchannel_parse_cache: Dict[str, List[tracemac_parser.EtherChannelEntry]] = {}


def handle_portchan(
    device_id: str, etherchannel_summary: str, chan_id: str
) -> Optional[str]:
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
        parsed_etherchannel = tracemac_parser.parse_etherchannel_summary(
            etherchannel_summary
        )
        etherchannel_parse_cache.update({etherchannel_summary: parsed_etherchannel})
    if len(parsed_etherchannel):
        for chan in parsed_etherchannel:
            if chan.group == chan_id:
                if len(chan.ports):
                    found = False
                    for port in chan.ports:
                        if tracemac_parser.EtherChannelStates.BUNDLED in port.state:
                            found = port
                            break
                    else:
                        return None
                    return expand_portname(found.name)
                else:
                    return None
    return None


def shrink_portname(portname: str) -> Optional[str]:
    """
    Abbreviate a port prefix.
    FastEthernet -> Fa
    GigabitEthernet -> Gi
    TenGigabitEthernet -> Te
    """
    if not portname:
        return None
    return (
        portname.replace("TenGigabit", "Te", 1)
        .replace("Ethernet", "", 1)
        .replace("Fast", "Fa", 1)
        .replace("Gigabit", "Gi", 1)
    )


def expand_portname(portname: str) -> Optional[str]:
    """
    Given a port name with a abbreviated prefix, expand the prefix.
    Fa -> FastEthernet
    Gi -> GigabitEthernet
    Te -> TenGigabitEthernet
    """
    if not portname:
        return None
    if portname.startswith("Fa") and not portname.startswith("FastEthernet"):
        return f"FastEthernet{portname[2:]}"
    if portname.startswith("Gi") and not portname.startswith("GigabitEthernet"):
        return f"GigabitEthernet{portname[2:]}"
    if portname.startswith("Te") and not portname.startswith("TenGigabitEthernet"):
        return f"TenGigabitEthernet{portname[2:]}"
    return portname


def fmac_cisco(mac: str) -> Optional[str]:
    """
    Given a string representation of a MAC address in a common format, return it in Cisco format.
    """
    # Fast-like remove ":", ".", and "-" in one go
    mac = mac.translate({58: None, 45: None, 46: None}).lower()
    if len(mac) != 12:
        return None
    return f"{mac[:4]}.{mac[4:8]}.{mac[8:12]}"


def trace_macs(
    connection_details: Dict[str, str], mac_list: List[str]
) -> List[List[str]]:
    result = []
    with ConnectHandler(**connection_details) as conn:
        switch_hostname = conn.find_prompt()[:-1]
        mac_table = conn.send_command("sh mac address-table")
        full_cdp_table = conn.send_command("show cdp neighbor detail")
        full_etherchannel_summary = conn.send_command("show etherchannel summary")
    mac_to_local_iface = {}
    parsed_mac_table = tracemac_parser.parse_full_mac_addr_table(mac_table)
    parsed_cdp_table = tracemac_parser.parse_full_cdp_table(full_cdp_table)
    for mac in mac_list:
        if not len(parsed_mac_table):
            result.append(["err", mac, "Failed to parse mac table", switch_hostname])
            break
        found = False
        for mac_entry in parsed_mac_table:
            if not isinstance(mac_entry, tracemac_parser.MACTableEntry):
                continue
            if mac_entry.mac_address == mac:
                found = mac_entry
                break
        if not found:
            result.append(
                ["err", mac, "MAC not found in mac address table", switch_hostname]
            )
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
        if tracemac_parser.CDPCapabilities.SWITCH in our_cdp.capabilities:
            result.append(["recurse", mac, iface, cdp_entry.mgmt_addresses[0]])
        else:
            result.append(["edge", mac, iface, switch_hostname])
    return result


def start_mac_trace(
    connection_details: Dict[str, str],
    inventory_path: Union[Path, str],
    oneshot_mac: str,
    progress_callback: Optional[Callable[[str, str, str, str], None]],
) -> List[str]:
    """
    Start the mac tracing.

    connection_details (dict): for netmiko connenctions
        host (str): the device to start tracing from.
        device_type (str): a device type supported by netmiko and this program - currently cisco_ios is the only supported
        username (str): username to login to each device
        password (str): password to login to each device
        secret (str): secret to enable to each device, if required.
    inventory_path (pathlib.Path | str): path to a text file with one MAC address per line (most common formats accepted). Mutually exclusive with oneshot_mac
    oneshot_mac (str): a single MAC address to find. Mutually exclusive with inventory_path
    progress_callback (optional callable accepting 4 str arguments): Called every time a trace is finished
        status: will be "ok" or "err-unknown"
        mac: the MAC address in question
        node: the traced node, or if error, last node where the trace stopped
        interface: the traced interface, or if error, last interface seen

    Returns a list of strings, comma delimited. Suitable to dump directly to CSV
    """
    if inventory_path and oneshot_mac:
        raise NotImplementedError("Both inventory and oneshot specified")
    if not inventory_path and not oneshot_mac:
        raise ValueError("No inventory or oneshot mac supplied")
    if not callable(progress_callback):
        # No callback, assign a lambda that will swallow anything.
        progress_callback: Callable[[str, str, str, str], None] = lambda *args: None
    current_node = str(connection_details["host"])
    initial_node_to_mac: Dict[str, List[str]] = {}
    if inventory_path:
        with open(inventory_path) as mac_f:
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
    else:
        formatted_oneshot_mac = fmac_cisco(oneshot_mac.strip())
        if formatted_oneshot_mac:
            initial_node_to_mac = {
                str(connection_details["host"]): [
                    formatted_oneshot_mac,
                ]
            }
    next_node_to_mac: Dict[str, List[str]] = {}
    results = list()
    while len(initial_node_to_mac) != 0:
        for current_node, mac_list in initial_node_to_mac.items():
            status = None
            interface = None
            next_connection_deetails = connection_details
            next_connection_deetails.update({"host": current_node})
            for status, mac, interface, current_node in trace_macs(
                next_connection_deetails, mac_list
            ):
                if status == "edge":
                    result_interface = shrink_portname(interface)
                    progress_callback("ok", mac, current_node, result_interface)
                    results.append(f"ok,{mac},{current_node},{result_interface}")
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
                    progress_callback(
                        "err-unknown", mac, current_node, result_interface
                    )
                    results.append(
                        f"err-unknown,{mac},{current_node},{result_interface}"
                    )
        initial_node_to_mac = next_node_to_mac
        next_node_to_mac = {}
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Bulk trace MAC addresses through a L2 network of Cisco switches"
    )
    parser.add_argument(
        "--username", help="User to login to network devices", required=True
    )
    parser.add_argument(
        "--root-node", help="Specify node to start tracing from.", required=True
    )
    parser.add_argument(
        "--insecure-password",
        help="Insecurely load password from the first line of a text file. Do not use.",
        action="store_true",
    )
    operating_mode = parser.add_mutually_exclusive_group(required=True)
    operating_mode.add_argument(
        "--inventory", help="File containing MAC addresses to trace, one per line."
    )
    operating_mode.add_argument("--one-shot", help="Trace a single MAC.")
    args = parser.parse_args()
    if args.insecure_password:
        with open(args.insecure_password, "r") as insecure:
            password = insecure.readline().strip()
    else:
        password = getpass("Enter password for login: ")
    connection_details: Dict[str, str] = {
        "device_type": "cisco_ios",
        "username": args.username,
    }
    connection_details.update(
        {"host": args.root_node, "password": password, "secret": password}
    )
    interactive_callback = lambda status, mac, node, interface: print(
        f"{status},{mac},{node},{interface}"
    )
    print("result,mac,switch,interface")
    start_time = time.perf_counter()
    start_mac_trace(
        connection_details, args.inventory, args.one_shot, interactive_callback
    )
    print(f"Elapsed: {time.perf_counter() - start_time}")
