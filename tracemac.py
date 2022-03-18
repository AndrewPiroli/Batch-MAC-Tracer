# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2022
import argparse
import time
from getpass import getpass
from netmiko import ConnectHandler
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def handle_portchan(device_connection_handle: Any, chan_id: str) -> Optional[str]:
    """
    Given a port channel and a netmiko connection reference, find the first link in the port channel.
    """
    if "Po" in chan_id:
        chan_id = "".join([char for char in chan_id if char.isnumeric()])
    all_chans = device_connection_handle.send_command(
        "show etherchannel summary", use_textfsm=True
    )
    if isinstance(all_chans, list):
        for chan in all_chans:
            if chan["group"] == chan_id:
                return expand_portname(chan["interfaces"][0])
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
        portname.replace("Ethernet", "", 1)
        .replace("Fast", "Fa", 1)
        .replace("Gigabit", "Gi", 1)
        .replace("TenGigabit", "Te", 1)
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
        mac_to_local_iface = {}
        for mac in mac_list:
            # It is not intelligent to ask the switch for a partial mac table many times
            # A better solution would be to ask the switch for it's entire mac table once
            # But textfsm had some problems with that last I checked
            # Parsing the mac table ourselves is a TODO for sure.
            mac_table = conn.send_command(
                f"sh mac address-table address {mac}", use_textfsm=True
            )
            if not isinstance(mac_table, list):
                result.append(["err", mac, "Unknown", switch_hostname])
                break
            iface = expand_portname(mac_table[0]["destination_port".strip()])
            if not iface:
                continue
            if "Port-channel" in iface:
                iface = handle_portchan(conn, iface)
            mac_to_local_iface.update({mac: iface})
        full_cdp_table = conn.send_command(f"sh cdp neighbor detail", use_textfsm=True)
    for mac, iface in mac_to_local_iface.items():
        our_cdp = None
        for cdp_entry in full_cdp_table:
            if cdp_entry["local_port"] == iface:
                our_cdp = cdp_entry
                break
        else:
            result.append(["edge", mac, iface, switch_hostname])
            continue
        if "Switch" in our_cdp["capabilities"]:
            result.append(["recurse", mac, iface, cdp_entry["management_ip"]])
        else:
            result.append(["edge", mac, iface, switch_hostname])
    return result


def start_mac_trace(
    connection_details: Dict[str, str],
    inventory_path: Union[Path, str],
    oneshot_mac: str,
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

    Returns a list of strings, comma delimited, with a header. Suitable to dump directly to CSV
    """
    if inventory_path and oneshot_mac:
        raise NotImplementedError("Both inventory and oneshot specified")
    if not inventory_path and not oneshot_mac:
        raise ValueError("No inventory or oneshot mac supplied")
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
    results.append("result,mac,switch,interface")
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
                    results.append(
                        f"ok,{mac},{current_node},{shrink_portname(interface)}"
                    )
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
                    results.append(
                        f"err-unknown,{mac},{current_node},{shrink_portname(interface)}"
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
    start_time = time.perf_counter()
    for line in start_mac_trace(connection_details, args.inventory, args.one_shot):
        print(line)
    print(f"Elapsed: {time.perf_counter() - start_time}")
