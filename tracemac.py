# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2022
import argparse
import time
from getpass import getpass
from netmiko import ConnectHandler
from typing import Any, Dict


class TraceUtils:
    @staticmethod
    def handle_portchan(device_connection_handle: Any, chan_id: str) -> str:
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
                    return TraceUtils.expand_portname(chan["interfaces"][0])
        return None

    @staticmethod
    def shrink_portname(portname: str) -> str:
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

    @staticmethod
    def expand_portname(portname: str) -> str:
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

    @staticmethod
    def fmac_cisco(mac: str) -> str:
        """
        Given a string representation of a MAC address in a common format, return it in Cisco format.
        """
        # Fast-like remove ":", ".", and "-" in one go
        mac = mac.translate({58: None, 45: None, 46: None}).lower()
        if len(mac) != 12:
            return None
        return f"{mac[:4]}.{mac[4:8]}.{mac[8:12]}"


def trace_macs(connection_details: Dict[str, str], host: str, mac_list: str):
    connection_details.update({"host": host})
    result = []
    with ConnectHandler(**connection_details) as conn:
        switch_hostname = conn.find_prompt()[:-1]
        mac_to_local_iface = {}
        for mac in mac_list:
            mac_table = conn.send_command(
                f"sh mac address-table address {mac}", use_textfsm=True
            )
            if not isinstance(mac_table, list):
                result.append(["err", mac, "Unknown", switch_hostname])
                break
            iface = TraceUtils.expand_portname(mac_table[0]["destination_port".strip()])
            if "Port-channel" in iface:
                iface = TraceUtils.handle_portchan(conn, iface)
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


def interactive(
    connection_details: Dict[str, str],
    starting_node: str,
    inventory_path: str,
    oneshot_mac: str,
):
    if inventory_path and oneshot_mac:
        raise NotImplementedError("Both inventory and oneshot specified")
    if not inventory_path and not oneshot_mac:
        raise ValueError("No inventory or oneshot mac supplied")
    current_node = starting_node
    initial_node_to_mac = {}
    if inventory_path:
        with open(inventory_path) as mac_f:
            for mac in mac_f:
                # FIXME: both of these cases silently swallow fmac_cisco() -> None
                if current_node in initial_node_to_mac:
                    initial_node_to_mac[current_node].append(
                        TraceUtils.fmac_cisco(mac.strip())
                    )
                else:
                    initial_node_to_mac.update(
                        {
                            current_node: [
                                TraceUtils.fmac_cisco(mac.strip()),
                            ]
                        }
                    )
    else:
        initial_node_to_mac = {
            starting_node: [
                oneshot_mac,
            ]
        }
    next_node_to_mac = {}
    print("result,mac,switch,interface")
    while len(initial_node_to_mac) != 0:
        for current_node, mac_list in initial_node_to_mac.items():
            status = None
            interface = None
            for status, mac, interface, current_node in trace_macs(
                connection_details.copy(), current_node, mac_list
            ):
                if status == "edge":
                    print(
                        f"ok,{mac},{current_node},{TraceUtils.shrink_portname(interface)}"
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
                    print(
                        f"err-unknown,{mac},{current_node},{TraceUtils.shrink_portname(interface)}"
                    )
        initial_node_to_mac = next_node_to_mac
        next_node_to_mac = {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Bulk trace MAC addresses through a L2 network of Cisco switches"
    )
    parser.add_argument("--username", help="User to login to network devices")
    parser.add_argument(
        "--insecure-password",
        help="Insecurely load password from the command line. Do not use.",
        action="store_true",
    )
    parser.add_argument("--root-node", help="Specify node to start tracing from.")
    operating_mode = parser.add_mutually_exclusive_group(required=True)
    operating_mode.add_argument(
        "--inventory", help="File containing MAC addresses to trace, one per line."
    )
    operating_mode.add_argument("--one-shot", help="Trace a single MAC.")
    args = parser.parse_args()
    connection_details: Dict[str, str] = {
        "device_type": "cisco_ios",
        "host": args.root_node,
        "username": args.username,
    }
    if args.insecure_password:
        with open(args.insecure_password, "r") as insecure:
            password = insecure.readline().strip()
    else:
        password = getpass("Enter password for login: ")
    connection_details.update({"password": password, "secret": password})
    start_time = time.perf_counter()
    interactive(connection_details, args.root_node, args.inventory, args.one_shot)
    print(f"Elapsed: {time.perf_counter() - start_time}")