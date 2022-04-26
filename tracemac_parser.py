import dataclasses
import re
import traceback
from enum import auto, Flag
from typing import List, Tuple

__cdp_entry_delimiter__ = "-------------------------"
__cdp_device_id__ = re.compile(r"Device ID: (.*?)(\r|\n|\r\n)", re.DOTALL)
__cdp_ip_addr__ = re.compile(r"IP address: (.*?)(\r|\n|\r\n)", re.DOTALL)
__cdp_platform__ = re.compile(r"Platform: (.*?),", re.DOTALL)
__cdp_capabilities__ = re.compile(r"Capabilities: (.*?)(\r|\n|\r\n)", re.DOTALL)
__cdp_local_int__ = re.compile(r"Interface: (.*?),", re.DOTALL)
__cdp_remote_int__ = re.compile(
    r"Port ID \(outgoing port\): (.*?)(\r|\n|\r\n)", re.DOTALL
)
__cdp_holdtime__ = re.compile(r"Holdtime : (.*?)(\r|\n|\r\n)", re.DOTALL)
__cdp_version__ = re.compile(
    r"Version :(.*?)advertisement version:", re.DOTALL | re.MULTILINE
)
__cdp_advertisement_ver__ = re.compile(
    r"advertisement version: (.*?)(\r|\n|\r\n)", re.DOTALL
)
__cdp_vtp_domain__ = re.compile(r"VTP Management Domain: (.*?)(\r|\n|\r\n)")
__cdp_native_vlan__ = re.compile(r"Native VLAN: (.*?)(\r|\n|\r\n)", re.DOTALL)
__cdp_duplex__ = re.compile(r"Duplex: (.*?)(\r|\n|\r\n)", re.DOTALL)
__cdp_unidirectional_mode__ = re.compile(
    r"Unidirectional Mode: (.*?)(\r|\n|\r\n)", re.DOTALL
)

__etherchannel_start__ = re.compile(
    r"--+--"
)  # This looks dumb, but it gets us in the ballpark
__etherchannel_strip_parens__ = re.compile(r"(.*?)(\(.*?\))", re.DOTALL)


@dataclasses.dataclass(order=True, frozen=True)
class MACTableEntry:
    vlan: int
    mac_address: str
    entry_type: str
    protocols: str
    port: str

    def __post_init__(self):
        if not isinstance(self.vlan, int):
            raise TypeError("vlan is not an integer type")
        if not 0 < self.vlan < 4096:
            raise ValueError("vlan out of range, 0 - 4096")
        if not isinstance(self.mac_address, str):
            raise TypeError("mac_address is not a str type")
        if not len(self.mac_address) == 14:
            raise ValueError(
                f"mac_address is poorly formatted: length: {len(self.mac_address)} expected: 14"
            )
        if not isinstance(self.entry_type, str):
            raise TypeError("entry_type is not a str type")
        if not self.entry_type.lower() in (
            "dynamic",
            "static",
            "system",
            "igmp",
        ):
            raise ValueError(
                "entry_type but be 'dynamic', 'static', 'system', or 'igmp'"
            )
        if not isinstance(self.protocols, str):
            raise TypeError("protocols must be a str type")
        if not isinstance(self.port, str):
            raise TypeError("port must be a str type")


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
                raise TypeError(
                    f"CDPTableEntry.entry_addreses[{idx}] is not a str type"
                )
        for idx, maybe_mgmt_addr in enumerate(self.mgmt_addresses):
            if not isinstance(maybe_mgmt_addr, str):
                raise TypeError(f"CDPTableEntry.mgmt_addreses[{idx}] is not a str type")


class EtherChannelStates(Flag):
    NONE = auto()
    DOWN = auto()
    BUNDLED = auto()
    STAND_ALONE = auto()
    SUSPENDED = auto()
    HOT_STANDBY = auto()
    LAYER3 = auto()
    LAYER2 = auto()
    IN_USE = auto()
    FAILED_TO_ALLOC = auto()
    NOT_IN_USE = auto()
    UNSUITABLE_FOR_BUNDLE = auto()
    WAITING_AGGREGATION = auto()
    DEFAULT_PORT = auto()


__etherchannel_str_to_state = {
    "D": EtherChannelStates.DOWN,
    "P": EtherChannelStates.BUNDLED,
    "I": EtherChannelStates.STAND_ALONE,
    "s": EtherChannelStates.SUSPENDED,
    "H": EtherChannelStates.HOT_STANDBY,
    "R": EtherChannelStates.LAYER3,
    "S": EtherChannelStates.LAYER2,
    "U": EtherChannelStates.IN_USE,
    "f": EtherChannelStates.FAILED_TO_ALLOC,
    "M": EtherChannelStates.NOT_IN_USE,
    "u": EtherChannelStates.UNSUITABLE_FOR_BUNDLE,
    "d": EtherChannelStates.DEFAULT_PORT,
}


@dataclasses.dataclass(order=True, frozen=True)
class EtherChannelPort:
    name: str
    state: EtherChannelStates

    def __post_init__(self):
        if not isinstance(self.state, EtherChannelStates):
            raise TypeError("EtherChannelPort.state is not a EtherChannelStates type")


@dataclasses.dataclass(order=True, frozen=True)
class EtherChannelEntry:
    group: int
    portchannel: str
    protocol: str
    ports: Tuple[EtherChannelPort]

    def __post_init__(self):
        if not isinstance(self.group, int):
            raise TypeError("EtherChannelEntry.group is not an integer type")
        if not isinstance(self.ports, tuple):
            raise TypeError("EtherChannelEntry.ports is not a tuple type")
        for idx, port in enumerate(self.ports):
            if not isinstance(port, EtherChannelPort):
                raise TypeError(
                    f"EtherChannelEntry.ports[{idx}] is not a EtherChannelPort type"
                )


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


def parse_full_mac_addr_table(mac_table: str) -> List[MACTableEntry]:
    ret = []
    for mac_table_line in mac_table.splitlines():
        if "Multicast Entries" in mac_table_line:
            break
        try:
            parsed_entry = mac_table_line.split()
            if (
                not 4 <= len(parsed_entry) <= 5
            ):  # Switches that "know" about non-ip protocols will have a 5th column, even if they don't support anything other than ip
                continue
            parsed_entry[0] = int(parsed_entry[0])
            if len(parsed_entry) == 4:
                parsed_entry.append(parsed_entry[3])
                parsed_entry[3] = "N/A"
            final_parsed = MACTableEntry(*parsed_entry)
            ret.append(final_parsed)
        except Exception as e:
            pass
    return ret


def parse_etherchannel_summary(etherchannel_summary: str) -> List[EtherChannelEntry]:
    if match := __etherchannel_start__.search(etherchannel_summary):
        etherchannel_table = (etherchannel_summary[match.start() :]).splitlines()
    else:
        return []
    ret = []
    for etherchannel_table_entry in etherchannel_table:
        table_parts = etherchannel_table_entry.split()
        if len(table_parts) < 3:
            continue
        try:
            group = int(table_parts.pop(0))
        except ValueError:
            continue
        if match := __etherchannel_strip_parens__.search(table_parts.pop(0)):
            port_channel = match.group(1)
        else:
            continue
        protocol = table_parts.pop(0)
        if protocol.lower() not in ("lacp", "pagp"):
            continue
        ifaces = []
        for iface in table_parts:
            if match := __etherchannel_strip_parens__.search(iface):
                port_name = match.group(1)
                port_states: str = match.group(2)
                parsed_states = EtherChannelStates.NONE
                for state_char in port_states:
                    try:
                        parsed_states |= __etherchannel_str_to_state[state_char]
                    except KeyError:
                        pass
                parsed_states ^= EtherChannelStates.NONE
                ifaces.append(EtherChannelPort(port_name, parsed_states))
        ret.append(EtherChannelEntry(group, port_channel, protocol, tuple(ifaces)))
    return ret
