import dataclasses
import re
import traceback
from enum import auto, Flag
from typing import List

__cdp_entry_delimiter__ = re.compile(
    r"Device ID:.*?Unidirectional Mode:.*?(\n|\r|\r\n)", re.DOTALL | re.MULTILINE
)
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
        assert isinstance(self.vlan, int), "Vlan must be an integer"
        assert 0 < self.vlan < 4096, "Vlan out of range, 0 - 4096"
        assert len(self.mac_address) == 14, "mac address string out of range"
        assert self.entry_type.lower() in (
            "dynamic",
            "static",
            "system",
            "igmp",
        ), 'Invalid entry_type, "dynamic", "static", "system", "igmp"'
        # We don't really care about the others.


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
    entry_addresses: List[str] = dataclasses.field(default_factory=list)
    mgmt_addresses: List[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(order=True, frozen=True)
class EtherChannelEntry:
    group: int
    portchannel: str
    protocol: str
    ports: List[str] = dataclasses.field(default_factory=list)


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
            capabilities |= __cdp_str_to_capability__[capability]
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
        entry_addrs,
        mgmt_addrs,
    )


def parse_full_cdp_table(cdp_table: str) -> List[CDPTableEntry]:
    ret = list()
    for match in __cdp_entry_delimiter__.finditer(cdp_table):
        try:
            entry_result = parse_single_cdp_entry(
                cdp_table[match.start() : match.end()]
            )
            if isinstance(entry_result, CDPTableEntry):
                ret.append(entry_result)
        except Exception as e:
            traceback.print_exc()
    return ret


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
                ifaces.append(
                    match.group(1)
                )  # FIXME: We should parse the flags here instead of throwing them away
        ret.append(EtherChannelEntry(group, port_channel, protocol, ifaces))
    return ret
