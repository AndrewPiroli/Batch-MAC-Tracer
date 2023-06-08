# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import re
import dataclasses
from enum import Flag, auto
from typing import List, Tuple

__etherchannel_start__ = re.compile(r"--+--")  # This looks dumb, but it gets us in the ballpark
__etherchannel_strip_parens__ = re.compile(r"(.*?)(\(.*?\))", re.DOTALL)


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
                raise TypeError(f"EtherChannelEntry.ports[{idx}] is not a EtherChannelPort type")


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
