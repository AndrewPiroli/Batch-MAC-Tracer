# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import dataclasses
from typing import List

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