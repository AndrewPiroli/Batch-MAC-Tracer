# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import dataclasses
from pathlib import Path
from typing import List, Optional, Union
from functools import partial
from sys import stderr

eprint = partial(print, file=stderr)


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class MACFormatStyle:
    chars_before_sep: int
    sep: str

    def __post_init__(self):
        if self.chars_before_sep == 0:
            raise ValueError("chars_before_sep cannot be 0")

    @staticmethod
    def bare(mac: str) -> str:
        return "".join(c for c in mac if c.lower() in "0123456789abcdef")

    def to_style(self, mac: str) -> str:
        mac = self.bare(mac)
        return self.sep.join(
            [mac[i : i + self.chars_before_sep] for i in range(0, len(mac), self.chars_before_sep)]
        )

    @classmethod
    def recognize_style(cls, mac: str):
        first_sep = next((i for i in mac if i.lower() not in "0123456789abcdef"), "")
        chars_before_sep = mac.index(first_sep)
        if (
            chars_before_sep == 0
        ):  # no separator, 0 is problematic, set to 12 (total length of MAC with no separator)
            chars_before_sep = 12
        return MACFormatStyle(chars_before_sep, first_sep)


CISCO_STYLE = MACFormatStyle(4, ".")
DASH_STYLE = MACFormatStyle(2, "-")
COLON_STYLE = MACFormatStyle(2, ":")


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class TraceResult:
    status: str
    mac: str
    node: str
    iface: str

    def __str__(self) -> str:
        return f"{self.status},{self.mac},{self.node},{self.iface}"


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


def resolve_macs(mac_file_or_single: Union[Path, str]) -> Optional[List[str]]:
    def style(mac: str) -> str:
        detected_style = MACFormatStyle.recognize_style(mac)
        return detected_style.to_style(MACFormatStyle.bare(mac))

    res = []
    try:
        with open(mac_file_or_single) as mac_f:
            for mac in mac_f:
                formatted_mac = style(mac.strip())
                if not formatted_mac:
                    continue
                res.append(formatted_mac)
    except FileNotFoundError:
        formatted_mac = style(str(mac_file_or_single).strip())
        if formatted_mac is None:
            return None
    return res
