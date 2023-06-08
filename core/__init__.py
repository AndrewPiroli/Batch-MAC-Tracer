# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import dataclasses
from typing import Optional


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


def fmac_cisco(mac: str) -> Optional[str]:
    """
    Given a string representation of a MAC address in a common format, return it in Cisco format.
    """
    # Fast-like remove ":", ".", and "-" in one go
    mac = mac.translate({58: None, 45: None, 46: None}).lower()
    if len(mac) != 12:
        return None
    return f"{mac[:4]}.{mac[4:8]}.{mac[8:12]}"


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
