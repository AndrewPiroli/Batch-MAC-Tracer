# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import dataclasses
import importlib.util
import sys
from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Callable, Any, Type
from core import TraceResult


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class PluginArgDescription:
    name: str
    description: str
    optional: bool = False
    can_fill_interactively: bool = True
    secret: bool = False
    default: Any = None


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class PluginArgs:
    details: Dict[str, Any]
    progress_callback: Optional[Callable[[TraceResult], None]]


class Plugin(ABC):
    @abstractmethod
    def start(self, args: PluginArgs) -> List[TraceResult]:
        pass

    @staticmethod
    @abstractmethod
    def args() -> List[PluginArgDescription]:
        pass


@dataclasses.dataclass(eq=True, order=False, frozen=True)
class PluginDecription:
    name: str
    description: str
    dependencies: List[str]
    cls: Type[Plugin]

    """
    Test if the plugin can be loaded by checking if its depenedencies are can be imported
    """

    def can_load(self) -> bool:
        for dependency in self.dependencies:
            if dependency in sys.modules:
                continue
            spec = importlib.util.find_spec(dependency)
            if spec is None:
                return False
        return True


from .cisco_ssh import CiscoSSHPlugin
from .librenms import LibreNMSPlugin

PLUGINS = [
    PluginDecription(
        name="CiscoSSH",
        description="An SSH based screen scraping tracer",
        dependencies=["netmiko"],
        cls=CiscoSSHPlugin,
    ),
    PluginDecription(
        name="LibreNMS",
        description="A LibreNMS discovery based tracer",
        dependencies=["requests"],
        cls=LibreNMSPlugin,
    ),
]
