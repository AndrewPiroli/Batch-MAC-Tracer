try:
    import requests
except ImportError:
    pass
from typing import List
from functools import cache
from . import Plugin, PluginArgs, PluginArgDescription
from core import *

LNMS_PORTS_MAC_SEARCH = "/api/v0/ports/mac/"
LNMS_DEVICES = "/api/v0/devices/"


class LibreNMSPlugin(Plugin):
    def start(self, args: PluginArgs) -> List[TraceResult]:
        self.auth_header = {"X-Auth-Token": args.details["api-key"]}
        self.session = requests.Session()
        self.session.headers.update(self.auth_header)
        self.host = args.details["host"]
        self.protocol = args.details["protocol"]
        if self.protocol not in ["http", "https"]:
            eprint("Invalid protocol [http, https]")
            return []
        self.macs = resolve_macs(args.details["macs"])
        if self.macs is None:
            eprint("Failed to resolve MACs")
            return []
        self.rps = args.details["rps"] if "rps" in args.details else 10
        port = args.details["port"] if "port" in args.details else 443
        if not isinstance(port, int) or port < 1 or port > 65535:
            eprint("Invalid port [1-65535]")
            return []
        self.base_uri = f"{self.protocol}://{self.host}:{port}"
        if self.protocol == "https":
            self.verify = args.details["tls_verify"] if "tls_verify" in args.details else True
        else:
            self.verify = False
        res = []
        for mac in self.macs:
            found = self.find_mac(mac)
            if callable(args.progress_callback):
                args.progress_callback(found)
            res.append(found)
        return res

    @staticmethod
    def args() -> List[PluginArgDescription]:
        return [
            PluginArgDescription(
                "api-key", "LibreNMS API Key", optional=False, can_fill_interactively=True, secret=True
            ),
            PluginArgDescription("host", "LibreNMS Host", optional=False, can_fill_interactively=True),
            PluginArgDescription(
                "macs",
                "Path to file containing MACs to trace OR a single MAC address",
                optional=False,
                can_fill_interactively=True,
            ),
            PluginArgDescription(
                "rps", "Maximum Requests per second", optional=True, can_fill_interactively=True, default=10
            ),
            PluginArgDescription(
                "protocol",
                "Protocol to use (http/https)",
                optional=True,
                can_fill_interactively=True,
                default="https",
            ),
            PluginArgDescription(
                "port", "Port to use", optional=True, can_fill_interactively=True, default=443
            ),
            PluginArgDescription(
                "tls_verify",
                "Verify TLS certificate",
                optional=True,
                can_fill_interactively=True,
                default=True,
            ),
        ]

    def find_mac(self, mac: str) -> TraceResult:
        request_mac = MACFormatStyle.bare(mac)
        url = f"{self.base_uri}{LNMS_PORTS_MAC_SEARCH}{request_mac}"
        r = self.session.get(url, verify=self.verify)
        if r.status_code == 200:
            data = r.json()
            if len(data) < 1:
                return TraceResult("err-unknown", mac, "Unknown", "Unknown")
            if data["status"] != "ok":
                return TraceResult("err-unknown", mac, "Unknown", "Unknown")
            if len(data["ports"]) < 1:
                return TraceResult("err-unknown", mac, "Unknown", "Unknown")
            candidate = {"port_id": "PLACEHOLDER", "fdb_entries_count": 9999999}
            for port in data["ports"]:
                if (
                    port["ifOperStatus"] == "up"
                    and port["fdb_entries_count"] < candidate["fdb_entries_count"]
                ):
                    candidate = port
            if candidate["port_id"] == "PLACEHOLDER":
                return TraceResult("err-unknown", mac, "Unknown", "Unknown")
            hostname = self.get_hostname_from_device_id(candidate["device_id"])
            if hostname is None:
                return TraceResult("err-unknown", mac, "Unknown", "Unknown")
            return TraceResult("ok", mac, hostname, str(candidate["ifName"]))
        else:
            return TraceResult("err-unknown", mac, "Unknown", "Unknown")

    @cache
    def get_hostname_from_device_id(self, device_id: str) -> Optional[str]:
        url = f"{self.base_uri}{LNMS_DEVICES}{device_id}"
        r = self.session.get(url, verify=self.verify)
        if r.status_code == 200:
            data = r.json()
            if len(data) < 1 or len(data["devices"]) < 1:
                return None
            if data["status"] != "ok":
                return None
            return data["devices"][0]["sysName"]
        else:
            return None
