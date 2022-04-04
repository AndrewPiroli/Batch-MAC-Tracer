## Cisco Batch MAC Tracer

A WIP MAC address tracer.

## Requirements

* Python <= 3.8
* netmiko

## Known Usability Issues

* Only works with Cisco IOS/IOS-XE devices (device type hardcoded to "cisco_ios" and uses `show mac address table`, `show cdp neighbors detail`, and `show etherchannel summary`)

* When parsing EtherChannel links, it assumes the first one listed in `show etherchannel summary` is up and working.

* Assumes password and enable secret are the same

* Assumes login directly to enable/privileged exec
