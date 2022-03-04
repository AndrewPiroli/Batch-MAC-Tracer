## Cisco Batch MAC Tracer

A WIP MAC address tracer.

## Requirements

* netmiko
* textfsm

## Known Usability Issues

* Only works with Cisco IOS/IOS-XE devices (device type hardcoded to "cisco_ios" and uses `show mac address table {mac}`, `show cdp neighbors detail`, and `show etherchannel summary`)

* Assumes password and enable secret are the same

* Assumes login directly to enable/privileged exec
