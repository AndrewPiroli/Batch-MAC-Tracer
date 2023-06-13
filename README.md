## Batch MAC Tracer

Find the switchport of MAC addresses on your network. Currently 2 plugins are available for discovery:

 * LibreNMS - new system that uses LibreNMS to find ports, a work in progress still
 * CiscoSSH - SSH screen scraping based. It's old reliable but has restrictions on when it can be used

## Requirements and Limitations

 * Python >= 3.8

### Requirements for LibreNMS Plugin

 * requests library (install via `pip install requests`)
 * A working LibreNMS installation with API access
 * The port you're looking for must be polled by LibreNMS
 * Work in progress, may return incorrect results

### Requirements and Limitations for CiscoSSH Plugin

 * netmiko library (install via `pip install netmiko`)
 * Not L3 aware, will not cross an L3 boundry under any circumstancs
 * Only works with Cisco IOS(-XE) switches due to fragile screen scaping templates and hardcoded console commands

