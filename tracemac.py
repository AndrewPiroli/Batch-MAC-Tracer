# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import argparse
import time
import json
from getpass import getpass
from plugin import PLUGINS, PluginArgs

if __name__ == "__main__":
    available_plugins = [plugin for plugin in PLUGINS if plugin.can_load()]
    plugin_names = "{}".format(" ".join(p.name for p in available_plugins))
    if len(available_plugins) == 0:
        print("No plugins available, please install the dependencies for at least one plugin.")
        exit(1)
    parser = argparse.ArgumentParser(description="Bulk trace MAC addresses")
    parser.add_argument("CONFIG", help="JSON Config file to load", type=argparse.FileType("r"))
    parser.add_argument("--plugin", "-p", help=f"The plugin to use, options: {plugin_names}")
    args = parser.parse_args()
    loaded_config = json.load(args.CONFIG)
    args_have = {*loaded_config}
    if args.plugin is not None:
        selected_plugin = next(
            p for p in available_plugins if p.name.strip().lower() == args.plugin.strip().lower()
        )
        if selected_plugin is None:
            print(f"No plugin found with name: {args.plugin}\nOptions: {plugin_names}")
            exit(1)
    else:
        if "plugin" not in args_have:
            print(f"No plugin specified on command line or config file, options: {plugin_names}")
            exit(1)
        requested_plugin = loaded_config["plugin"].strip().lower()
        selected_plugin = next(p for p in available_plugins if p.name.strip().lower() == requested_plugin)
        if selected_plugin is None:
            print(f"No plugin found with name: {requested_plugin}\nOptions: {plugin_names}")
            exit(1)
    print("Loaded plugin: {}".format(selected_plugin.name))
    plugin = selected_plugin.cls()
    args_need = plugin.args()
    while True:
        missing = [m for m in args_need if m.name not in args_have and not m.optional]
        if len(missing) == 0:
            break
        print("Missing arguments: {}".format(", ".join([m.name for m in missing])))
        for arg in missing:
            if arg.can_fill_interactively == False:
                print(
                    f"Argument {arg.name}: {arg.description} cannot be filled interactively and is required"
                )
                exit(1)
            print(f"Enter value for {arg.name} ({arg.description}): ", end="", flush=True)
            if arg.secret:
                loaded_config[arg.name] = getpass("")
            else:
                loaded_config[arg.name] = input("")
        args_have = {*loaded_config}
    p_args = PluginArgs(details=loaded_config, progress_callback=print)
    print("result,mac,switch,interface")
    start_time = time.perf_counter()
    try:
        plugin.start(p_args)
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print(f"Elapsed: {time.perf_counter() - start_time}")
