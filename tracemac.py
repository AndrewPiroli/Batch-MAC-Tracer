# SPDX-License-Identifier: BSD-3-Clause
# Andrew Piroli 2023

import argparse
import sys
import time
import json
from getpass import getpass
from plugin import PLUGINS, PluginArgs, PluginDecription, PluginArgDescription
from core import eprint
from typing import List, Optional


def _find_plugin(name: str, available_plugins: List[PluginDecription]) -> Optional[PluginDecription]:
    needle = name.strip().lower()
    return next((p for p in available_plugins if p.name.strip().lower() == needle), None)


if __name__ == "__main__":
    available_plugins = [plugin for plugin in PLUGINS if plugin.can_load()]
    plugin_names = "{}".format(" ".join(p.name for p in available_plugins))
    if len(available_plugins) == 0:
        eprint("No plugins available, please install the dependencies for at least one plugin.")
        exit(1)

    # extract --plugin and --config only, ignore everything else.
    # This tells us which plugin to load so we can register its flags before
    # parsing the remaining arguments
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument("--plugin", "-p")
    pre_parser.add_argument("--config", "-c")
    pre_args, _ = pre_parser.parse_known_args()

    pre_loaded_config = {}
    if pre_args.config is not None:
        try:
            with open(pre_args.config, "r") as f:
                pre_loaded_config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            eprint(f"Error reading config file '{pre_args.config}': {e}")
            exit(1)

    plugin_name_hint = pre_args.plugin or pre_loaded_config.get("plugin")
    if plugin_name_hint is None:
        selected_plugin = None
    else:
        selected_plugin = _find_plugin(plugin_name_hint, available_plugins)

    # add per-plugin flags if we know the plugin at this point.
    parser = argparse.ArgumentParser(description="Bulk trace MAC addresses")
    parser.add_argument(
        "--config",
        "-c",
        help="JSON config file to load (optional when all required args are supplied on the command line)",
        metavar="FILE",
    )
    parser.add_argument("--plugin", "-p", help=f"The plugin to use. Options: {plugin_names}")
    parser.add_argument(
        "--non-interactive",
        action="store_true",
        default=False,
        help="Never prompt for missing arguments; exit with an error instead",
    )

    if selected_plugin is not None:
        plugin_arg_descs = selected_plugin.cls.args()
        for pad in plugin_arg_descs:
            flag = f"--{pad.name}"
            kwargs = dict(
                help=pad.description + (" [optional]" if pad.optional else ""),
                default=None,
            )
            parser.add_argument(flag, **kwargs)  # pyright: ignore[reportArgumentType]
    else:
        plugin_arg_descs: List[PluginArgDescription] = []

    args = parser.parse_args()
    loaded_config = {}
    if args.config is not None:
        try:
            with open(args.config, "r") as f:
                loaded_config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            eprint(f"Error reading config file '{args.config}': {e}")
            exit(1)

    # Overlay any plugin args explicitly passed on the CLI.
    for pad in plugin_arg_descs:
        cli_val = getattr(args, pad.name.replace("-", "_"), None)
        if cli_val is not None:
            loaded_config[pad.name] = cli_val

    args_have = {*loaded_config}
    if args.plugin is not None:
        selected_plugin = _find_plugin(args.plugin, available_plugins)
        if selected_plugin is None:
            eprint(f"No plugin found with name: {args.plugin}\nOptions: {plugin_names}")
            exit(1)
    else:
        if "plugin" not in args_have:
            eprint(f"No plugin specified on command line or in config file. Options: {plugin_names}")
            exit(1)
        selected_plugin = _find_plugin(loaded_config["plugin"], available_plugins)
        if selected_plugin is None:
            eprint(f"No plugin found with name: {loaded_config['plugin']}\nOptions: {plugin_names}")
            exit(1)
    eprint("Loaded plugin: {}".format(selected_plugin.name))

    plugin = selected_plugin.cls()
    args_need = plugin.args()
    non_interactive: bool = args.non_interactive or not sys.stdin.isatty()
    while True:
        missing = [m for m in args_need if m.name not in args_have and not m.optional]
        if len(missing) == 0:
            break

        if non_interactive:
            eprint(
                "Missing required arguments: {}\n"
                "Supply them via the config file or command-line flags.".format(
                    ", ".join(m.name for m in missing)
                )
            )
            exit(1)

        eprint("Missing arguments: {}".format(", ".join([m.name for m in missing])))
        for arg in missing:
            if arg.can_fill_interactively == False:
                eprint(
                    f"Argument {arg.name}: {arg.description} cannot be filled interactively and is required"
                )
                exit(1)
            eprint(f"Enter value for {arg.name} ({arg.description}): ", end="", flush=True)
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
        eprint(f"Error: {e}")
    finally:
        eprint(f"Elapsed: {time.perf_counter() - start_time}")
