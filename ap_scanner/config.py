"""Configuration file support using configparser.

Default path: ~/.config/ap-scanner/config.ini
CLI arguments always take precedence over config file values.
"""

import configparser
from pathlib import Path

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "ap-scanner" / "config.ini"

# Defaults that match CLI defaults
DEFAULTS = {
    "interface": "",
    "channels": "",
    "band": "all",
    "sort": "rssi",
    "no_color": "false",
    "verbose": "false",
    "log_file": "",
    "write": "",
    "dwell": "",
}


def load_config(config_path: str | None = None) -> dict[str, str]:
    """Load configuration from an INI file.

    Returns a dict of setting name -> string value.
    Missing keys are filled with defaults.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    result = dict(DEFAULTS)

    if not path.is_file():
        return result

    parser = configparser.ConfigParser()
    parser.read(path, encoding="utf-8")

    if parser.has_section("scanner"):
        for key in DEFAULTS:
            if parser.has_option("scanner", key):
                result[key] = parser.get("scanner", key)

    return result


def apply_config_to_args(args, config: dict[str, str]) -> None:
    """Apply config file values to argparse namespace where CLI didn't override.

    CLI arguments (non-default values) always take precedence.
    """
    # interface: CLI default is None
    if args.interface is None and config["interface"]:
        args.interface = config["interface"]

    # channels: CLI default is None
    if args.channels is None and config["channels"]:
        args.channels = config["channels"]

    # band: CLI default is "all"
    if args.band == "all" and config["band"] != "all":
        args.band = config["band"]

    # sort: CLI default is "rssi"
    if args.sort == "rssi" and config["sort"] != "rssi":
        args.sort = config["sort"]

    # no_color: CLI default is False
    if not args.no_color and config["no_color"].lower() == "true":
        args.no_color = True

    # verbose: CLI default is False
    if not args.verbose and config["verbose"].lower() == "true":
        args.verbose = True

    # log_file: CLI default is None
    if args.log_file is None and config["log_file"]:
        args.log_file = config["log_file"]

    # write: CLI default is None
    if args.write is None and config["write"]:
        args.write = config["write"]

    # dwell: CLI default is None
    if getattr(args, "dwell", None) is None and config.get("dwell"):
        try:
            args.dwell = float(config["dwell"])
        except ValueError:
            pass
