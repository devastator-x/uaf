"""Tests for ap_scanner.config."""

import argparse

from ap_scanner.config import apply_config_to_args, load_config


def test_load_config_missing_file(tmp_path):
    result = load_config(str(tmp_path / "nonexistent.ini"))
    assert result["band"] == "all"
    assert result["sort"] == "rssi"
    assert result["interface"] == ""


def test_load_config_valid_file(tmp_path):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[scanner]\ninterface = wlan0\nband = 5\nsort = channel\n")
    result = load_config(str(cfg))
    assert result["interface"] == "wlan0"
    assert result["band"] == "5"
    assert result["sort"] == "channel"


def test_load_config_partial_file(tmp_path):
    cfg = tmp_path / "config.ini"
    cfg.write_text("[scanner]\nband = 2.4\n")
    result = load_config(str(cfg))
    assert result["band"] == "2.4"
    assert result["sort"] == "rssi"  # default


def test_apply_config_cli_overrides():
    args = argparse.Namespace(
        interface="wlan1", channels=None, band="all",
        sort="rssi", no_color=False, verbose=False,
        log_file=None, write=None,
    )
    config = {"interface": "wlan0", "channels": "1,6,11", "band": "5",
              "sort": "channel", "no_color": "false", "verbose": "false",
              "log_file": "", "write": ""}
    apply_config_to_args(args, config)
    # CLI set interface to wlan1, should NOT be overridden
    assert args.interface == "wlan1"
    # CLI didn't set channels, should pick up from config
    assert args.channels == "1,6,11"
    # CLI band is default "all", config says "5"
    assert args.band == "5"


def test_apply_config_all_defaults():
    args = argparse.Namespace(
        interface=None, channels=None, band="all",
        sort="rssi", no_color=False, verbose=False,
        log_file=None, write=None,
    )
    config = {"interface": "", "channels": "", "band": "all",
              "sort": "rssi", "no_color": "false", "verbose": "false",
              "log_file": "", "write": ""}
    apply_config_to_args(args, config)
    assert args.interface is None
    assert args.band == "all"


def test_apply_config_bool_options():
    args = argparse.Namespace(
        interface=None, channels=None, band="all",
        sort="rssi", no_color=False, verbose=False,
        log_file=None, write=None,
    )
    config = {"interface": "", "channels": "", "band": "all",
              "sort": "rssi", "no_color": "true", "verbose": "true",
              "log_file": "/tmp/test.log", "write": ""}
    apply_config_to_args(args, config)
    assert args.no_color is True
    assert args.verbose is True
    assert args.log_file == "/tmp/test.log"
