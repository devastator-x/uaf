"""Tests for ap_scanner.oui."""

from ap_scanner.oui import lookup_vendor


def test_lookup_known_vendor_tp_link():
    result = lookup_vendor("5C:A6:E6:11:22:33")
    assert result == "TP-Link"


def test_lookup_known_vendor_cisco():
    result = lookup_vendor("00:1B:2A:11:22:33")
    assert result == "Cisco"


def test_lookup_unknown_vendor():
    result = lookup_vendor("FF:FF:FF:11:22:33")
    # Should return empty string or some value from system OUI file
    assert isinstance(result, str)


def test_lookup_case_insensitive():
    # The function should handle lowercase MAC addresses
    result = lookup_vendor("5c:a6:e6:11:22:33")
    assert result == "TP-Link"
