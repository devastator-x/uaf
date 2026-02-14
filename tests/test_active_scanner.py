"""Tests for ap_scanner.active_scanner utility functions."""

from ap_scanner.active_scanner import _calculate_network, _cidr_to_netmask, _is_ip


# --- _cidr_to_netmask ---

def test_cidr_to_netmask_24():
    assert _cidr_to_netmask(24) == "255.255.255.0"


def test_cidr_to_netmask_16():
    assert _cidr_to_netmask(16) == "255.255.0.0"


def test_cidr_to_netmask_32():
    assert _cidr_to_netmask(32) == "255.255.255.255"


def test_cidr_to_netmask_8():
    assert _cidr_to_netmask(8) == "255.0.0.0"


# --- _calculate_network ---

def test_calculate_network_24():
    result = _calculate_network("192.168.1.100", "255.255.255.0")
    assert result == "192.168.1.0/24"


def test_calculate_network_16():
    result = _calculate_network("10.0.5.42", "255.255.0.0")
    assert result == "10.0.0.0/16"


def test_calculate_network_invalid():
    result = _calculate_network("not_an_ip", "255.255.255.0")
    assert result == ""


# --- _is_ip ---

def test_is_ip_valid():
    assert _is_ip("192.168.1.1") is True


def test_is_ip_valid_zeros():
    assert _is_ip("0.0.0.0") is True


def test_is_ip_invalid_string():
    assert _is_ip("not_ip") is False


def test_is_ip_invalid_overflow():
    assert _is_ip("256.1.1.1") is False


def test_is_ip_empty():
    assert _is_ip("") is False


# --- _cidr_to_netmask edge cases ---

def test_cidr_to_netmask_0():
    assert _cidr_to_netmask(0) == "0.0.0.0"


def test_cidr_to_netmask_1():
    assert _cidr_to_netmask(1) == "128.0.0.0"


# --- _calculate_network edge cases ---

def test_calculate_network_32():
    """Host-only mask returns single host /32."""
    result = _calculate_network("192.168.1.42", "255.255.255.255")
    assert result == "192.168.1.42/32"


def test_calculate_network_8():
    """Class A mask."""
    result = _calculate_network("10.200.50.1", "255.0.0.0")
    assert result == "10.0.0.0/8"
