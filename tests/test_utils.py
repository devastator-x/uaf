"""Tests for ap_scanner.utils."""

from ap_scanner.utils import (
    ALL_CHANNELS,
    CHANNELS_2G,
    CHANNELS_5G,
    CHANNELS_6G,
    channel_band,
    channel_to_freq,
    freq_to_channel,
    parse_channels_arg,
)


# --- freq_to_channel ---

def test_freq_to_channel_2g_ch1():
    assert freq_to_channel(2412) == 1


def test_freq_to_channel_2g_ch6():
    assert freq_to_channel(2437) == 6


def test_freq_to_channel_2g_ch11():
    assert freq_to_channel(2462) == 11


def test_freq_to_channel_5g_ch36():
    assert freq_to_channel(5180) == 36


def test_freq_to_channel_5g_ch48():
    assert freq_to_channel(5240) == 48


def test_freq_to_channel_5g_ch149():
    assert freq_to_channel(5745) == 149


def test_freq_to_channel_unknown():
    assert freq_to_channel(0) == 0


# --- channel_to_freq ---

def test_channel_to_freq_2g():
    assert channel_to_freq(1) == 2412
    assert channel_to_freq(6) == 2437


def test_channel_to_freq_5g():
    assert channel_to_freq(36) == 5180
    assert channel_to_freq(165) == 5825


def test_channel_to_freq_invalid():
    assert channel_to_freq(999) == 0


# --- channel_band ---

def test_channel_band_2g():
    assert channel_band(1) == "2.4"
    assert channel_band(6) == "2.4"
    assert channel_band(11) == "2.4"


def test_channel_band_5g():
    assert channel_band(36) == "5"
    assert channel_band(149) == "5"
    assert channel_band(165) == "5"


def test_channel_band_6g_with_freq():
    # Channel 1 at 5955 MHz is 6GHz, not 2.4GHz
    assert channel_band(1, freq=5955) == "6"
    assert channel_band(37, freq=6135) == "6"


def test_channel_band_disambiguate_by_freq():
    # Channel 1 without freq defaults to 2.4GHz
    assert channel_band(1) == "2.4"
    # Channel 1 with 2.4GHz freq
    assert channel_band(1, freq=2412) == "2.4"
    # Channel 1 with 6GHz freq
    assert channel_band(1, freq=5955) == "6"


def test_freq_to_channel_6g():
    assert freq_to_channel(5955) == 1
    assert freq_to_channel(6135) == 37


def test_channels_6g_contains_common():
    for ch in [1, 5, 9, 13, 37, 53, 149, 233]:
        assert ch in CHANNELS_6G


# --- parse_channels_arg ---

def test_parse_channels_single():
    result = parse_channels_arg("6")
    assert result == [6]


def test_parse_channels_list():
    result = parse_channels_arg("1,6,11")
    assert result == [1, 6, 11]


def test_parse_channels_range():
    result = parse_channels_arg("36-48")
    assert result == [36, 40, 44, 48]


def test_parse_channels_mixed():
    result = parse_channels_arg("1,6,36-48")
    assert result == [1, 6, 36, 40, 44, 48]


def test_parse_channels_invalid_falls_back():
    result = parse_channels_arg("999")
    assert result == ALL_CHANNELS


# --- Channel lists ---

def test_channels_2g_range():
    assert CHANNELS_2G == list(range(1, 15))


def test_channels_5g_contains_common():
    for ch in [36, 40, 44, 48, 149, 153, 157, 161, 165]:
        assert ch in CHANNELS_5G
