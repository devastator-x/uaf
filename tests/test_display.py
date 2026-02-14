"""Tests for ap_scanner.display."""

from ap_scanner.display import Display, _display_width, _pad_to_width, _truncate_to_width


# --- _display_width ---

def test_display_width_ascii():
    assert _display_width("hello") == 5


def test_display_width_cjk():
    # CJK characters are 2 cells wide each
    assert _display_width("\u5317\u4eac") == 4  # 北京


def test_display_width_mixed():
    assert _display_width("AB\u5317\u4eac") == 6  # 2 ASCII + 2 CJK


def test_display_width_empty():
    assert _display_width("") == 0


# --- _truncate_to_width ---

def test_truncate_no_change():
    assert _truncate_to_width("short", 10) == "short"


def test_truncate_long_ascii():
    result = _truncate_to_width("a" * 30, 10)
    assert _display_width(result) <= 11  # 10 + ellipsis


def test_truncate_cjk():
    # 5 CJK chars = 10 cells, truncate to 7
    result = _truncate_to_width("\u5317\u4eac\u4e0a\u6d77\u5e7f", 7)
    assert _display_width(result) <= 8  # truncated + ellipsis


# --- _pad_to_width ---

def test_pad_to_width_shorter():
    result = _pad_to_width("hi", 10)
    assert _display_width(result) == 10


def test_pad_to_width_exact():
    result = _pad_to_width("12345", 5)
    assert result == "12345"


def test_pad_to_width_cjk():
    # 2 CJK chars = 4 cells, pad to 10
    result = _pad_to_width("\u5317\u4eac", 10)
    assert _display_width(result) == 10
    assert result.endswith(" " * 6)


# --- Display class ---

def test_cycle_sort():
    d = Display()
    assert d.sort_field == "rssi"
    d.cycle_sort()
    assert d.sort_field == "channel"
    d.cycle_sort()
    assert d.sort_field == "essid"
    d.cycle_sort()
    assert d.sort_field == "enc"
    d.cycle_sort()
    assert d.sort_field == "rssi"  # wraps around


def test_cycle_band():
    d = Display()
    assert d.band_filter is None

    result = d.cycle_band()
    assert result == "2.4GHz"
    assert d.band_filter == "2.4GHz"

    result = d.cycle_band()
    assert result == "5GHz"

    result = d.cycle_band()
    assert result == "6GHz"
    assert d.band_filter == "6GHz"

    result = d.cycle_band()
    assert result == "all"
    assert d.band_filter is None


def test_set_sort_valid():
    d = Display()
    d.set_sort("channel")
    assert d.sort_field == "channel"


def test_set_sort_invalid():
    d = Display()
    d.set_sort("nonexistent")
    assert d.sort_field == "rssi"  # unchanged


# --- Selection mode ---

def test_selection_mode_toggle():
    d = Display()
    assert d._selection_mode is False
    d.enter_selection_mode()
    assert d._selection_mode is True
    assert d._selected_index == 0
    d.exit_selection_mode()
    assert d._selection_mode is False
    assert d._selected_index == 0


def test_move_selection_bounds():
    d = Display()
    d.enter_selection_mode()
    # Move down within bounds
    d.move_selection(1, 5)
    assert d._selected_index == 1
    d.move_selection(1, 5)
    assert d._selected_index == 2
    # Move past end — should clamp
    d.move_selection(10, 5)
    assert d._selected_index == 4
    # Move past start — should clamp to 0
    d.move_selection(-10, 5)
    assert d._selected_index == 0


def test_move_selection_empty():
    d = Display()
    d.enter_selection_mode()
    d.move_selection(1, 0)
    assert d._selected_index == 0


def test_get_sorted_filtered(sample_ap, open_ap):
    d = Display()
    aps = {sample_ap.bssid: sample_ap, open_ap.bssid: open_ap}
    result = d.get_sorted_filtered(aps)
    assert len(result) == 2
    # Default sort by rssi descending: -42 > -73
    assert result[0].bssid == sample_ap.bssid


def test_get_sorted_filtered_band(sample_ap, open_ap):
    d = Display()
    d.band_filter = "5GHz"
    aps = {sample_ap.bssid: sample_ap, open_ap.bssid: open_ap}
    result = d.get_sorted_filtered(aps)
    # Both are 2.4GHz, so filtering to 5GHz returns nothing
    assert len(result) == 0


# --- Overlay title padding fix ---

def test_overlay_title_width():
    """Verify overlay title line does not exceed border width (bug fix)."""
    from ap_scanner.display import _display_width

    box_width = 72
    title = "ACTIVE SCAN: TestNet (AA:BB:CC:DD:EE:FF)"
    title_line = f"| {title}"
    pad = box_width - 3 - _display_width(title)
    title_line += " " * max(0, pad) + "|"

    border = "+" + "-" * (box_width - 2) + "+"

    assert _display_width(title_line) == _display_width(border), (
        f"title_line width ({_display_width(title_line)}) != "
        f"border width ({_display_width(border)})"
    )


def test_overlay_content_line_width():
    """Verify overlay content lines match border width."""
    from ap_scanner.display import _display_width, _truncate_to_width

    box_width = 72
    line = "Assigned IP:  192.168.1.100"
    display_line = _truncate_to_width(line, box_width - 4)
    pad = box_width - 2 - _display_width(display_line) - 1
    row = f"| {display_line}" + " " * max(0, pad) + "|"

    border = "+" + "-" * (box_width - 2) + "+"

    assert _display_width(row) == _display_width(border)


def test_overlay_title_width_cjk():
    """Overlay title with CJK characters must not exceed border width."""
    from ap_scanner.display import _display_width

    box_width = 72
    title = "\u5317\u4eac\u7f51\u7edc (AA:BB:CC:DD:EE:FF)"  # 北京网络
    title_line = f"| {title}"
    pad = box_width - 3 - _display_width(title)
    title_line += " " * max(0, pad) + "|"

    border = "+" + "-" * (box_width - 2) + "+"

    assert _display_width(title_line) == _display_width(border)
