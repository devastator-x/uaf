"""Tests for ap_scanner.exporter."""

import csv
import json
from pathlib import Path

from ap_scanner.exporter import generate_filename, save_csv, save_json


def test_generate_filename_format():
    name = generate_filename()
    assert name.startswith("ap_scan_")
    assert name.endswith(".csv")


def test_save_csv_creates_file(sample_ap, tmp_path):
    filepath = tmp_path / "test_output.csv"
    aps = {sample_ap.bssid: sample_ap}
    result = save_csv(aps, str(filepath))
    assert Path(result).exists()


def test_save_csv_field_count(sample_ap, tmp_path):
    filepath = tmp_path / "test_fields.csv"
    aps = {sample_ap.bssid: sample_ap}
    save_csv(aps, str(filepath))

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.reader(f, delimiter=";")
        header = next(reader)
        assert len(header) == 20
        row = next(reader)
        assert len(row) == 20


def test_save_csv_semicolon_delimiter(sample_ap, tmp_path):
    filepath = tmp_path / "test_delim.csv"
    aps = {sample_ap.bssid: sample_ap}
    save_csv(aps, str(filepath))

    content = filepath.read_text(encoding="utf-8")
    # Header should contain semicolons (semicolon-delimited)
    assert ";" in content.splitlines()[0]


def test_save_csv_auto_filename(sample_ap, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    aps = {sample_ap.bssid: sample_ap}
    result = save_csv(aps)
    assert result.startswith("ap_scan_")
    assert Path(result).exists()


# --- JSON export ---

def test_generate_filename_json():
    name = generate_filename("json")
    assert name.startswith("ap_scan_")
    assert name.endswith(".json")


def test_save_json_creates_file(sample_ap, tmp_path):
    filepath = tmp_path / "test_output.json"
    aps = {sample_ap.bssid: sample_ap}
    result = save_json(aps, str(filepath))
    assert Path(result).exists()


def test_save_json_valid_structure(sample_ap, tmp_path):
    filepath = tmp_path / "test_struct.json"
    aps = {sample_ap.bssid: sample_ap}
    save_json(aps, str(filepath))

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "scan_time" in data
    assert "access_points" in data
    assert len(data["access_points"]) == 1
    ap = data["access_points"][0]
    assert ap["bssid"] == sample_ap.bssid
    assert ap["ssid"] == sample_ap.display_ssid
    assert ap["channel"] == sample_ap.channel


def test_save_json_auto_filename(sample_ap, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    aps = {sample_ap.bssid: sample_ap}
    result = save_json(aps)
    assert result.startswith("ap_scan_")
    assert result.endswith(".json")
    assert Path(result).exists()


# --- Active scan export ---

def test_save_json_with_active_scan(open_ap, tmp_path):
    from ap_scanner.models import ActiveScanClient, ActiveScanResult

    open_ap.active_scan_result = ActiveScanResult(
        bssid=open_ap.bssid, ssid=open_ap.display_ssid,
        connected=True, assigned_ip="192.168.1.100",
        gateway_ip="192.168.1.1", gateway_mac="AA:BB:CC:DD:EE:01",
        dns_servers=["8.8.8.8"], gateway_open_ports=[80, 443],
        clients=[ActiveScanClient(ip="192.168.1.50", mac="AA:AA:AA:AA:AA:AA")],
        duration_secs=12.3,
    )
    filepath = tmp_path / "active.json"
    aps = {open_ap.bssid: open_ap}
    save_json(aps, str(filepath))

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    ap_data = data["access_points"][0]
    assert "active_scan" in ap_data
    scan = ap_data["active_scan"]
    assert scan["connected"] is True
    assert scan["assigned_ip"] == "192.168.1.100"
    assert scan["gateway_ip"] == "192.168.1.1"
    assert scan["gateway_open_ports"] == [80, 443]
    assert len(scan["clients"]) == 1
    assert scan["clients"][0]["ip"] == "192.168.1.50"


def test_save_csv_active_scan_columns(open_ap, tmp_path):
    from ap_scanner.models import ActiveScanResult

    open_ap.active_scan_result = ActiveScanResult(
        bssid=open_ap.bssid, ssid=open_ap.display_ssid,
        connected=True, assigned_ip="10.0.0.5",
        gateway_ip="10.0.0.1", gateway_open_ports=[22, 80],
    )
    filepath = tmp_path / "active.csv"
    aps = {open_ap.bssid: open_ap}
    save_csv(aps, str(filepath))

    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        row = next(reader)

    assert row["Active Scan IP"] == "10.0.0.5"
    assert row["Active Scan Gateway"] == "10.0.0.1"
    assert row["Active Scan Ports"] == "22,80"


def test_save_json_no_active_scan(sample_ap, tmp_path):
    filepath = tmp_path / "no_active.json"
    aps = {sample_ap.bssid: sample_ap}
    save_json(aps, str(filepath))

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    ap_data = data["access_points"][0]
    assert "active_scan" not in ap_data
