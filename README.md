# AP Scanner

Real-time wireless access point scanner with active reconnaissance for Linux.

## Features

### Passive Scanning
- Real-time AP discovery with terminal display
- Automatic channel hopping (2.4GHz / 5GHz / 6GHz)
- Security detection: WEP, WPA, WPA2, WPA3
- WiFi standard detection: 802.11 a/b/g/n/ac/ax
- Channel width detection (20/40/80/160 MHz)
- Hidden SSID detection and resolution
- MAC vendor lookup
- Band filtering and sort modes

### Active Scanning (New!)
- Interactive AP selection with arrow keys
- Connect to open (OPN) networks for reconnaissance
- DHCP lease acquisition and network info extraction
- ARP scan to discover connected clients
- Gateway port scanning (22, 53, 80, 443, 8080, 8443)
- Client device enumeration with MAC vendor lookup
- Results displayed in overlay panel

### Export & Configuration
- CSV / JSON export with active scan results
- Configuration file support

## Requirements

- Python 3.10+
- Linux with `iw` and `ip` commands
- Root privileges
- WiFi adapter that supports monitor mode

## Installation

### From PyPI (recommended)

```bash
# Using pipx (isolated environment)
pipx install uaf

# Or using pip
pip install uaf
```

### From source

```bash
git clone https://github.com/devastator-x/uaf.git
cd uaf
pip install -e .
```

### Ubuntu/Debian (.deb package)

```bash
# Download from releases
wget https://github.com/devastator-x/uaf/releases/download/v1.0.0/uaf_1.0.0_all.deb
sudo dpkg -i uaf_1.0.0_all.deb
sudo apt-get install -f  # Install dependencies
```

## Usage

```bash
# Basic scan (auto-detect interface)
sudo uaf

# Specify interface
sudo uaf -i wlan0

# Scan specific channels
sudo uaf -c 1,6,11

# Band filter
sudo uaf -b 2.4

# Sort by channel
sudo uaf --sort channel

# Save to specific file
sudo uaf -w output.csv

# Use config file
sudo uaf --config /path/to/config.ini
```

## Keybindings

### Normal Mode
| Key | Action |
|-----|--------|
| `q` | Quit |
| `w` | Write CSV |
| `j` | Write JSON |
| `b` | Cycle band filter (All / 2.4GHz / 5GHz / 6GHz) |
| `s` | Cycle sort mode (RSSI / Channel / ESSID / ENC) |
| `Enter` | Enter AP selection mode |

### Selection Mode
| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate through AP list |
| `Enter` | Run active scan on selected open AP |
| `Esc` | Exit selection mode |

## Configuration

Default config path: `~/.config/ap-scanner/config.ini`

```ini
[scanner]
interface = wlan0
band = all
sort = rssi
no_color = false
verbose = false
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

GPL-2.0-or-later. See [LICENSE](LICENSE) for details.
