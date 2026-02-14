# UAF — Ultimate AP Finder

A Linux-based wireless AP detection and analysis tool for PCI-DSS security auditing.

> **[한국어 (Korean)](#uaf--ultimate-ap-finder-1)**

## Why UAF?

In enterprise environments, PCI-DSS (Payment Card Industry Data Security Standard) compliance requires **wireless AP vulnerability assessments**. You need to identify authorized vs. rogue APs, and detect open networks or APs using weak encryption.

Existing tools either stop at basic scanning, lack active reconnaissance capabilities, or don't provide output formats ready for enterprise audit reports.

**UAF** was built to solve this:

- Real-time collection of all nearby APs with automatic security classification (encryption/authentication/WPS)
- Visual highlighting of open (OPN) APs for immediate identification
- Active connection to suspicious APs to map network structure (DHCP, gateway, clients)
- Export results to CSV/JSON for direct use in audit reports

---

## Features

### Passive Scanning
- Real-time AP detection across 2.4GHz / 5GHz / 6GHz bands
- Security classification: WEP, WPA, WPA2, WPA3, OPN
- 802.11 a/b/g/n/ac/ax standard detection
- Channel width detection (20/40/80/160 MHz)
- Hidden SSID detection and recovery
- MAC vendor lookup
- Band/sort filtering

### Active Scanning
- Interactive UI with arrow key AP selection
- Active reconnaissance after connecting to open (OPN) APs
- DHCP information gathering, ARP scan for connected client detection
- Gateway port scan (22, 53, 80, 443, 8080, 8443)
- Instant results via overlay panel

### Export
- CSV / JSON export (including active scan results)
- Configuration file support

---

## Requirements

- Python 3.10+
- Linux (`iw`, `ip` commands)
- Root privileges
- WiFi adapter with monitor mode support

## Installation

### From PyPI

```bash
pip install uaf
```

### From source

```bash
git clone https://github.com/devastator-x/uaf.git
cd uaf
pip install -e .
```

## Usage

```bash
# Basic scan (auto-detect interface)
sudo uaf

# Specify interface
sudo uaf -i wlan0

# Scan specific channels only
sudo uaf -c 1,6,11

# Band filter
sudo uaf -b 2.4

# Change sort order
sudo uaf --sort channel

# Save to CSV
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

---

# UAF — Ultimate AP Finder

PCI-DSS 무선 보안 감사 대응을 위한 Linux 기반 AP 탐지 및 분석 도구.

## Why UAF?

기업 환경에서 PCI-DSS(Payment Card Industry Data Security Standard) 인증을 대응하다 보면 **무선 AP 취약점 점검** 항목을 마주하게 됩니다. 인가된 AP와 비인가(Rogue) AP를 식별하고, 오픈 네트워크나 취약한 암호화를 사용하는 AP를 탐지해야 합니다.

기존 도구들은 단순 스캔에 그치거나, 능동적 정찰이 불가능하거나, 기업 감사 보고서에 바로 활용할 수 있는 출력 포맷을 제공하지 않았습니다.

**UAF**는 이 문제를 해결하기 위해 만들어졌습니다:

- 주변 전체 AP를 실시간으로 수집하고, 보안 설정(암호화/인증/WPS)을 자동 분류
- 오픈(OPN) AP를 시각적으로 강조하여 즉시 식별
- 의심스러운 AP에 직접 접속해 네트워크 구조(DHCP, 게이트웨이, 클라이언트)까지 파악
- 결과를 CSV/JSON으로 내보내 감사 보고서에 바로 활용

---

## 기능

### 수동 스캔 (Passive Scanning)
- 2.4GHz / 5GHz / 6GHz 전 대역 실시간 AP 탐지
- 보안 분류: WEP, WPA, WPA2, WPA3, OPN
- 802.11 a/b/g/n/ac/ax 표준 탐지
- 채널 폭 탐지 (20/40/80/160 MHz)
- Hidden SSID 탐지 및 복원
- MAC 벤더 조회
- 대역/정렬 필터링

### 능동 스캔 (Active Scanning)
- 화살표 키로 AP 선택하는 인터랙티브 UI
- 오픈(OPN) AP 접속 후 능동 정찰
- DHCP 정보 수집, ARP 스캔으로 연결 클라이언트 탐지
- 게이트웨이 포트 스캔 (22, 53, 80, 443, 8080, 8443)
- 결과 오버레이 패널로 즉시 확인

### 내보내기 (Export)
- CSV / JSON 내보내기 (능동 스캔 결과 포함)
- 설정 파일 지원

---

## 요구 사항

- Python 3.10+
- Linux (`iw`, `ip` 명령어)
- Root 권한
- Monitor 모드 지원 WiFi 어댑터

## 설치

### PyPI에서 설치

```bash
pip install uaf
```

### 소스에서 설치

```bash
git clone https://github.com/devastator-x/uaf.git
cd uaf
pip install -e .
```

## 사용법

```bash
# 기본 스캔 (인터페이스 자동 탐지)
sudo uaf

# 인터페이스 지정
sudo uaf -i wlan0

# 특정 채널만 스캔
sudo uaf -c 1,6,11

# 대역 필터
sudo uaf -b 2.4

# 정렬 기준 변경
sudo uaf --sort channel

# CSV로 저장
sudo uaf -w output.csv

# 설정 파일 사용
sudo uaf --config /path/to/config.ini
```

## 키 바인딩

### 일반 모드
| 키 | 동작 |
|----|------|
| `q` | 종료 |
| `w` | CSV 저장 |
| `j` | JSON 저장 |
| `b` | 대역 필터 순환 (All / 2.4GHz / 5GHz / 6GHz) |
| `s` | 정렬 모드 순환 (RSSI / Channel / ESSID / ENC) |
| `Enter` | AP 선택 모드 진입 |

### 선택 모드
| 키 | 동작 |
|----|------|
| `↑` / `↓` | AP 목록 탐색 |
| `Enter` | 선택한 오픈 AP에 능동 스캔 실행 |
| `Esc` | 선택 모드 종료 |

## 설정

기본 설정 파일 경로: `~/.config/ap-scanner/config.ini`

```ini
[scanner]
interface = wlan0
band = all
sort = rssi
no_color = false
verbose = false
```

## 개발

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## 라이선스

GPL-2.0-or-later. 자세한 내용은 [LICENSE](LICENSE)를 참조하세요.
