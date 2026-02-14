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

## Features

### Passive Scanning
- 2.4GHz / 5GHz / 6GHz 전 대역 실시간 AP 탐지
- 보안 분류: WEP, WPA, WPA2, WPA3, OPN
- 802.11 a/b/g/n/ac/ax 표준 탐지
- 채널 폭 탐지 (20/40/80/160 MHz)
- Hidden SSID 탐지 및 복원
- MAC 벤더 조회
- 대역/정렬 필터링

### Active Scanning
- 화살표 키로 AP 선택하는 인터랙티브 UI
- 오픈(OPN) AP 접속 후 능동 정찰
- DHCP 정보 수집, ARP 스캔으로 연결 클라이언트 탐지
- 게이트웨이 포트 스캔 (22, 53, 80, 443, 8080, 8443)
- 결과 오버레이 패널로 즉시 확인

### Export
- CSV / JSON 내보내기 (능동 스캔 결과 포함)
- 설정 파일 지원

---

## Requirements

- Python 3.10+
- Linux (`iw`, `ip` 명령어)
- Root 권한
- Monitor 모드 지원 WiFi 어댑터

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
