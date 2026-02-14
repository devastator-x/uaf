# Release Guide: PyPI & APT 패키지 배포

## 1. PyPI 배포 (pipx 지원)

### 1-1. PyPI 계정 생성
1. https://pypi.org/account/register/ 방문
2. 계정 생성 및 이메일 인증
3. (선택) 2FA 활성화 (권장)

### 1-2. API 토큰 생성
1. https://pypi.org/manage/account/token/ 방문
2. "Add API token" 클릭
3. Token name: `uaf-upload`
4. Scope: "Entire account" (첫 업로드) 또는 "Project: uaf"
5. 생성된 토큰 복사 (다시 볼 수 없음!)

### 1-3. TestPyPI에서 먼저 테스트 (권장)

```bash
# TestPyPI 계정 생성: https://test.pypi.org/account/register/
# TestPyPI API 토큰 생성: https://test.pypi.org/manage/account/token/

# 빌드
python -m build

# 테스트 업로드
twine upload --repository testpypi dist/*

# Username: __token__
# Password: pypi-AgE... (복사한 토큰 전체)

# 테스트 설치
pipx install --index-url https://test.pypi.org/simple/ uaf

# 테스트 실행
sudo uaf --help
```

### 1-4. 정식 PyPI 업로드

```bash
# 정식 업로드
twine upload dist/*

# Username: __token__
# Password: pypi-AgE... (복사한 토큰 전체)
```

업로드 성공 후 URL: https://pypi.org/project/uaf/

### 1-5. 전 세계 사용자가 설치 가능!

```bash
# pipx로 설치 (권장)
pipx install uaf

# 또는 pip로 설치
pip install uaf

# 사용
sudo uaf
```

---

## 2. APT 패키지 배포 (.deb)

### 2-1. 필요한 도구 설치

```bash
sudo apt install debhelper dh-python python3-all python3-setuptools
```

### 2-2. debian/ 디렉토리 구조 생성

```bash
mkdir -p debian
cd debian
```

다음 파일들을 생성해야 합니다:

#### `debian/control`

```
Source: uaf
Section: net
Priority: optional
Maintainer: devastator-x
Build-Depends: debhelper-compat (= 13),
               dh-python,
               python3-all,
               python3-setuptools
Standards-Version: 4.6.0
Homepage: https://github.com/devastator-x/uaf
Vcs-Git: https://github.com/devastator-x/uaf.git

Package: uaf
Architecture: all
Depends: ${python3:Depends},
         ${misc:Depends},
         python3-scapy,
         iw,
         iproute2
Recommends: wireless-tools
Description: Real-time wireless access point scanner with active reconnaissance
 UAF is a Linux CLI tool for discovering and analyzing WiFi access
 points. It supports passive monitoring across 2.4/5/6 GHz bands and active
 reconnaissance on open networks.
 .
 Features:
  - Real-time AP discovery with channel hopping
  - Security detection (WEP/WPA/WPA2/WPA3)
  - Active scanning: DHCP, ARP, port scanning
  - CSV/JSON export with scan results
```

#### `debian/rules`

```makefile
#!/usr/bin/make -f

export PYBUILD_NAME=uaf

%:
	dh $@ --with python3 --buildsystem=pybuild
```

#### `debian/changelog`

```
uaf (1.0.0-1) unstable; urgency=medium

  * Initial release
  * Passive WiFi scanning with channel hopping
  * Active reconnaissance on open networks
  * CSV/JSON export support

 -- devastator-x  Tue, 11 Feb 2026 22:00:00 +0900
```

#### `debian/copyright`

```
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: uaf
Upstream-Contact: devastator-x
Source: https://github.com/devastator-x/uaf

Files: *
Copyright: 2026 devastator-x
License: GPL-2.0-or-later

License: GPL-2.0-or-later
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.
 .
 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 .
 On Debian systems, the complete text of the GNU General
 Public License version 2 can be found in "/usr/share/common-licenses/GPL-2".
```

#### `debian/compat`

```
13
```

### 2-3. .deb 패키지 빌드

```bash
# 프로젝트 루트에서
dpkg-buildpackage -us -uc -b

# 또는 debuild 사용
debuild -us -uc -b
```

빌드 성공 후 상위 디렉토리에 `.deb` 파일이 생성됩니다:
```
../uaf_1.0.0-1_all.deb
```

### 2-4. 로컬 테스트

```bash
# 설치
sudo dpkg -i ../uaf_1.0.0-1_all.deb

# 의존성 해결 (필요시)
sudo apt-get install -f

# 테스트
sudo uaf --help

# 제거
sudo apt remove uaf
```

### 2-5. GitHub Releases에 업로드

1. GitHub 저장소 → Releases → "Create a new release"
2. Tag: `v1.0.0`
3. Title: `UAF v1.0.0`
4. Description: Release notes 작성
5. `.deb` 파일 업로드 (Assets)
6. "Publish release" 클릭

사용자는 다음과 같이 설치:
```bash
wget https://github.com/devastator-x/uaf/releases/download/v1.0.0/uaf_1.0.0-1_all.deb
sudo dpkg -i uaf_1.0.0-1_all.deb
sudo apt-get install -f
```

### 2-6. PPA (Personal Package Archive) 생성 (고급)

Ubuntu 공식 저장소처럼 `apt install uaf`를 지원하려면:

1. Launchpad 계정 생성: https://launchpad.net/
2. PPA 생성: https://launchpad.net/~/+activate-ppa
3. GPG 키 생성 및 등록
4. 소스 패키지 빌드 & 업로드

자세한 가이드: https://help.launchpad.net/Packaging/PPA

---

## 3. 릴리스 체크리스트

배포 전 확인사항:

- [ ] 모든 테스트 통과 (`pytest tests/ -v`)
- [ ] README.md 업데이트 (기능, 설치 방법)
- [ ] CHANGELOG 작성
- [ ] 버전 번호 업데이트 (`pyproject.toml`)
- [ ] LICENSE 파일 확인
- [ ] GitHub 저장소 public으로 설정
- [ ] .gitignore 확인 (민감 정보 제외)

---

## 4. 문제 해결

### PyPI 업로드 실패
- 이름 충돌: 다른 이름 선택
- 버전 충돌: 버전 번호 증가 후 재빌드
- 인증 실패: API 토큰 재확인

### .deb 빌드 실패
- 의존성 부족: `debian/control` Dependencies 확인
- 권한 문제: `debian/rules`에 실행 권한 (`chmod +x debian/rules`)

---

## 5. 다음 릴리스 (v1.1.0)

향후 기능 추가 시:

1. 버전 번호 업데이트 (`pyproject.toml`, `debian/changelog`)
2. 패키지 재빌드 (`python -m build`, `dpkg-buildpackage`)
3. 업로드 (`twine upload dist/*`, GitHub Release)
