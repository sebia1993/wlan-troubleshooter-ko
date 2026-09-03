# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 전송하지 않고 로컬에서 분석하여, 초급 네트워크 엔지니어에게 확인된 사실과 확인할 수 없는 범위를 쉬운 한국어로 안내하는 도구입니다.

AI로 원인을 생성하지 않습니다. 프로그램 런타임에는 외부 API, 인터넷 통신, 텔레메트리, 자동 업데이트와 온라인 조회가 없습니다.

## 가장 쉬운 실행 방법

`v0.4.0-alpha.1` 릴리즈에서 다음 파일을 받습니다.

```text
WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip
```

1. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
2. 압축을 푼 폴더의 `WlanTroubleshooterKO.exe`를 실행합니다.
3. `PCAP 또는 PCAPNG 파일 선택`을 누릅니다.
4. 캡처 구조와 프로토콜 존재 인벤토리를 확인합니다.

ZIP 안에서 EXE를 바로 실행하지 않습니다. Python, Wireshark, Node.js, 관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 이번 버전에서 실제로 분석하는 내용

먼저 PCAP·PCAPNG 구조를 검사합니다.

- 캡처 형식과 바이트 순서
- 인터페이스 수와 Link Type
- Snap Length
- 패킷 레코드 수
- 잘린 패킷과 일부 스캔 여부
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부

그다음 내장 TShark를 실제 캡처에 실행해 다음 프로토콜 그룹의 **존재 프레임 수**를 집계합니다.

| 그룹 | 초급자용 의미 |
|---|---|
| Radiotap | RSSI·채널 같은 무선 메타데이터를 담을 수 있는 헤더 |
| IEEE 802.11 | 무선 LAN 관리·제어·데이터 프레임 |
| EAPOL | 802.1X 시작과 키 교환 |
| EAP | 사용자·단말 인증 대화 |
| RADIUS | ClearPass 등 인증 서버 통신 |
| DHCP | IP 주소 할당 |
| DNS | 이름 조회 |
| ARP | 같은 네트워크의 IP·MAC 대응 확인 |
| TCP | 연결형 통신 |
| TLS | 암호화 연결 |
| ICMP | Ping과 네트워크 오류 알림 |
| QUIC | UDP 기반 암호화 연결 |

각 그룹에 대해 관찰된 프레임 수와 처음·마지막 프레임 번호를 표시합니다.

## 반드시 알아야 할 결과 의미

```text
RADIUS 관찰됨 ≠ 인증 성공
RADIUS 미관찰 ≠ ClearPass 장애
DHCP 관찰됨 ≠ IP 할당 성공
TCP 관찰됨 ≠ 서비스 정상
프로토콜 미관찰 ≠ 해당 단계 장애
```

현재 결과는 **프로토콜 존재 인벤토리**입니다. 장애 원인 판정이 아닙니다. 캡처 위치·시간·방향 때문에 필요한 패킷이 보이지 않을 수 있습니다.

## 데이터 보호

Phase 4A 추출 필드는 다음 다섯 개로 제한됩니다.

```text
frame.number
frame.interface_id  선택 필드
frame.cap_len
frame.len
frame.protocols
```

다음 정보는 추출하거나 결과에 기록하지 않습니다.

```text
IP·MAC·SSID·BSSID
호스트명·DNS 질의명
사용자명·RADIUS User-Name
Raw Payload
쿠키·Authorization·자격 증명
원본 파일명·절대경로
```

TShark 표준 오류 원문도 화면과 로그에 표시하지 않습니다.

## 실행 안전장치

- 프로젝트에 포함된 고정 TShark만 사용
- 전체 TShark 파일의 크기·SHA-256을 실행 전후 검증
- 캡처의 형식·크기·SHA-256을 실행 전후 검증
- `-n`으로 네트워크 이름 해석 비활성화
- 실시간·원격 캡처와 사용자 임의 옵션 차단
- 빈 설정·플러그인·extcap·임시 디렉터리 사용
- stdout·stderr 동시 처리로 교착 방지
- 출력 크기·실행시간·패킷 수 상한
- 분석 취소 지원
- 종료 후 임시 작업공간 자동 삭제

## Portable 패키지 구성

```text
WlanTroubleshooterKO.exe       사용자 프로그램
_internal/                     내장 Python 3.13·Tcl/Tk 런타임
vendor/wireshark/tshark.exe    내장 Wireshark 4.6.8 패킷 해석 엔진
vendor/wireshark/manifest.json TShark 전체 파일 무결성 목록
licenses/                      Python·Tcl·Tk·PyInstaller 라이선스
BUILD_INFO.json                버전·공급망·인벤토리 활성 상태
```

Portable 패키지에는 Wireshark GUI, `dumpcap.exe`, Npcap 설치 파일과 extcap 실행 도구가 없습니다.

## SHA-256 확인

릴리즈에는 Portable ZIP과 같은 이름의 `.sha256` 파일이 제공됩니다.

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

출력값이 `.sha256` 파일의 값과 같은지 확인합니다. 애플리케이션 EXE의 상용 코드 서명 인증서는 아직 없으므로 Windows가 `알 수 없는 게시자` 경고를 표시할 수 있습니다.

## 아직 지원하지 않는 기능

- EAP·RADIUS 인증 성공·실패 상관분석
- DHCP Discover–Offer–Request–ACK 판정
- DNS 요청·응답·오류 판정
- TCP 연결·RST·재전송 장애 판정
- 4-Way Handshake와 로밍 중단 분석
- 장애 원인별 한국어 Finding과 조치 안내
- 최종 오프라인 HTML 보고서
- 실시간·원격 캡처
- 장비 로그인·조회·설정 변경
- 온라인 OUI·WHOIS·GeoIP 조회

세부 구현 경계는 `docs/PHASE_4A_PLAN.md`, 실제 검증 상태는 `IMPLEMENTATION_STATUS.md`, 제3자 고지는 `THIRD_PARTY_NOTICES.md`를 확인합니다.
