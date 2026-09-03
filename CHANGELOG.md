# 변경 기록

## 0.3.0-alpha.1 — 2026-09-04

### 추가

- Python 미설치 Windows 11 PC용 PyInstaller `onedir` GUI 실행 파일
- 공식 Wireshark 4.6.8 x64 기반 내장 TShark 런타임
- Wireshark MSI Authenticode 서명과 고정 SHA-256 검증
- 전체 TShark 파일 목록·크기·SHA-256 매니페스트
- Python 경로를 제거한 상태의 EXE 자체 점검
- 내장 TShark `-n -v`와 `-n -G fields` 빌드 Smoke Test
- Python·Tcl·Tk·PyInstaller·Wireshark 라이선스 파일
- Portable ZIP·ZIP SHA-256·정확한 Wireshark 소스 아카이브 릴리즈 자동화

### 보안

- `tshark.exe` 이외의 Wireshark 실행 파일과 extcap·Npcap·plugin 디렉터리를 Portable 패키지에서 제거
- 최종 패키지의 실행 파일을 `WlanTroubleshooterKO.exe`와 `vendor/wireshark/tshark.exe` 두 개로 제한
- 빌드 입력 URL·버전·해시를 저장소 고정값으로 제한
- 런타임 외부 통신, AI, 텔레메트리, 자동 업데이트 없음

### 제한

- 애플리케이션 EXE의 상용 코드 서명 인증서는 아직 없음
- 실제 EAP·RADIUS·DHCP·DNS·TCP 장애 판정은 아직 지원하지 않음
- 현재 UI는 캡처 구조와 분석 가능 범위의 프리뷰임

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서·프로토콜 인벤토리 정규화 기반

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
