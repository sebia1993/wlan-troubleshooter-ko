# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 전송하지 않고 로컬에서 점검하여, 초급 네트워크 엔지니어에게 확인 가능한 범위와 근거를 쉬운 한국어로 안내하는 도구입니다.

AI로 원인을 생성하지 않습니다. 입력 파일을 업로드하지 않으며 런타임 외부 통신, 텔레메트리, 자동 업데이트, 온라인 조회를 포함하지 않습니다.

## 가장 쉬운 실행 방법

`v0.3.0-alpha.1` 릴리즈에서 다음 파일을 받습니다.

```text
WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip
```

1. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
2. 압축을 푼 폴더의 `WlanTroubleshooterKO.exe`를 실행합니다.
3. `PCAP 또는 PCAPNG 파일 선택`을 누릅니다.
4. 캡처 유형, 인터페이스, 패킷 잘림과 분석 가능 범위를 확인합니다.

ZIP 안에서 EXE를 바로 실행하지 않습니다. Python, Wireshark, Node.js, 관리자 권한과 인터넷 연결은 필요하지 않습니다.

## Portable 패키지에 포함되는 것

```text
WlanTroubleshooterKO.exe       사용자 프로그램
_internal/                     내장 Python 3.13·Tcl/Tk 런타임
vendor/wireshark/tshark.exe    내장 Wireshark 패킷 해석 엔진
vendor/wireshark/manifest.json TShark 파일 무결성 목록
licenses/                      Python·Tcl·Tk·PyInstaller 라이선스
BUILD_INFO.json                빌드 버전·공급망 정보
```

TShark는 공식 Wireshark 4.6.8 x64 MSI에서 추출합니다. 빌드 서버는 MSI의 Authenticode 서명과 고정 SHA-256을 확인하고, 최종 패키지의 모든 TShark 파일을 별도 매니페스트로 봉인합니다. 사용자 PC에서는 다운로드나 설치를 하지 않습니다.

## 현재 가능한 기능

- PCAP·PCAPNG 형식과 기본 구조 검사
- 다중 Section·다중 인터페이스 PCAPNG 처리
- Link Type과 Snap Length 확인
- 잘린 패킷과 불완전 스캔 경고
- Radiotap·IEEE 802.11·Ethernet·PPI의 보수적 분류
- 현재 캡처에서 확인 가능한 항목과 확인할 수 없는 항목 안내
- TShark 필드 카탈로그·고정 필드 프로파일·프로토콜 인벤토리 정규화 기반
- 내장 Python과 TShark의 실행·무결성 빌드 검증

## 아직 지원하지 않는 기능

- EAP·RADIUS·DHCP·DNS·TCP의 실제 성공·실패 판정
- 4-Way Handshake와 로밍 장애 판정
- 최종 한국어 장애 Finding과 HTML 보고서
- 실시간·원격 캡처
- 장비 로그인·조회·설정 변경
- Payload·쿠키·Authorization·자격 증명·파일 추출
- 온라인 OUI·WHOIS·GeoIP 조회

현재 릴리즈는 **실행 가능한 캡처 사전 점검 프리뷰**입니다. 프로토콜이 보였다는 사실은 접속 성공을 뜻하지 않고, 보이지 않았다는 사실도 장애 증거가 아닙니다.

## 데이터 반출 방지 원칙

- AI·LLM·Ollama·MCP·외부 API 없음
- HTTP·소켓·DNS 조회·수신 포트 없음
- 텔레메트리·오류 자동 전송·자동 업데이트 없음
- 시스템 TShark와 `PATH` 자동 대체 없음
- 실시간 캡처용 `dumpcap.exe`와 Wireshark GUI를 Portable 패키지에서 제거
- TShark 실행 시 이름 해석 비활성화와 빈 설정·플러그인·extcap 환경 사용
- 실제 사내 PCAP·프로파일·로그·보고서를 공개 저장소에 커밋하지 않음

## SHA-256 확인

릴리즈에는 Portable ZIP과 같은 이름의 `.sha256` 파일이 함께 제공됩니다.

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

출력된 값이 `.sha256` 파일의 값과 일치하는지 확인합니다. 현재 애플리케이션 EXE 자체의 상용 코드 서명 인증서는 구성되지 않았으므로 Windows에서 `알 수 없는 게시자` 경고가 표시될 수 있습니다.

## 개발 검증

```powershell
$env:PYTHONPATH = "src"
py -3.13 -m compileall -q src tests scripts
py -3.13 -m unittest discover -s tests -v
py -3.13 -m wlan_troubleshooter_ko --self-test
py -3.13 scripts/audit_source.py
py -3.13 scripts/audit_repository.py
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_offline.ps1
```

Portable 빌드는 공식 Wireshark 파일과 PyInstaller 패키지를 내려받으므로 GitHub Actions 빌드 단계에서만 네트워크를 사용합니다. 생성된 프로그램 런타임에는 다운로드 코드가 포함되지 않습니다.

세부 배포 설계는 `docs/PHASE_3_PORTABLE_PLAN.md`, 실제 검증 상태는 `IMPLEMENTATION_STATUS.md`, 제3자 고지는 `THIRD_PARTY_NOTICES.md`를 확인합니다.
