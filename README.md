# wlan-troubleshooter-ko

`wlan-troubleshooter-ko`는 Windows 11에서 로컬 PCAP·PCAPNG 파일을 분석해 무선 접속 절차의 확인 가능한 범위와 근거를 쉬운 한국어로 안내하기 위한 완전 오프라인 도구입니다.

주 사용자는 Wireshark와 무선 인증 절차에 익숙하지 않은 초급 네트워크 엔지니어입니다. 이 도구는 그럴듯한 원인을 만들어 내는 대신 실제로 관찰된 패킷 근거와 판단할 수 없는 영역을 분리하는 것을 목표로 합니다.

## 현재 개발 범위

- Phase 0: 저장소 기반, 아키텍처 결정, 데이터 반출 방지 정책, 정적 감사
- Phase 1: 최소 GUI, 입력 검증, 임시공간, 로그 마스킹, Portable TShark 실행 경계
- Phase 2A: PCAP·PCAPNG 구조, 인터페이스 Link Type, Snap Length, 패킷 잘림 여부와 형식상 분석 가능 범위 사전 점검

Phase 2A는 승인된 TShark가 없어도 동작합니다. 다만 Link Type은 특정 프로토콜이 실제로 포착됐다는 증거가 아니므로 EAP·RADIUS·DHCP·DNS·TCP 장애를 아직 판정하지 않습니다. 세부 범위는 `docs/PHASE_2A_PLAN.md`, 실제 상태는 `IMPLEMENTATION_STATUS.md`를 확인합니다.

## v0.2.0-alpha.1 프리뷰

첫 프리뷰 릴리즈는 Python 3.13이 필요한 소스 패키지입니다. 승인된 Portable TShark, Python 런타임, 설치 프로그램은 포함하지 않습니다. 최종 사용자용 Portable Windows 실행 파일이 아니라 캡처 사전 점검 기능을 검토하기 위한 개발자 프리뷰입니다.

릴리즈 워크플로는 Windows에서 전체 컴파일·테스트·감사를 다시 통과한 뒤에만 태그와 GitHub Release를 생성합니다.

## 고정 원칙

- AI, LLM, Ollama, MCP, 외부 API를 사용하지 않습니다.
- 런타임 외부 통신, 텔레메트리, 자동 업데이트, 온라인 조회를 제공하지 않습니다.
- 입력 파일을 업로드하거나 외부로 전송하지 않습니다.
- Python 3.13 표준 라이브러리만 런타임에 사용합니다.
- GUI는 `tkinter/ttk`를 사용합니다.
- 승인된 Portable TShark만 고정 해시 검증 후 사용할 수 있습니다.
- 시스템 설치 TShark나 `PATH` 실행 파일로 자동 대체하지 않습니다.
- 같은 입력과 같은 버전은 같은 정규화 결과를 만들어야 합니다.
- 패킷 부재를 장애 발생으로 해석하지 않습니다.
- TCP Retransmission만으로 RF 장애를 확정하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널·무선 Retry를 판단하지 않습니다.
- 원시 Payload, 쿠키, Authorization 값, 인증정보를 로그나 기본 보고서에 기록하지 않습니다.
- 실제 사내 PCAP, 사이트 프로파일, 사용자 정보, 장비 설정, 로그, 보고서를 공개 저장소에 커밋하지 않습니다.

## Phase 2A 화면의 의미

파일을 선택하면 다음을 로컬에서 점검합니다.

- PCAP 또는 PCAPNG 컨테이너 구조
- 바이트 순서와 인터페이스 수
- 인터페이스별 Link Type과 Snap Length
- 검사한 패킷 레코드 수
- 캡처 길이가 원본 길이보다 짧은 패킷의 관찰 수
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부
- 현재 형식에서 확인 가능한 항목과 확인할 수 없는 항목

Ethernet 캡처는 DHCP·DNS·TCP를 담을 수 있지만 Association·Deauthentication·RSSI를 보여 주지는 못합니다. Radiotap이 없는 IEEE 802.11 캡처는 관리 프레임을 담을 수 있어도 RSSI·채널 정보는 확인할 수 없습니다.

Phase 2A 결과는 **형식상 분석 가능성**이며 실제 장애 원인의 판정이 아닙니다.

## 저장소 구성

```text
wlan-troubleshooter-ko/
├─ src/wlan_troubleshooter_ko/   Python 애플리케이션과 분석 계층
├─ tests/                        합성 데이터 기반 단위 테스트
├─ scripts/                      정적 감사와 오프라인 검증 도구
├─ vendor/wireshark/             승인된 Portable TShark 배치 지점
├─ docs/adr/                     설계 결정
├─ docs/PHASE_2A_PLAN.md         현재 허용된 구현 범위
├─ RELEASE_NOTES.md              현재 프리뷰 릴리즈 설명
└─ IMPLEMENTATION_STATUS.md      실제 구현·검증 상태
```

## 개발 및 검증

### Windows PowerShell

```powershell
$env:PYTHONPATH = "src"
py -3.13 -m compileall -q src tests scripts
py -3.13 -m unittest discover -s tests -v
py -3.13 -m wlan_troubleshooter_ko --self-test
py -3.13 scripts/audit_source.py
py -3.13 scripts/audit_repository.py
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_offline.ps1
```

### 소스 프리뷰 실행

```powershell
$env:PYTHONPATH = "src"
py -3.13 -m wlan_troubleshooter_ko
```

테스트는 실행 중 임시 디렉터리에 최소 PCAP·PCAPNG 구조를 합성합니다. 실제 캡처는 저장소에 넣지 않습니다.

## Portable TShark 정책

TShark와 관련 DLL은 현재 소스 저장소와 프리뷰 릴리즈에 포함하지 않습니다. 승인된 배포본은 정해진 디렉터리에 넣고 버전·파일별 크기·SHA-256·라이선스 정보를 매니페스트로 고정해야 합니다. 매니페스트가 없거나 크기·해시가 다르면 실행하지 않습니다. 프로그램이나 빌드 스크립트가 인터넷에서 TShark를 자동 다운로드해서는 안 됩니다.

## 아직 지원하지 않는 기능

- 실제 EAP·RADIUS·DHCP·DNS·TCP 장애 판정
- AI 또는 자연어 생성 분석
- 실시간·원격 캡처
- 장비 로그인, 설정 조회, 설정 변경
- Payload, 파일, 자격 증명 추출
- 온라인 OUI·WHOIS·GeoIP 조회
- 설치형 Windows 실행 파일

프로젝트 자체 코드는 MIT 라이선스입니다. 향후 TShark 등 제3자 구성요소를 실제 배포하기 전에는 정확한 버전과 재배포 의무를 별도 문서와 배포물에 반영합니다.
