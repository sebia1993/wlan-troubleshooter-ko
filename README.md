# wlan-troubleshooter-ko

`wlan-troubleshooter-ko`는 Windows 11에서 로컬 PCAP·PCAPNG 파일을 분석해 무선 접속 절차의 확인 가능한 범위와 근거를 쉬운 한국어로 안내하기 위한 완전 오프라인 도구입니다.

주 사용자는 Wireshark와 무선 인증 절차에 익숙하지 않은 초급 네트워크 엔지니어입니다. 이 도구는 그럴듯한 원인을 만들어 내는 대신, 실제로 관찰된 패킷 근거와 판단할 수 없는 영역을 분리하는 것을 목표로 합니다.

## 현재 개발 범위

현재 작업은 Phase 0과 Phase 1에만 한정됩니다.

- Phase 0: 저장소 기반, 아키텍처 결정 기록, 데이터 반출 방지 정책, 정적 감사 기반을 구축합니다.
- Phase 1: Python 3.13 표준 라이브러리와 `tkinter/ttk`로 최소 실행 화면, 입력 파일 기초 검증, 안전한 임시 작업공간, 로그 마스킹, 결정론적 JSON 기반, Portable TShark 실행 정책의 경계를 구축합니다.

Phase 2에 해당하는 실제 프로토콜 이벤트 추출, 장애 규칙 판정, 완성형 HTML 보고서, Windows 패키징은 시작하지 않습니다. 구현 상태는 `IMPLEMENTATION_STATUS.md`를 기준으로 확인합니다.

## 고정 원칙

- AI, LLM, Ollama, MCP, 외부 API를 사용하지 않습니다.
- 런타임 외부 통신, 텔레메트리, 자동 업데이트, 온라인 조회를 제공하지 않습니다.
- 입력 파일을 업로드하거나 외부로 전송하지 않습니다.
- Python 3.13 표준 라이브러리만 런타임에 사용합니다.
- GUI는 `tkinter/ttk`를 사용합니다.
- 승인된 Portable TShark만 고정 해시 검증 후 사용할 수 있습니다.
- 시스템에 설치된 TShark나 `PATH`의 실행 파일로 자동 대체하지 않습니다.
- 같은 입력, 같은 규칙 버전, 같은 TShark 버전은 같은 정규화 결과를 만들어야 합니다.
- 모든 판단은 근거 프레임과 재현 가능한 Wireshark Display Filter로 추적할 수 있어야 합니다.
- 근거가 부족하거나 충돌하면 `판단 불가`로 처리합니다.
- 원시 Payload, 쿠키, Authorization 값, 인증정보를 로그나 기본 보고서에 기록하지 않습니다.
- 실제 사내 PCAP, 사이트 프로파일, 사용자 정보, 장비 설정, 로그, 보고서를 저장소에 커밋하지 않습니다.

## 현재 화면의 의미

Phase 1의 화면은 오프라인 안전 기반을 확인하기 위한 최소 골격입니다. 파일을 선택할 수 있더라도 실제 WLAN 장애 분석이 구현되었다는 뜻은 아닙니다. 승인된 TShark 번들이 없거나 검증되지 않은 경우 프로그램은 준비되지 않은 상태를 분명히 표시하고 실패를 숨기지 않아야 합니다.

## 저장소 구성

```text
wlan-troubleshooter-ko/
├─ src/wlan_troubleshooter_ko/   Python 애플리케이션과 버전 고정 리소스
├─ tests/                        합성 데이터 기반 단위 테스트
├─ scripts/                      정적 감사와 오프라인 검증 도구
├─ vendor/wireshark/             승인된 Portable TShark 배치 지점
├─ docs/adr/                     변경하기 어려운 설계 결정
├─ CODEX_IMPLEMENTATION_PLAN.md  단계별 구현 기준
├─ IMPLEMENTATION_STATUS.md      실제 구현·검증 상태
└─ AGENTS.md                     저장소 작업 규칙
```

## 개발 환경

- Python 3.13
- Windows 11이 최종 대상 운영체제입니다.
- macOS에서 수행한 테스트는 로컬 호환성 검사일 뿐 Windows 검증으로 간주하지 않습니다.
- Windows 호환성은 저장소의 GitHub Actions `windows-latest` 작업 결과로 별도 확인합니다.

런타임 의존성은 없습니다. 개발 및 검증 명령은 저장소 루트에서 실행합니다.

### macOS 또는 리눅스

```bash
PYTHONPATH=src python3.13 -m compileall -q src tests scripts
PYTHONPATH=src python3.13 -m unittest discover -s tests -v
PYTHONPATH=src python3.13 -m wlan_troubleshooter_ko --self-test
python3.13 scripts/audit_source.py
python3.13 scripts/audit_repository.py
```

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

구현 단계에 따라 일부 명령은 해당 파일이 추가된 뒤 사용할 수 있습니다. 실제 통과 여부와 미검증 범위는 `IMPLEMENTATION_STATUS.md`에 기록합니다.

## 테스트 데이터 정책

저장소에는 실제 PCAP·PCAPNG를 넣지 않습니다. Phase 0·1 테스트는 실행 중 임시 디렉터리에 생성한 최소 헤더 바이트와 합성 JSON만 사용합니다. 이후 공개 테스트 캡처가 필요해도 출처, 재배포 허가, 개인정보 제거, 해시를 검토하고 별도 승인받기 전에는 추가하지 않습니다.

## Portable TShark 정책

TShark와 관련 DLL은 이 초기 소스 저장소에 포함하지 않습니다. 승인된 배포본은 정해진 디렉터리에 넣고 버전·파일별 크기·SHA-256·라이선스 정보를 매니페스트로 고정해야 합니다. 매니페스트가 없거나 크기·해시가 다르면 실행하지 않습니다. 프로그램이나 빌드 스크립트가 인터넷에서 TShark를 자동 다운로드해서는 안 됩니다.

Phase 1에서 허용되는 TShark 실행은 캡처를 열지 않는 고정 `-n -v` 준비 확인뿐입니다. 필드 추출용 고정 인자는 검증해 준비할 수 있지만 실제 캡처 필드 추출은 실행하지 않습니다.

TShark 격리 루트에는 기존 임시 디렉터리를 넘기지 않습니다. `AnalysisWorkspace`가
소유한 공간에서 `allocate("tshark-isolation")`으로 받은 아직 존재하지 않는 하위
경로만 넘기며, 실행 경계가 빈 설정·플러그인·extcap·데이터·임시 디렉터리를 배타적으로
만듭니다. 호출자는 상위 `AnalysisWorkspace`를 종료해 이 트리를 함께 정리합니다.

## 보안 경계

이 프로그램은 저장된 로컬 캡처를 읽는 도구입니다. 다음 기능은 지원하지 않습니다.

- 실시간 또는 원격 캡처
- 장비 로그인, 설정 조회, 설정 변경
- 수신 대기 포트와 로컬 HTTP 서버
- 임의 명령줄 옵션과 임의 Lua 스크립트
- Payload, 파일, 자격 증명 추출
- 외부 리소스나 JavaScript가 포함된 보고서

PCAP은 신뢰할 수 없는 입력으로 취급합니다. 원본은 수정하지 않고, 임시 산출물은 정상 종료·오류·취소 시 모두 정리해야 합니다.

UNC 경로와 심볼릭 링크·Windows 재분석 지점은 거부합니다. 운영체제 API만으로 로컬 볼륨과 동일하게 보이는 매핑 네트워크 드라이브는 Phase 1에서 완전히 식별할 수 없으므로, 실제 배포 환경에서는 매핑 드라이브 금지 정책과 방화벽 차단을 별도로 검증해야 합니다.

## 라이선스와 출처

프로젝트 자체 코드는 MIT 라이선스로 배포합니다. 비교 대상 프로젝트의 소스나 자산은 복사하지 않고 공개된 개념만 독립적으로 구현합니다. 향후 TShark 등 제3자 구성요소를 실제로 묶어 배포하기 전에는 해당 버전의 라이선스와 재배포 의무를 `THIRD_PARTY_NOTICES.md`와 배포물에 반영해야 합니다.
