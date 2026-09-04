# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 임의로 넓히지 않습니다.

사용자는 개발을 계속 진행하고, 각 작업 종료 시 남은 개발 항목을 반드시 보고하도록 지시했습니다.

## 현재 범위

현재 범위는 `docs/PHASE_4G_PLAN.md`의 **캡처 관찰 가능성과 미응답 해석 경계**입니다.

- Phase 4F까지의 Finding·거래·단말 가명·여정 결과를 보존합니다.
- 요청이 보이고 응답이 보이지 않는 상황을 확정 장애로 표현하지 않습니다.
- 구조·이벤트·거래 완전성과 캡처 경계·잘림·상세 생략을 구분합니다.
- 파일 전체 처리는 장애 구간 전체 포함, 양방향 수집과 무손실을 뜻하지 않습니다.
- 초급 엔지니어가 Wireshark 근거 프레임을 다시 확인할 수 있게 합니다.
- 가짜 응답·임시 성공값·근거 없는 책임 시스템 판정을 만들지 않습니다.

## 기술과 런타임 금지사항

- Python 3.13 표준 라이브러리와 `tkinter/ttk`만 제품 런타임에 사용합니다.
- AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, 온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 추가하지 않습니다.
- 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다.
- GitHub Actions의 공급망 다운로드는 제품 런타임과 분리하며 다운로드 코드를 애플리케이션에 넣지 않습니다.

## TShark 실행 경계

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용합니다.
- 시스템 설치본, 레지스트리와 PATH 실행 파일로 대체하지 않습니다.
- 실행 파일과 종속 파일의 크기·SHA-256을 실행 전후 확인합니다.
- 자식 프로세스 생성은 `tshark/runner.py`의 검토된 단일 함수만 허용합니다.
- `shell=False`, stdin 비활성화와 Windows 콘솔 숨김을 고정합니다.
- `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 고정 fields 출력만 허용합니다.
- 실시간 `-i`, rpcap, TCP@호스트, 임의 extcap·Lua·필터·필드·사용자 옵션을 금지합니다.
- stdout·stderr를 동시에 읽고 크기·시간 상한을 적용합니다.
- stderr 원문은 저장·표시하지 않습니다.
- 호출마다 빈 config·plugin·extcap·data·temp 경로를 만들고 종료 후 무잔류를 확인합니다.

## 입력과 개인정보 경계

Phase 4G 모델은 다음 이미 공개 가능한 결과만 사용합니다.

```text
CaptureStructure
EventTimeline
TransactionSessionReport
```

다음 값은 모델·GUI·JSON·로그에 기록하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 거래 ID·Stream 번호
HMAC 키와 내부 토큰
절대 epoch
Raw Payload·파일·쿠키·Authorization·자격 증명
캡처 파일명·절대경로
TShark stderr 원문
```

## 분석 입력 완전성

`analysis_input_complete=true`는 다음 조건을 모두 만족할 때만 허용합니다.

```text
CaptureStructure.scan_complete = true
EventTimeline.complete = true
TransactionSessionReport.complete = true
EventTimeline.events_omitted = 0
구조 패킷 수 = 이벤트 분석 프레임 수
타임라인 이벤트 수 = 거래 보고서 이벤트 수
```

이 값이 true여도 캡처 시작·종료·무손실·양방향 수집은 증명되지 않습니다.

## 미완료 거래 평가

- `response-not-observed`: 완전한 분석 입력의 중간 프레임 범위에서 최종 응답 미관찰
- `capture-boundary-risk`: 거래가 첫 프레임 또는 마지막 관찰 프레임에 닿음
- `packet-truncation-risk`: 잘린 패킷으로 상위 필드 누락 가능성
- `insufficient-analysis-input`: 일부 처리·이벤트 생략·거래 근거 생략

우선순위는 다음과 같습니다.

```text
불완전 입력
→ 패킷 잘림
→ 캡처 경계
→ 응답 미관찰
```

## 절대 판정 경계

다음 값은 항상 `false`입니다.

```text
capture_start_proven
capture_end_proven
capture_loss_excluded
directionality_proven
absence_can_confirm_failure
absence_is_failure
```

- 요청·응답 계열 이벤트가 모두 보여도 모든 방향 수집으로 확정하지 않습니다.
- 응답 미관찰을 ClearPass·AD·DHCP·DNS·방화벽·서버·RF 장애로 확정하지 않습니다.
- 거래가 파일 경계에 닿으면 캡처 전·후 패킷 가능성을 명시합니다.
- 잘린 패킷이 있으면 직접 인과관계를 확정하지 않고 필드 누락 가능성만 표시합니다.
- 근거가 부족하면 `판단 불가` 또는 위험 상태가 우선입니다.

## 기존 단말 여정 경계 유지

- `DEVICE-N`, `AP-N`은 현재 실행에서만 유효합니다.
- 단일 L2 근거로 이미 `linked`된 거래만 단말 여정에 포함합니다.
- RADIUS처럼 단말 근거가 없는 거래를 시간으로 연결하지 않습니다.
- 첫 실패 관찰 단계는 근본 원인 위치가 아닙니다.
- `device_identity_confirmed=false`
- `cross_protocol_session_confirmed=false`
- `root_cause_confirmed=false`

## Windows 격리 디렉터리

실행 후 디렉터리 객체 교체는 장치 ID, 파일 ID/inode, 객체 종류, 링크 수와 Reparse Point 비트로 확인합니다. TShark 임시파일 사용으로 정상 변경되는 크기·mtime·ctime·Archive는 교체 판단에서 제외합니다. Symlink·Junction·Reparse Point와 실행 후 잔류 파일은 계속 거부합니다.

## 자원 제한

- 프로파일 처리 최대 100,000프레임
- 상세 이벤트 최대 2,000건
- 거래 시도 최대 50,000개
- 거래 근거 프레임 최대 64개
- 단말 여정 근거 최대 96개
- TShark stdout 64MiB, stderr 1MiB, 기본 실행 180초

## 검증과 릴리스

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 통합검증을 수행합니다.

Portable 관찰 가능성 게이트는 런타임 생성 4프레임 PCAP을 사용합니다.

```text
#1 ARP Request
#2 DNS Query — 중간 프레임, 응답 미관찰
#3 ARP Reply
#4 DNS Query — 마지막 프레임, 응답 미관찰
```

예상 결과:

```text
DNS-1-A1 = response-not-observed
DNS-2-A1 = capture-boundary-risk
DNS-2-A1 risk = capture-end-boundary-risk
absence_is_failure = false
absence_can_confirm_failure = false
```

Python·Wireshark가 없는 환경에서 최종 EXE로 검증하고 식별정보·경로·절대 시간 비노출과 배포 폴더 무변경을 확인합니다.

`v0.10.0-alpha.1`은 캡처 관찰 가능성과 미응답 해석 프리릴리스입니다. 응답 미관찰을 실제 장애로 확정하는 제품으로 표현하지 않습니다. 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
