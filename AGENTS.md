# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 임의로 넓히지 않습니다.

사용자는 개발을 계속 진행하고, 각 작업 종료 시 남은 개발 항목을 반드시 보고하도록 지시했습니다.

## 현재 범위

현재 범위는 `docs/PHASE_4F_PLAN.md`의 **단말 가명별 접속 관찰 여정**입니다.

- Phase 4E의 분석 실행별 `DEVICE-N`·`AP-N` 가명만 사용합니다.
- Phase 4D의 EAP·RADIUS·DHCP·DNS·TCP 거래 시도를 단말 가명별로 집계합니다.
- Phase 4E가 단일 L2 근거로 이미 `linked`한 거래만 여정에 포함합니다.
- 실제 근거 프레임 순서로 관찰 단계를 표시합니다.
- 첫 실패 관찰 단계와 마지막 성공 방향 단계를 구분합니다.
- RADIUS처럼 단말 근거가 없는 거래를 시간 근접성으로 연결하지 않습니다.
- 동일 사용자 신원, 하나의 완전한 교차 프로토콜 세션과 근본 원인을 확정하지 않습니다.
- 가짜 패킷 결과, 임시 성공값과 근거 없는 원인을 만들지 않습니다.

## 기술과 런타임 금지사항

- Python 3.13 표준 라이브러리와 `tkinter/ttk`만 제품 런타임에 사용합니다.
- AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, 온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 추가하지 않습니다.
- 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다.
- GitHub Actions의 공급망 다운로드는 제품 런타임과 분리하며 다운로드 코드를 애플리케이션에 넣지 않습니다.

## TShark 실행 경계

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용합니다.
- 시스템 설치본, 레지스트리와 PATH 실행 파일로 대체하지 않습니다.
- 실행 파일과 모든 종속 파일의 크기·SHA-256을 실행 전후 확인합니다.
- 자식 프로세스 생성은 `tshark/runner.py`의 검토된 단일 함수만 허용합니다.
- `shell=False`, stdin 비활성화와 Windows 콘솔 숨김을 고정합니다.
- `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 고정 fields 출력만 허용합니다.
- 실시간 `-i`, rpcap, TCP@호스트, 임의 extcap·Lua·필터·필드·사용자 옵션을 금지합니다.
- stdout·stderr를 동시에 읽고 크기·시간 상한을 적용합니다.
- stderr 원문은 저장·표시하지 않습니다.
- 호출마다 빈 config·plugin·extcap·data·temp 경로를 만들고 종료 후 무잔류를 확인합니다.

## Windows 격리 디렉터리 정체성

실행 후 디렉터리 객체 교체 여부는 장치 ID, 파일 ID/inode, 객체 종류, 링크 수와 Reparse Point 비트로 확인합니다.

TShark가 임시파일을 생성·삭제하면서 정상 변경할 수 있는 크기·mtime·ctime·Archive 등 일반 메타데이터는 교체 판단에서 제외합니다. Symlink·Junction·Reparse Point와 실행 후 잔류 파일은 계속 거부합니다.

## Phase 4F 입력 경계

단말 여정 모델은 다음 이미 비식별화된 결과만 받습니다.

```text
transaction_sessions
device_sessions
```

허용 가명:

```text
DEVICE-N
AP-N
EAP-N-AN
RADIUS-N-AN
DHCP-N-AN
DNS-N-AN
TCP-N-AN
```

다음 값은 여정 모델·GUI·기본 JSON·로그에 기록하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 EAP·RADIUS·DHCP·DNS 거래 ID
원본 TCP·UDP Stream 번호
HMAC 키와 HMAC 내부 토큰
절대 epoch
Raw Payload·파일·쿠키·Authorization·자격 증명
캡처 파일명·절대경로
TShark 표준 오류 원문
```

## 여정 연결 규칙

거래는 다음 조건을 모두 만족할 때만 `DEVICE-N` 여정에 들어갑니다.

- Phase 4E 연결 상태 `linked`
- 단말 후보가 정확히 하나
- 연결 근거 프레임과 원 거래 근거가 정확히 일치
- 근거 프레임이 비어 있지 않음
- 근거 프레임 생략 수가 0
- 단말의 `linked_attempt_ids`와 연결 객체가 정확히 일치

다음 거래는 여정에서 제외합니다.

- `unassigned`
- `ambiguous`
- 생략된 근거가 있는 거래
- 연결 객체와 원 거래 근거가 다른 거래
- 잘못되거나 중복된 가명·거래 ID

생략된 거래가 Phase 4E 연결용 임시 복사본에서 빈 근거와 미연결 상태로 정제된 경우에만 분석을 계속합니다. 생략 거래가 단말에 연결되거나 연결 근거를 유지하면 실패-폐쇄 처리합니다.

## 판정 안전성

- 단계·여정 상태는 실제 패킷 관찰 결과입니다.
- 첫 실패 관찰 단계는 근본 원인 위치가 아닙니다.
- 마지막 성공 방향 단계는 전체 접속 성공을 뜻하지 않습니다.
- RADIUS처럼 단말 근거가 없는 거래를 시간으로 연결하지 않습니다.
- 성공 방향과 실패가 함께 있으면 `mixed`로 표시합니다.
- 혼재 단계도 성공 방향 응답이 실제 존재하면 마지막 성공 방향 단계 후보로 유지합니다.
- TCP SYN/SYN-ACK만으로 3-Way Handshake 완료를 확정하지 않습니다.
- TCP 재전송만으로 RF·서버·방화벽 장애를 확정하지 않습니다.
- 프로토콜·응답 미관찰을 장애로 해석하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널을 판단하지 않습니다.
- 근거가 부족하면 미연결 또는 판단 불가가 우선입니다.

다음 값은 항상 `false`입니다.

```text
raw_identifiers_serialized
alias_secret_persisted
aliases_stable_across_runs
device_identity_confirmed
cross_protocol_session_confirmed
root_cause_confirmed
```

## 자원 제한

- 단말 가명 최대 20,000개
- 거래 시도 최대 50,000개
- 원 거래 근거 프레임 최대 64개
- 단계·여정 근거 프레임 최대 96개
- 이벤트·패킷·stdout·stderr·실행시간 상한 유지

## 검증과 릴리스

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 통합검증을 수행합니다.

최종 Portable은 Python 환경변수와 일반 Python PATH를 제거한 상태에서 런타임 생성 Ethernet PCAP을 분석해 다음을 확인해야 합니다.

- `DEVICE-1` EAP·DHCP·DNS·TCP 관찰 단계
- EAP·DHCP·DNS 완료 거래
- TCP 성공 방향 거래와 별도 RST 실패 거래의 `mixed` 단계
- 첫 실패 관찰 단계 TCP
- 마지막 성공 방향 단계 TCP
- 단말 근거 없는 RADIUS 거래의 여정 제외
- 개인정보·가명화 키·절대 시간 비노출
- 모든 신원·세션·근본 원인 확정 플래그 `false`
- 분석 전후 Portable 폴더 무변경

`v0.9.0-alpha.1`은 단말 가명별 관찰 여정 프리릴리스입니다. 동일 사용자 신원이나 완성형 WLAN 근본 원인 분석기로 표현하지 않습니다. 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
