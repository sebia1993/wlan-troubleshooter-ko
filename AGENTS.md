# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 임의로 넓히지 않습니다.

사용자는 개발을 계속 진행하고, 각 작업 종료 시 남은 개발 항목을 반드시 보고하도록 지시했습니다.

## 현재 범위

현재 범위는 `docs/PHASE_4I_PLAN.md`의 **EAPOL-Key M1~M4 메시지 순서 관찰**입니다.

- 기존 캡처 사전 점검·Finding·타임라인·거래·단말 가명·여정·관찰 가능성 결과를 보존합니다.
- 이미 비식별화된 이벤트와 `DEVICE-N`·`AP-N` 근거만 사용합니다.
- M1~M4 첫 관찰 순서, 미관찰 번호, 번호 반복과 같은 프레임 Retry 비트를 표시합니다.
- 메시지 번호 순서를 동일 Handshake·키 설치·암호학적 성공으로 승격하지 않습니다.
- Replay Counter·Nonce·MIC·Key Data를 제품 결과에 추가하지 않습니다.
- 가짜 키 교환 결과, 임시 성공값과 근거 없는 원인을 만들지 않습니다.

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

## Phase 4I 입력 경계

사용 입력:

```text
EventTimeline
DeviceSessionReport
```

허용 값:

```text
eapol_key_message_1~4
wlan_retry_flag
frame_number
relative_time_ms
DEVICE-N
AP-N
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
Replay Counter 원문
Nonce·MIC·Key Data
암호화 키
절대 epoch
Raw Payload·파일·쿠키·Authorization·자격 증명
캡처 파일명·절대경로
TShark stderr 원문
```

## 이벤트·근거 검증

- 이벤트 종류는 `eapol_key_message_1`부터 `eapol_key_message_4`만 허용합니다.
- `details.message_number`가 이벤트 이름의 번호와 일치해야 합니다.
- 이벤트 범주는 `eapol`이어야 합니다.
- 근거 필터는 해당 `frame.number`와 일치해야 합니다.
- 프레임과 상대 시간이 역순이면 거부합니다.
- 동일 프레임의 Key 이벤트 중복을 거부합니다.
- 단말 가명 보고서의 원문 직렬화·키 저장·실행 간 별칭 고정 플래그가 `false`가 아니면 거부합니다.

## 단말·AP 연결 규칙

Key 이벤트는 다음 조건을 모두 만족할 때만 관찰에 포함합니다.

```text
이벤트 프레임이 DEVICE-N의 보관 근거에 포함
해당 프레임의 DEVICE-N 후보가 정확히 1개
해당 DEVICE-N의 AP-N 후보가 정확히 1개
```

- 단말 후보 없음: 미할당
- 단말 후보 둘 이상: 모호
- AP 후보 없음 또는 둘 이상: 모호
- 시간 근접성만으로 단말·AP 연결 금지
- 단말 근거 프레임이 일부 생략되면 전체 완료 금지

로밍으로 한 단말의 AP 가명이 둘 이상이면 현재 단계에서는 보수적으로 모호 처리합니다. 프레임별 비식별 DEVICE/AP 링크는 후속 Phase에서 설계합니다.

## 관찰 창과 상태

관찰 창 분리:

- M4 뒤 새 Key 메시지: 새 관찰
- M1 이후 단계가 진행된 상태에서 새 M1: 기존 관찰 종료 후 새 관찰
- M1만 반복: 같은 관찰 유지

상태:

```text
sequence-observed
message-repetition-observed
out-of-order
incomplete
```

메시지 번호 반복과 Retry 비트가 함께 보여도 Replay Counter 관계가 없으므로 실제 동일 Handshake 재전송으로 확정하지 않습니다.

## 절대 판정 경계

다음 값은 항상 `false`입니다.

```text
replay_counter_correlation_available
raw_key_material_serialized
raw_identifiers_serialized
same_handshake_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

M1→M2→M3→M4가 모두 보여도 전체 무선 접속 성공이나 근본 원인을 확정하지 않습니다.

기존 Phase 4G 경계도 유지합니다.

```text
capture_start_proven = false
capture_end_proven = false
capture_loss_excluded = false
directionality_proven = false
absence_can_confirm_failure = false
```

## 자원 제한

- 프로파일 처리 최대 100,000프레임
- 상세 이벤트 최대 2,000건
- 거래 시도 최대 50,000개
- 단말·AP 가명 각각 최대 20,000개
- EAPOL-Key 이벤트 최대 20,000개
- EAPOL 관찰 최대 10,000개
- 관찰 근거 프레임 최대 64개
- TShark stdout 64MiB, stderr 1MiB, 기본 실행 180초

## 검증과 릴리스

Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 통합검증을 수행합니다.

Portable 합성 캡처:

```text
Authentication Request/Response
Association Request/Response
M1
M2
M3
Retry 비트가 있는 반복 M3
M4
```

필수 결과:

```text
DEVICE-1 ↔ AP-1
state = message-repetition-observed
observed_message_numbers = [1,2,3,3,4]
first_observed_order = [1,2,3,4]
repeated_message_numbers = [3]
retry_flag_frames = [8]
```

Python·Wireshark가 없는 환경에서 최종 EXE로 검증하고 원본 식별정보·키 정보·절대 시간 비노출과 배포 폴더 무변경을 확인합니다.

`v0.11.0-alpha.1`은 EAPOL-Key 메시지 번호 순서 관찰 프리릴리스입니다. 4-Way Handshake 성공 분석기로 표현하지 않으며 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
