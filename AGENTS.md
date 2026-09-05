# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선이며 범위를 임의로 넓히지 않습니다.

사용자는 개발을 계속 진행하고 각 작업 종료 시 남은 개발 항목을 반드시 보고하도록 지시했습니다.

## 현재 범위

현재 범위는 `docs/PHASE_4K_PLAN.md`의 **PCAPNG Interface Statistics Block 비식별 분석**입니다.

- 검증된 로컬 PCAPNG에서 표준 숫자 ISB Counter만 읽습니다.
- 실제 인터페이스 이름·설명 대신 `IFACE-N`을 사용합니다.
- 여러 ISB를 합산하지 않고 관찰 횟수·첫·마지막 값과 변화 방향만 제공합니다.
- 드롭 0·통계 부재를 무손실로 해석하지 않습니다.
- 양수 드롭을 특정 패킷 누락이나 RF·AP·단말·SPAN 장애로 확정하지 않습니다.
- 가짜 Counter·임시 성공값·근거 없는 책임 시스템 판정을 만들지 않습니다.

## 런타임 금지사항

- Python 3.13 표준 라이브러리와 `tkinter/ttk`만 제품 런타임에 사용합니다.
- AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, 온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 추가하지 않습니다.
- 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다.
- `struct`는 로컬 PCAPNG 이진 구조 해석에만 사용하며 네트워크 기능을 제공하지 않습니다.
- GitHub Actions의 공급망 다운로드는 제품 런타임과 분리합니다.

## 입력·캡처 검증 경계

입력은 기존 `validate_capture`로 검증된 로컬 `CaptureInfo`뿐입니다.

```text
로컬 절대경로
PCAP 또는 PCAPNG 형식
파일 크기
SHA-256
```

ISB 분석 전후에 `validate_capture`를 다시 실행하여 링크·재분석 지점·파일 정체성·형식·크기·SHA-256을 확인합니다. URL, 네트워크 공유, 실시간·원격 캡처는 사용하지 않습니다.

## PCAPNG 구조 검증

- SHB Byte-Order Magic으로 섹션별 엔디언을 결정합니다.
- 블록 앞·뒤 Total Length가 일치해야 합니다.
- 블록 길이는 4바이트 정렬이어야 합니다.
- 블록·옵션이 선언 경계를 벗어나면 거부합니다.
- ISB는 같은 섹션에서 먼저 선언된 Interface ID만 참조할 수 있습니다.
- 허용 Counter 옵션 길이는 정확히 8바이트여야 합니다.
- 같은 ISB의 동일 Counter 옵션 중복을 거부합니다.
- 옵션 패딩은 0이어야 합니다.
- 파일·블록·섹션·인터페이스·ISB·옵션 수에 상한을 적용합니다.
- 알 수 없는 블록·옵션은 구조만 검증하고 문자열을 디코딩하지 않습니다.

## 허용 Counter

```text
isb_ifrecv
isb_ifdrop
isb_filteraccept
isb_osdrop
isb_usrdeliv
```

다음 값은 결과에 기록하지 않습니다.

```text
인터페이스 이름·설명·GUID·장치 경로
하드웨어·운영체제·캡처 애플리케이션 문자열
캡처 필터와 PCAPNG 주석
ISB Timestamp·starttime·endtime
원본 MAC·BSSID·SSID
IP·포트·사용자명·호스트명
캡처 파일명·절대경로
```

## 상태와 변화 관계

상태:

```text
reported-drop-observed
zero-reported-drop-counters
statistics-without-drop-counters
no-interface-statistics
unsupported-capture-format
```

Counter 변화:

```text
not-reported
single-value-observed
counter-increase-observed
counter-decrease-observed
counter-unchanged-observed
```

다음 값은 항상 `false`입니다.

```text
raw_interface_identifiers_serialized
absolute_timestamps_serialized
capture_loss_excluded
specific_packet_loss_confirmed
root_cause_confirmed
```

## 기존 경계 유지

- `DEVICE-N`, `AP-N`은 현재 실행에서만 유효합니다.
- Replay Counter 원문은 전용 처리 후 관계로만 공개합니다.
- 동일 Handshake·실제 재전송·키 설치·암호학적 성공을 확정하지 않습니다.
- 응답 미관찰만으로 장애를 확정하지 않습니다.
- 캡처 시작·종료·무손실·양방향 수집은 증명되지 않습니다.

## TShark 실행 경계

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용합니다.
- 시스템 설치본·레지스트리·PATH 실행 파일로 대체하지 않습니다.
- 실행 파일과 종속 파일의 크기·SHA-256을 실행 전후 확인합니다.
- `shell=False`, stdin 비활성화, Windows 콘솔 숨김을 고정합니다.
- `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 승인된 fields만 허용합니다.
- 실시간·원격 캡처, 임의 extcap·Lua·필터·필드·사용자 옵션을 금지합니다.
- stderr 원문은 저장·표시하지 않습니다.
- 빈 config·plugin·extcap·data·temp 경로와 종료 후 무잔류를 유지합니다.

## 검증·릴리스

Windows 전체 테스트·자체 점검·소스 감사·저장소 감사와 Python·Wireshark 없는 Portable 실제 분석을 모두 통과해야 병합합니다.

Portable PCAPNG에는 다음을 포함합니다.

```text
SHB 1개
IDB 1개
Ethernet EPB 2개
ISB 2개
인터페이스·OS·하드웨어·앱·주석 문자열
원본 MAC·IP와 절대 Timestamp
```

기대 결과:

```text
IFACE-1
statistics_blocks=2
state=reported-drop-observed
ifrecv 2→4
ifdrop 0→3
osdrop 0→1
capture_loss_excluded=false
specific_packet_loss_confirmed=false
root_cause_confirmed=false
```

민감한 문자열·원본 주소·절대 시각·파일 경로가 최종 JSON에 없어야 합니다.

`v0.13.0-alpha.1`은 PCAPNG 인터페이스 통계 프리릴리스입니다. 캡처 무손실 증명기나 WLAN 근본 원인 분석기로 표현하지 않습니다.
