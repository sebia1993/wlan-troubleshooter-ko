# Phase 4K 실행 계획 — PCAPNG Interface Statistics Block 비식별 분석

## 목적

PCAPNG Interface Statistics Block(ISB)을 로컬에서 직접 해석해 캡처 도구가 보고한 인터페이스별 수신·드롭 Counter를 한국어로 제공합니다.

드롭 Counter가 없거나 0이라고 해서 캡처 손실이 없었다고 확정하지 않습니다. 양수 드롭 Counter가 있어도 특정 장애 패킷이 누락됐거나 RF·AP·단말·SPAN이 원인이라고 확정하지 않습니다.

## 입력·실행 경계

입력은 기존 `validate_capture`를 통과한 로컬 `CaptureInfo`뿐입니다.

```text
로컬 절대경로
PCAP 또는 PCAPNG 형식
파일 크기
SHA-256
```

ISB 분석 전후에 `validate_capture`를 다시 실행하여 링크·재분석 지점·파일 정체성·형식·크기·SHA-256이 기존 값과 같은지 확인합니다.

ISB 해석은 Python 표준 라이브러리로 수행합니다. TShark·AI·외부 API·네트워크 통신을 추가로 사용하지 않습니다. 따라서 내장 TShark가 없는 소스 실행 모드에서도 PCAPNG 통계 보고서를 제공합니다.

## 해석 구조

필요한 PCAPNG 블록:

```text
Section Header Block           0x0A0D0D0A
Interface Description Block    0x00000001
Interface Statistics Block     0x00000005
```

지원하는 표준 unsigned 64-bit Counter 옵션:

| 옵션 | 코드 |
|---|---:|
| `isb_ifrecv` | 4 |
| `isb_ifdrop` | 5 |
| `isb_filteraccept` | 6 |
| `isb_osdrop` | 7 |
| `isb_usrdeliv` | 8 |

ISB Timestamp, `isb_starttime`, `isb_endtime`과 문자열 옵션은 공개 결과에 기록하지 않습니다.

## 구조 검증

- SHB Byte-Order Magic으로 섹션별 little/big-endian을 결정합니다.
- 블록 앞·뒤 Total Length가 일치해야 합니다.
- 블록 길이는 4바이트 정렬이어야 합니다.
- 블록·옵션이 파일 또는 블록 경계를 벗어나면 거부합니다.
- ISB는 같은 섹션에서 먼저 선언된 Interface ID만 참조할 수 있습니다.
- 지원 Counter 옵션 길이는 정확히 8바이트여야 합니다.
- 같은 ISB의 동일 Counter 옵션 중복을 거부합니다.
- 옵션 패딩은 0이어야 합니다.
- 파일·블록·섹션·인터페이스·ISB·옵션 수에 상한을 적용합니다.
- 알 수 없는 블록·옵션은 구조만 확인하고 내용을 직렬화하지 않습니다.

## 인터페이스 가명

IDB 선언 순서로 다음 표시 가명을 만듭니다.

```text
IFACE-1
IFACE-2
```

`section_index`와 숫자 `interface_id`는 PCAPNG 내부 참조 위치이며 실제 인터페이스 이름·GUID·장치 경로가 아닙니다. 실제 문자열 식별자는 출력하지 않습니다.

## 여러 ISB 처리

Counter는 누적 스냅샷일 수 있으므로 ISB 값을 합산하지 않습니다. Counter별로 다음만 제공합니다.

```text
observations
first_value
last_value
progression
```

변화 상태:

```text
not-reported
single-value-observed
counter-increase-observed
counter-decrease-observed
counter-unchanged-observed
```

Counter 감소는 초기화·재시작·wrap·여러 수집 상태 가능성을 포함합니다. 어느 하나로 확정하지 않습니다.

## 드롭 상태

```text
reported-drop-observed
zero-reported-drop-counters
statistics-without-drop-counters
no-interface-statistics
unsupported-capture-format
```

- `reported-drop-observed`: `ifdrop` 또는 `osdrop`에서 양수 값 관찰
- `zero-reported-drop-counters`: 드롭 Counter가 있고 관찰값이 모두 0
- `statistics-without-drop-counters`: ISB는 있으나 드롭 Counter 옵션 없음
- `no-interface-statistics`: PCAPNG에 ISB가 없음
- `unsupported-capture-format`: 일반 PCAP

## 절대 판정 경계

다음 값은 항상 `false`입니다.

```text
raw_interface_identifiers_serialized
absolute_timestamps_serialized
capture_loss_excluded
specific_packet_loss_confirmed
root_cause_confirmed
```

금지하는 자동 결론:

```text
ifdrop=0 또는 osdrop=0 → 캡처 무손실
ISB 없음 → 캡처 무손실
양수 드롭 → 특정 EAPOL·DHCP·DNS·TCP 패킷 누락
양수 드롭 → RF·AP·단말·SPAN 장애
Counter 감소 → 초기화·재시작·wrap 확정
```

## 개인정보·메타데이터 보호

GUI·JSON·로그·릴리스 자산에 다음 값을 기록하지 않습니다.

```text
인터페이스 이름·설명·GUID·장치 경로
하드웨어·운영체제·캡처 애플리케이션 문자열
캡처 필터
Section·Interface·Packet·Statistics 주석
ISB Timestamp·starttime·endtime
원본 MAC·BSSID·SSID
IP 주소·포트·사용자명·호스트명
절대 epoch
Raw Payload
캡처 파일명·절대경로
```

## 단위 검증

- little-endian 두 ISB와 양수 드롭
- big-endian 0 드롭 Counter
- ISB 있으나 드롭 옵션 없음
- PCAPNG에 ISB 없음
- 일반 PCAP 비적용 상태
- 다중 섹션·Interface ID 재시작·전역 `IFACE-N`
- 증가·감소·변화 없음·단일 Counter 관찰
- 선언되지 않은 Interface ID 거부
- 중복 Counter 옵션 거부
- 8바이트가 아닌 Counter 거부
- 앞·뒤 Total Length 불일치 거부
- 옵션 padding 오류 거부
- 분석 취소
- 분석 전후 캡처 변경 거부
- 민감 문자열·절대 시각·경로 비노출
- TShark 실패 시 독립 통계 보고서 보존

## Portable 실제 검증

런타임 생성 PCAPNG:

```text
SHB 1개
IDB 1개
Ethernet EPB 2개
ISB 2개
```

첫 ISB:

```text
ifrecv=2
ifdrop=0
filteraccept=2
osdrop=0
usrdeliv=2
```

둘째 ISB:

```text
ifrecv=4
ifdrop=3
filteraccept=4
osdrop=1
usrdeliv=4
```

기대 공개 결과:

```text
IFACE-1
statistics_blocks=2
state=reported-drop-observed
ifrecv first=2 last=4 progression=counter-increase-observed
ifdrop first=0 last=3 progression=counter-increase-observed
osdrop first=0 last=1 progression=counter-increase-observed
capture_loss_excluded=false
specific_packet_loss_confirmed=false
root_cause_confirmed=false
```

fixture에는 인터페이스 이름·설명, 하드웨어, 운영체제, 캡처 애플리케이션, 패킷·통계 주석, 절대 시작·종료 시각과 원본 MAC·IP를 넣습니다. 최종 JSON에서 하나라도 발견되면 검증을 실패시킵니다.

외부 Python·Wireshark를 사용할 수 없는 PATH에서 최종 EXE를 실행하고 분석 전후 Portable 폴더 무변경도 확인합니다.

## 완료 기준

- Windows 전체 테스트·자체 점검·소스 감사·저장소 감사 통과
- Python·Wireshark 미설치 Portable 실제 PCAPNG 분석 통과
- GUI `[12. PCAPNG 인터페이스 통계]`
- 최상위 분석 JSON `schema_version = 2` 유지
- 기존 Finding·DEVICE-N·미응답·EAPOL·Replay 관계 게이트 유지
- `v0.13.0-alpha.1` Win64 Portable 프리릴리스 게시

## 다음 단계

1. PCAP·PCAPNG 첫→마지막 패킷 상대 시간 범위
2. `if_tsresol`·`if_tsoffset`과 ISB 상대 시간
3. 캡처 경계와 미응답 거래의 관찰 시간 결합
4. 프레임별 비식별 `DEVICE-N ↔ AP-N` 연결과 로밍 관찰
5. Radiotap RSSI·채널·데이터율 기반 RF 관찰
6. Aruba·ClearPass 맞춤 점검 안내
7. 오프라인 단일 HTML 보고서
