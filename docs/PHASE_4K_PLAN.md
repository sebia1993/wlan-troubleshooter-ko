# Phase 4K 실행 계획 — PCAPNG Interface Statistics Block 관찰

## 목적

Phase 4K는 PCAPNG의 Interface Statistics Block(ISB, Block Type 5)을 로컬에서 직접 해석하여 캡처 도구가 기록한 인터페이스별 통계 카운터를 한국어로 제공합니다.

드롭 카운터가 없거나 0이라고 해서 캡처 손실이 없었다고 확정하지 않습니다. 0보다 큰 드롭 카운터가 있어도 특정 장애 패킷이 누락됐거나 해당 드롭이 장애 원인이라고 확정하지 않습니다.

## 입력 경계

기존 bounded PCAPNG 컨테이너 스캐너에서 다음 블록만 추가 해석합니다.

```text
Interface Statistics Block = 0x00000005
```

ISB 고정 본문:

```text
Interface ID       32-bit
Timestamp High     32-bit
Timestamp Low      32-bit
Options             32-bit aligned
```

지원 옵션:

```text
isb_starttime       code 2, length 8
isb_endtime         code 3, length 8
isb_ifrecv          code 4, length 8
isb_ifdrop          code 5, length 8
isb_filteraccept    code 6, length 8
isb_osdrop          code 7, length 8
isb_usrdeliv        code 8, length 8
```

원본 인터페이스 이름·설명·운영체제 정보는 읽거나 결과에 기록하지 않습니다.

## 결과 모델

각 ISB를 다음과 같은 관찰 객체로 유지합니다.

```text
section_index
interface_id
observation_index
counter_state
ifrecv
ifdrop
filteraccept
osdrop
usrdeliv
start_time_present
end_time_present
block_timestamp_present
absolute_timestamps_serialized = false
capture_loss_excluded = false
root_cause_confirmed = false
```

동일 인터페이스에 여러 ISB가 있으면 각각 별도 관찰로 유지합니다. 카운터가 누적값일 수 있으므로 블록 간 값을 단순 합산하지 않습니다.

GUI에서는 실제 인터페이스 이름 대신 분석 실행 내 표시용 별칭을 사용합니다.

```text
IFACE-1
IFACE-2
```

별칭은 Section Index와 Interface ID를 정렬한 순서로 결정하며 원본 이름을 의미하지 않습니다.

## Counter 상태

| 상태 | 의미 |
|---|---|
| `reported-drop-observed` | `ifdrop` 또는 `osdrop` 중 하나 이상이 0보다 큼 |
| `zero-reported-drop-counters` | 드롭 카운터가 하나 이상 제공됐고 제공된 값이 모두 0임 |
| `statistics-without-drop-counters` | ISB는 있지만 `ifdrop`·`osdrop` 옵션이 없음 |
| `no-interface-statistics` | 전체 캡처에 ISB가 없음 |

다음 해석은 금지합니다.

```text
ifdrop = 0 → 캡처 무손실
osdrop = 0 → 커널·드라이버 드롭 없음
ISB 없음 → 캡처 손실 없음
드롭 증가 → 특정 EAPOL·DHCP·DNS 패킷 누락 확정
드롭 증가 → RF·AP·단말 장애 확정
```

## 옵션 검증

- 모든 옵션은 32-bit padding 경계를 검증합니다.
- 카운터·시간 옵션은 길이 8일 때만 해석합니다.
- 길이가 다르면 값을 사용하지 않고 안전 경고를 남깁니다.
- 동일 ISB 안에서 같은 지원 옵션이 중복되면 실패-폐쇄 처리합니다.
- End-of-Options(code 0)는 길이 0이어야 합니다.
- 정의되지 않은 Interface ID를 참조한 ISB는 카운터를 연결하지 않고 경고합니다.
- ISB 최소 전체 길이는 24바이트입니다.
- 기존 최대 블록 길이·최대 레코드 수·취소 경계를 유지합니다.

## 시간 값 경계

ISB Timestamp, `isb_starttime`, `isb_endtime`의 원본 값은 절대 시간일 수 있으므로 공개 결과에 숫자를 기록하지 않습니다.

Phase 4K에서는 존재 여부만 제공합니다.

```text
block_timestamp_present
start_time_present
end_time_present
absolute_timestamps_serialized = false
```

상대 지속시간 변환은 인터페이스별 `if_tsresol`과 `if_tsoffset`까지 함께 검증하는 후속 단계에서 추가합니다.

## 개인정보·데이터 반출 방지

다음 값을 GUI·JSON·로그·릴리스 자산에 기록하지 않습니다.

```text
인터페이스 이름·설명
운영체제 문자열
원본 MAC·BSSID·SSID
IP 주소·포트·사용자명·호스트명
절대 타임스탬프
캡처 파일명·절대경로
Raw Payload
TShark stderr 원문
```

ISB 해석은 Python 표준 라이브러리로 로컬 파일을 읽으며 TShark·네트워크·외부 API·AI를 추가로 사용하지 않습니다.

## 자동 검증

### 단위 테스트

- Little-endian·Big-endian ISB
- `ifrecv`, `ifdrop`, `filteraccept`, `osdrop`, `usrdeliv` 해석
- 0보다 큰 드롭 → `reported-drop-observed`
- 제공된 드롭 값이 모두 0 → `zero-reported-drop-counters`
- 드롭 옵션 없음 → `statistics-without-drop-counters`
- ISB 없음 → 캡처 전체 `no-interface-statistics`
- 여러 인터페이스·여러 Section의 관찰 분리
- 동일 인터페이스 여러 ISB 비합산
- 정의되지 않은 Interface ID 경고
- 잘못된 옵션 길이 경고 및 값 미사용
- 중복 지원 옵션 거부
- 옵션 padding·블록 trailing length 검증
- 결정론적 직렬화와 인터페이스 이름·절대 시간 비노출

### Portable 실제 검증

런타임에 다음 PCAPNG를 생성합니다.

```text
Section Header Block
Interface Description Block: Ethernet
Enhanced Packet Block 2개
Interface Statistics Block 1개
```

ISB 합성 값:

```text
ifrecv = 2
ifdrop = 3
filteraccept = 2
osdrop = 1
usrdeliv = 2
```

최종 EXE 기대 결과:

```text
IFACE-1
counter_state = reported-drop-observed
ifrecv = 2
ifdrop = 3
filteraccept = 2
osdrop = 1
usrdeliv = 2
capture_loss_excluded = false
root_cause_confirmed = false
absolute_timestamps_serialized = false
```

Python·Wireshark가 없는 PATH에서 실행하고 캡처 경로·인터페이스 이름·절대 시간 비노출 및 분석 전후 Portable 폴더 무변경을 확인합니다.

## 완료 기준

- Windows 전체 테스트·자체 점검·소스 감사·저장소 감사 통과
- PCAPNG ISB bounded parser와 한국어 GUI 결과 제공
- 기존 분석 JSON 최상위 `schema_version = 2` 유지
- 기존 Finding·거래·DEVICE-N·EAPOL·Replay Counter 관계 게이트 유지
- Portable 실제 PCAPNG ISB 검증 통과
- 다음 프리릴리스 게시

## 다음 단계

1. PCAP·PCAPNG 패킷 타임스탬프의 첫→마지막 상대 시간 범위
2. `if_tsresol`·`if_tsoffset`을 포함한 ISB 시작·종료 상대 지속시간
3. 캡처 경계와 미응답 거래의 대기시간 결합
4. 프레임별 비식별 `DEVICE-N ↔ AP-N` 연결과 로밍 관찰
5. Radiotap RSSI·채널·데이터율 기반 RF 관찰
6. Aruba·ClearPass 맞춤 점검 안내
7. 오프라인 단일 HTML 보고서
