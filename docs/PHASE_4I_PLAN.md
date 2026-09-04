# Phase 4I 실행 계획 — EAPOL-Key M1~M4 메시지 순서 관찰

## 배경

기존 이벤트 타임라인은 `eapol_key_message_1`부터 `eapol_key_message_4`까지의 개별 이벤트를 표시합니다. 그러나 초급 엔지니어는 같은 단말·AP에서 어떤 메시지 번호가 어떤 순서로 관찰됐고, 일부 번호가 빠졌거나 반복됐는지를 다시 조합해야 합니다.

Phase 4I는 이미 비식별화된 이벤트와 현재 분석 실행의 `DEVICE-N`·`AP-N` 근거만 사용해 EAPOL-Key 메시지 번호의 관찰 순서를 정리합니다.

## 핵심 원칙

M1→M2→M3→M4가 모두 보이더라도 다음을 확정하지 않습니다.

```text
동일한 한 번의 4-Way Handshake
키 설치 성공
암호학적 검증 성공
전체 무선 접속 성공
장애 근본 원인
```

현재 단계에서는 Replay Counter를 사용하지 않습니다. 같은 메시지 번호가 반복돼도 실제 동일 교환의 재전송이라고 단정하지 않고 **메시지 번호 반복 관찰**로만 표현합니다.

## 입력 경계

Phase 4I는 다음 공개·비식별 결과만 사용합니다.

```text
EventTimeline
DeviceSessionReport
```

사용 값:

```text
EAPOL-Key 이벤트 종류
메시지 번호 1~4
프레임 번호
캡처 시작 기준 상대 시간
802.11 Retry 이벤트의 같은 프레임 여부
DEVICE-N
AP-N
```

사용하거나 출력하지 않는 값:

```text
원본 Ethernet·802.11 MAC 주소
BSSID·SSID
Replay Counter 원문
Nonce
MIC
Key Data
암호화 키
사용자명·EAP Identity
IP 주소·포트
절대 epoch
Raw Payload
캡처 파일명·절대경로
```

## EAPOL-Key 이벤트 검증

허용하는 이벤트는 다음 네 종류뿐입니다.

```text
eapol_key_message_1
eapol_key_message_2
eapol_key_message_3
eapol_key_message_4
```

각 이벤트는 다음 조건을 만족해야 합니다.

- 범주가 `eapol`
- `details.message_number`가 이벤트 이름의 번호와 일치
- `evidence_filter`가 해당 `frame.number`와 일치
- 프레임·상대 시간이 역순이 아님
- 동일 프레임에 Key 이벤트가 중복되지 않음

입력 불일치는 실패-폐쇄 처리합니다.

## 단말·AP 연결

Key 이벤트 프레임이 단말 가명 보고서의 보관된 근거 프레임에 포함될 때만 단말 후보가 됩니다.

연결 조건:

```text
해당 프레임의 DEVICE-N 후보가 정확히 1개
해당 DEVICE-N의 AP-N 후보가 정확히 1개
```

다음은 관찰에 포함하지 않습니다.

- 단말 후보 없음: `unassigned_key_events`
- 단말 후보 둘 이상: `ambiguous_key_events`
- 단말 AP 가명 없음 또는 둘 이상: `ambiguous_key_events`

시간 근접성만으로 단말이나 AP를 연결하지 않습니다.

현재 단말 가명 보고서는 단말별 AP 집합을 제공하므로, 로밍이 포함되어 AP가 둘 이상인 단말의 Key 이벤트는 보수적으로 모호 처리합니다. 프레임별 `DEVICE-N ↔ AP-N` 대응은 후속 단계에서 별도로 설계합니다.

## 단말 근거 보관 상한

단말별 공개 근거 프레임은 최대 64개입니다. `evidence_frames_omitted > 0`이면 보관되지 않은 프레임의 Key 이벤트를 완전히 연결할 수 없으므로:

```text
device_evidence_complete = false
complete = false
```

로 표시합니다. 보관된 일부 프레임만으로 전체 Handshake를 확정하지 않습니다.

## 관찰 창 분리

같은 `DEVICE-N ↔ AP-N`의 Key 이벤트를 프레임 순서로 정렬한 뒤 다음 규칙으로 관찰 창을 나눕니다.

- M4 뒤에 새 Key 메시지가 나오면 새 관찰 시작
- M2·M3 등 M1 이후 단계가 진행된 상태에서 새 M1이 나오면 기존 관찰 종료 후 새 관찰 시작
- M1만 반복되는 동안에는 같은 관찰에 유지

관찰 창 ID:

```text
EAPOL-HS-1
EAPOL-HS-2
```

Replay Counter를 사용하지 않으므로 이 경계는 패킷 관찰 창 구분일 뿐 동일한 실제 Handshake 경계를 확정하지 않습니다.

## 관찰 상태

| 상태 | 의미 |
|---|---|
| `sequence-observed` | 첫 관찰 순서가 M1→M2→M3→M4이며 번호 반복이 없음 |
| `message-repetition-observed` | M1→M2→M3→M4 첫 순서와 같은 번호 반복이 함께 관찰됨 |
| `out-of-order` | 메시지 번호가 이전 관찰 번호보다 작아지는 역순이 있음 |
| `incomplete` | M1~M4 중 일부만 관찰됨 |

예시:

```text
관찰 메시지: M1 → M2 → M3 → M3 → M4
첫 관찰 순서: M1 → M2 → M3 → M4
반복 메시지 번호: M3
상태: message-repetition-observed
```

반복된 프레임에 802.11 Retry 비트가 있으면 같은 프레임 번호를 별도로 제공합니다. Retry 비트와 메시지 번호 반복이 함께 있어도 Replay Counter가 없으므로 실제 재전송을 확정하지 않습니다.

## 결과

전체 보고서:

- 메시지 번호 필드 사용 가능 여부
- 타임라인·단말 보고서·단말 근거 완전성
- 전체 Key 이벤트 수
- 연결·미할당·모호 Key 이벤트 수
- 관찰 수와 상태별 개수
- 확정 금지 플래그와 주의사항

각 관찰:

- `EAPOL-HS-N`
- `DEVICE-N`, `AP-N`
- 상태와 한국어 설명
- 전체 관찰 메시지 번호
- 첫 관찰 번호 순서
- 미관찰 번호
- 반복 번호
- Retry 비트 관찰 프레임
- 첫·마지막 프레임과 상대 지속시간
- 근거 프레임과 Wireshark `frame.number` 필터

## 확정 금지 플래그

전체 보고서와 각 관찰에서 다음 값은 항상 `false`입니다.

```text
replay_counter_correlation_available
raw_key_material_serialized
raw_identifiers_serialized
same_handshake_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

## Portable 실제 패킷 검증

런타임에 Radiotap/IEEE 802.11 PCAP을 생성합니다.

```text
#1 802.11 Authentication Request
#2 802.11 Authentication Response
#3 Association Request
#4 Association Response
#5 EAPOL-Key M1
#6 EAPOL-Key M2
#7 EAPOL-Key M3
#8 Retry 비트가 있는 EAPOL-Key M3
#9 EAPOL-Key M4
```

최종 `WlanTroubleshooterKO.exe`를 다음 환경에서 실행합니다.

```text
PYTHONPATH 제거
PYTHONHOME 제거
PATH를 Windows 시스템 폴더로 제한
외부 Python 사용 불가
외부 Wireshark 사용 불가
```

필수 결과:

```text
field_available = true
source_key_events_total = 5
linked_key_events = 5
unassigned_key_events = 0
ambiguous_key_events = 0
observations_total = 1
DEVICE-1 ↔ AP-1
state = message-repetition-observed
observed_message_numbers = [1,2,3,3,4]
first_observed_order = [1,2,3,4]
repeated_message_numbers = [3]
retry_flag_frames = [8]
```

원본 MAC·BSSID, 합성 Nonce·MIC·Key Data, Replay Counter 원문, 절대 시각, 파일명과 경로가 결과에 없는지 검사합니다. 분석 전후 Portable 폴더 파일 목록도 같아야 합니다.

## 완료 기준

- Windows 전체 단위 테스트·자체 점검·소스 감사·저장소 감사 통과
- 기존 Finding·타임라인·거래·단말 가명·여정·관찰 가능성 게이트 유지
- 최종 Portable EAPOL-Key 실제 해석 게이트 통과
- GUI와 비대화형 JSON에 결과 제공
- `v0.11.0-alpha.1` Win64 Portable 프리릴리스 게시

## 다음 단계

1. Replay Counter 원문을 출력하지 않고 관계만 비교하는 상관분석
2. 로밍 환경을 위한 프레임별 비식별 `DEVICE-N ↔ AP-N` 링크
3. PCAPNG Interface Statistics Block과 드롭 카운터 활용
4. Radiotap RSSI·채널·데이터율·Retry 기반 RF 관찰
5. Aruba Controller·ClearPass 맞춤 점검 안내
6. 최종 오프라인 한국어 HTML 보고서
