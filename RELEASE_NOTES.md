# v0.11.0-alpha.1 — EAPOL-Key M1~M4 메시지 순서 관찰 프리뷰

이번 릴리스는 기존 캡처 품질·Finding·비식별 거래·`DEVICE-N` 여정·미응답 해석에 **EAPOL-Key M1~M4 메시지 번호 순서 관찰**을 추가합니다.

Python과 Wireshark를 별도로 설치할 필요가 없습니다. AI·LLM·외부 API·인터넷 조회·텔레메트리·자동 업데이트도 사용하지 않습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.11.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- EAPOL-Key M1·M2·M3·M4 번호 순서 관찰
- 같은 메시지 번호의 반복 관찰
- 같은 프레임의 802.11 Retry 비트 표시
- 미관찰 메시지 번호 표시
- 메시지 번호 역순 관찰
- 진행 중 새 M1과 M4 이후 새 메시지의 관찰 창 분리
- `EAPOL-HS-N` 로컬 관찰 번호
- `DEVICE-N ↔ AP-N` 비식별 근거
- 첫·마지막 프레임, 상대 지속시간과 Wireshark `frame.number` 필터
- GUI `[10. EAPOL 4-Way Handshake 메시지 순서]`
- 기존 최상위 JSON `schema_version = 2`를 유지하는 `eapol_handshakes` 추가 결과

## 관찰 상태

| 상태 | 의미 |
|---|---|
| `sequence-observed` | M1→M2→M3→M4 첫 순서가 관찰되고 번호 반복이 없음 |
| `message-repetition-observed` | M1→M2→M3→M4 첫 순서와 같은 번호 반복이 함께 관찰됨 |
| `out-of-order` | 메시지 번호가 이전 번호보다 작아지는 역순이 관찰됨 |
| `incomplete` | M1~M4 중 일부만 관찰됨 |

예시:

```text
EAPOL-HS-1 · DEVICE-1 ↔ AP-1
관찰 메시지: M1 → M2 → M3 → M3 → M4
첫 관찰 순서: M1 → M2 → M3 → M4
반복 메시지 번호: M3
Retry 비트 관찰 프레임: #8
상태: message-repetition-observed
```

## 단말·AP 연결 경계

EAPOL-Key 이벤트는 다음 조건에서만 관찰에 포함됩니다.

```text
Key 이벤트 프레임이 DEVICE-N의 공개 근거 프레임에 포함됨
해당 프레임의 단말 후보가 정확히 1개
해당 DEVICE-N의 AP-N 후보가 정확히 1개
```

다음은 관찰에 포함하지 않습니다.

- 단말 후보 없음
- 단말 후보 둘 이상
- AP 가명 없음 또는 둘 이상
- 단말 근거 프레임 일부 생략으로 확인할 수 없는 이벤트

시간 근접성만으로 단말이나 AP를 연결하지 않습니다. 로밍이 포함되어 한 단말의 AP 가명이 둘 이상이면 현재 단계에서는 보수적으로 모호 처리합니다.

## 메시지 반복과 Retry 비트

같은 M3가 반복되고 두 번째 M3 프레임에 802.11 Retry 비트가 있어도 실제 같은 Handshake의 재전송이라고 확정하지 않습니다.

현재는 Replay Counter를 사용하지 않으므로 다음 표현만 허용합니다.

```text
같은 메시지 번호 반복 관찰
같은 프레임에서 Retry 비트 관찰
```

## 확정하지 않는 항목

M1→M2→M3→M4가 모두 보여도 다음 값은 항상 `false`입니다.

```text
replay_counter_correlation_available
raw_key_material_serialized
raw_identifiers_serialized
same_handshake_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

따라서 이 결과는 다음을 의미하지 않습니다.

- 동일한 한 번의 4-Way Handshake 확정
- 키 설치 성공 확정
- MIC·Nonce 검증 성공 확정
- 전체 무선 접속 성공 확정
- AP·단말·ClearPass 중 근본 원인 확정

## 개인정보·키 정보 보호

Phase 4I 모델은 이미 비식별화된 다음 값만 사용합니다.

```text
EAPOL-Key 이벤트 종류
메시지 번호 1~4
프레임 번호
상대 시간
DEVICE-N
AP-N
같은 프레임의 Retry 이벤트
```

다음 값은 GUI·JSON·로그·릴리스 자산에 포함하지 않습니다.

```text
원본 MAC·BSSID·SSID
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
TShark stderr 원문
```

## Portable 실제 통합검증

릴리스 빌드는 런타임에 다음 Radiotap/IEEE 802.11 PCAP을 생성합니다.

```text
#1 Authentication Request
#2 Authentication Response
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

동시에 다음을 검사합니다.

- 합성 MAC·BSSID 비노출
- Nonce·MIC·Key Data 비노출
- Replay Counter 원문 비노출
- 절대 시각·파일명·경로 비노출
- 모든 Handshake·키 설치·암호학적 성공·근본 원인 확정 플래그 `false`
- 분석 전후 Portable 배포 폴더 무변경

기존 Finding, 이벤트 타임라인, 거래 시도, 단말·AP 가명, 단말 여정과 캡처 관찰 가능성 실제 패킷 게이트도 함께 통과해야 릴리스됩니다.

## 호환성

기존 분석 JSON의 최상위 `schema_version = 2`를 유지합니다. `eapol_handshakes`는 기존 결과를 변경하지 않는 추가 항목입니다.

## 아직 지원하지 않는 기능

- Replay Counter 관계를 이용한 동일 교환 상관분석
- 로밍 단말의 프레임별 비식별 `DEVICE-N ↔ AP-N` 연결
- PCAPNG Interface Statistics Block·실제 드롭 카운터 활용
- 응답 미관찰을 실제 미응답으로 확정
- Radiotap RSSI·채널·데이터율 기반 RF 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 단일 오프라인 한국어 HTML 보고서
- 실제 사내 Aruba·ClearPass 캡처 검증
- 애플리케이션 EXE 상용 코드 서명

## 릴리스 자산

- `WlanTroubleshooterKO-v0.11.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.11.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
