# Phase 4J 실행 계획 — EAPOL Replay Counter 비식별 관계 분석

## 목적

Phase 4I는 EAPOL-Key M1~M4의 메시지 번호 순서를 관찰합니다. Phase 4J는 Wireshark 4.6.8의 `eapol.keydes.replay_counter`를 별도 최소 프로파일에서만 일시적으로 읽어, 원문 숫자를 남기지 않고 메시지 사이의 관계만 제공합니다.

관계가 일반적인 형태와 일치하더라도 동일한 한 번의 Handshake, 실제 재전송, 키 설치, 암호학적 성공이나 장애 근본 원인을 확정하지 않습니다.

## 입력·실행 경계

전용 TShark 프로파일은 다음 세 필드만 허용합니다.

```text
frame.number
wlan_rsna_eapol.keydes.msgnr
eapol.keydes.replay_counter
```

Replay Counter 필드는 다음 경로에서 차단합니다.

```text
일반 프로토콜 인벤토리
공개 이벤트 타임라인
단말 가명화 프로파일
레거시 TShark 실행 경로
GUI·JSON·로그
```

전용 실행은 기존 분석과 같은 캡처 경로·형식·크기·SHA-256 및 같은 TShark 버전·매니페스트 SHA-256을 다시 확인합니다.

## 관계

### M1/M2

- `equal-observed`
- `mismatch-observed`
- `multiple-values-observed`
- `unavailable`
- `not-observed`

### M3/M4

동일한 상태를 사용합니다.

### M1→M3

- `increased-observed`
- `equal-observed`
- `decreased-observed`
- `multiple-values-observed`
- `unavailable`
- `not-observed`

### 반복 메시지

- `same-counter-observed`
- `different-counters-observed`
- `unavailable`

같은 메시지 번호와 같은 Counter 관계가 반복돼도 실제 동일 프레임 재전송으로 확정하지 않습니다.

## 관찰 상태

| 상태 | 의미 |
|---|---|
| `expected-relations-observed` | M1/M2·M3/M4 동일 및 M1→M3 증가 등 관찰 가능한 관계가 일반적 형태와 일치 |
| `relation-mismatch-observed` | 쌍 불일치, 후반 감소·동일 또는 반복 메시지의 다른 Counter 관계 관찰 |
| `multiple-values-observed` | 한 관찰 창에서 비교 기준을 하나로 정할 수 없는 여러 값 관계 |
| `partial` | 프레임 또는 Counter 일부 누락·근거 생략 |
| `insufficient-events` | 비교 가능한 메시지 쌍 부족 |
| `unavailable` | 내장 TShark에 필요한 필드가 없음 |

## 절대 확정 금지

다음 값은 전체 보고서와 각 관찰에서 항상 `false`입니다.

```text
raw_replay_counters_serialized
replay_counter_values_persisted
same_handshake_confirmed
retransmission_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

Counter 관계 불일치는 다음 가능성을 포함합니다.

```text
캡처 누락
여러 교환 혼재
관찰 창 분리 한계
AP·단말 재시도
비정상 메시지 흐름
```

따라서 키 설치 실패나 AP·단말·RF 장애로 자동 확정하지 않습니다.

## 개인정보·키 정보 보호

결과에 포함하지 않습니다.

```text
Replay Counter 원문 숫자
Nonce·MIC·Key Data
원본 MAC·BSSID·SSID
IP·포트·사용자명
암호화 키·자격 증명
절대 epoch
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

## Portable 실제 검증

Phase 4I의 Radiotap/IEEE 802.11 M1→M2→M3→반복 M3→M4 합성 패킷을 사용하되, Counter는 출력 누출 여부를 확인하기 쉬운 고유 64비트 값으로 교체합니다.

```text
M1 = 18446744073709551000
M2 = 18446744073709551000
M3 = 18446744073709551001
반복 M3 = 18446744073709551001
M4 = 18446744073709551001
```

기대 관계:

```text
M1/M2 = equal-observed
M3/M4 = equal-observed
M1→M3 = increased-observed
반복 M3 = same-counter-observed
state = expected-relations-observed
```

최종 JSON에는 위 숫자, 필드명, Nonce·MIC·Key Data와 원본 주소가 없어야 합니다. 외부 Python·Wireshark 없이 최종 EXE를 실행하며 분석 전후 Portable 폴더 무변경도 확인합니다.

## 완료 기준

- Windows 전체 테스트·자체 점검·소스 감사·저장소 감사 통과
- 전용 필드 정책에서 일반 경로의 Counter 원문 차단 확인
- Portable 실제 내장 TShark 관계 검증 통과
- GUI `[11. EAPOL Replay Counter 관계]`
- 기존 최상위 JSON 스키마 2 유지
- `v0.12.0-alpha.1` Win64 Portable 프리릴리스 게시

## 다음 단계

Phase 4J 다음에는 PCAPNG Interface Statistics Block과 캡처 도구 드롭 통계를 활용한 캡처 손실 관찰을 강화합니다. 이후 로밍·Radiotap RF 분석, Aruba·ClearPass 맞춤 안내와 오프라인 HTML 보고서를 진행합니다.
