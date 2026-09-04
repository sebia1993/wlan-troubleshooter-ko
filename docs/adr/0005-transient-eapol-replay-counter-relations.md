# ADR 0005 — EAPOL Replay Counter는 전용 관계 분석에서만 일시 사용한다

- 상태: 승인
- 날짜: 2026-09-05
- 관련 Phase: 4J

## 배경

Phase 4I는 EAPOL-Key M1~M4 메시지 번호와 802.11 Retry 비트를 비식별 관찰로 제공합니다. 그러나 메시지 번호만으로는 다음 상황을 구분하기 어렵습니다.

```text
M1과 M2가 일반적인 같은 Counter 관계인지
M3과 M4가 일반적인 같은 Counter 관계인지
M1에서 M3로 Counter가 증가했는지
반복 메시지에서 같은 Counter 관계가 보이는지
```

Replay Counter는 암호화 키나 사용자 신원은 아니지만, 원문 숫자를 일반 이벤트·GUI·JSON에 추가하면 불필요한 상관 식별자와 장기 보관 값이 됩니다. 또한 Counter 관계만으로 하나의 실제 Handshake나 재전송을 확정할 수 없습니다.

## 결정

Wireshark 4.6.8의 다음 필드는 Phase 4J 전용 프로파일에서만 허용합니다.

```text
eapol.keydes.replay_counter
```

전용 프로파일 전체 필드는 다음 세 개뿐입니다.

```text
frame.number
wlan_rsna_eapol.keydes.msgnr
eapol.keydes.replay_counter
```

원문 Counter는 다음 순서로 처리합니다.

1. 기존 분석과 같은 캡처 형식·크기·SHA-256인지 확인한다.
2. 기존 분석과 같은 TShark 버전·매니페스트 SHA-256인지 확인한다.
3. 전용 격리 작업공간에서 고정 필드만 추출한다.
4. 각 `EAPOL-HS-N`의 근거 프레임과 메시지 번호가 일치하는지 확인한다.
5. 원문 숫자를 같음·증가·감소·불일치 관계로 변환한다.
6. 원문 텍스트와 정수 참조를 가능한 한 빨리 해제한다.
7. 관계와 근거 프레임만 GUI·JSON에 제공한다.

## 허용 결과

```text
M1/M2 = equal-observed
M3/M4 = mismatch-observed
M1→M3 = increased-observed
반복 M3 = same-counter-observed
```

## 금지 결과

```text
Replay Counter 원문 숫자
Counter 기반 장기 장치 식별자
Nonce
MIC
Key Data
암호화 키
Raw Payload
동일 Handshake 확정
실제 재전송 확정
키 설치 성공 확정
암호학적 성공 확정
근본 원인 확정
```

다음 플래그는 항상 `false`입니다.

```text
raw_replay_counters_serialized
replay_counter_values_persisted
same_handshake_confirmed
retransmission_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

## 프로파일 격리

Replay Counter 원문 필드는 다음 경로에서 거부합니다.

```text
protocol-inventory
connection-events
device-identities
레거시 build_analysis_argv
사용자 임의 필드
```

메시지 번호 필드가 현재 TShark에 없으면 Counter 필드가 존재하더라도 Counter 단독 추출을 하지 않습니다. 이 경우 관계 분석은 `unavailable`로 표시합니다.

## 메모리 경계

Python은 문자열과 정수 메모리의 확정적인 zeroization을 보장하지 않습니다. 따라서 다음을 보장하지 않습니다.

```text
실행 중 메모리 포렌식에 대한 원문 완전 비노출
```

현재 보장 범위는 다음과 같습니다.

```text
디스크에 원문 Counter 미저장
로그에 원문 Counter 미기록
GUI·JSON에 원문 Counter 미직렬화
릴리스 자산에 원문 Counter 미포함
외부 네트워크로 원문 Counter 미전송
```

## 대안

### Counter를 전혀 사용하지 않는다

개인정보 경계는 단순하지만 M1/M2·M3/M4 관계와 반복 메시지 관계를 구분할 수 없습니다.

### 일반 이벤트 타임라인에 Counter를 추가한다

구현은 간단하지만 모든 분석 결과에 원문 값을 노출하고 저장하게 되어 채택하지 않습니다.

### Counter를 해시하거나 가명화한다

실행별 관계 비교는 가능하지만 원문에서 파생된 불필요한 토큰을 결과에 남기며, 증가·감소 관계를 직접 표현할 수 없어 채택하지 않습니다.

## 결과

- 전용 TShark 실행 한 번이 추가되어 분석 시간이 늘어납니다.
- 원문 Counter는 메모리에서 일시적으로 존재합니다.
- 관계 결과는 초급 엔지니어가 이해하기 쉬우며 원문 숫자를 노출하지 않습니다.
- 관계가 일반적인 형태와 일치해도 Handshake 성공 판정으로 승격하지 않습니다.
- 관계 불일치가 보여도 AP·단말·RF·ClearPass 근본 원인으로 승격하지 않습니다.
