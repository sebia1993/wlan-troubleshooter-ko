# v0.12.0-alpha.1 — Replay Counter 비식별 관계 분석 프리뷰

이번 릴리스는 EAPOL-Key M1~M4 순서 관찰에 **Replay Counter 관계 분석**을 추가합니다. Counter 숫자는 GUI·JSON·로그에 기록하지 않고 메시지 사이의 같음·증가·감소·불일치 관계만 제공합니다.

Python과 Wireshark를 별도로 설치할 필요가 없습니다. AI·LLM·외부 API·인터넷 조회·텔레메트리·자동 업데이트도 사용하지 않습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행하고 PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- 전용 최소 TShark 프로파일에서만 `eapol.keydes.replay_counter` 사용
- M1/M2 Counter 동일·불일치 관계
- M3/M4 Counter 동일·불일치 관계
- M1→M3 Counter 증가·동일·감소 관계
- 반복 M1~M4의 같은 Counter·다른 Counter 관계
- 필드 부재, Counter 누락과 근거 생략의 `unavailable`·`partial`
- GUI `[11. EAPOL Replay Counter 관계]`
- 기존 최상위 JSON `schema_version = 2`를 유지하는 `eapol_replay_relations`

## 관계 상태

```text
expected-relations-observed
relation-mismatch-observed
multiple-values-observed
partial
insufficient-events
unavailable
```

일반적인 관계가 관찰돼도 동일 Handshake·실제 재전송·키 설치·암호학적 성공을 확정하지 않습니다. 불일치는 캡처 누락이나 여러 교환 혼재 가능성을 포함하므로 AP·단말·RF 장애와 근본 원인을 자동 확정하지 않습니다.

## 항상 false인 값

```text
raw_replay_counters_serialized
replay_counter_values_persisted
same_handshake_confirmed
retransmission_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

## 전용 실행 경계

Replay Counter 관계 분석은 기존 분석과 같은 캡처 형식·크기·SHA-256, 같은 TShark 버전과 매니페스트 SHA-256을 다시 확인합니다. 분석 단계 사이에 캡처나 내장 TShark가 바뀌면 결과를 만들지 않습니다.

Replay Counter 원문은 다음 경로에서 차단됩니다.

```text
일반 프로토콜 인벤토리
공개 이벤트 타임라인
DEVICE-N/AP-N 가명화
레거시 TShark 실행
GUI·JSON·로그
```

Nonce, MIC, Key Data와 Payload 필드는 추출하지 않습니다.

## Portable 실제 통합검증

런타임 생성 Radiotap/IEEE 802.11 PCAP에서 다음 원문 Counter를 사용했습니다.

```text
M1/M2 = 18446744073709551000
M3/반복 M3/M4 = 18446744073709551001
```

최종 EXE의 공개 결과는 다음 관계뿐입니다.

```text
M1/M2 = equal-observed
M3/M4 = equal-observed
M1→M3 = increased-observed
반복 M3 = same-counter-observed
state = expected-relations-observed
```

검증 조건:

- 외부 Python·Wireshark를 사용할 수 없는 PATH
- 기존 Finding·타임라인·거래·`DEVICE-N`·여정·미응답·EAPOL 순서 게이트 유지
- 두 Counter 숫자와 원본 필드명 비노출
- MAC·BSSID·Nonce·MIC·Key Data·절대 시간·캡처 경로 비노출
- 모든 Handshake·재전송·키 설치·암호학적 성공·근본 원인 확정 값 `false`
- 분석 전후 Portable 배포 폴더 무변경

후보 빌드 검증값:

```text
ZIP: WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip
크기: 98,539,557 bytes
SHA-256: 0273bbc000d3fc0b19ca4d4109c756fcf4c43d61945e09ba3f1ede09501ba3eb
```

병합 후 릴리스 워크플로가 `main` 커밋에서 다시 빌드하므로 게시 자산의 최종 크기와 SHA-256은 새로 확정됩니다.

## 데이터 보호

다음 값은 결과에 기록하지 않습니다.

```text
Replay Counter 원문 숫자
Nonce·MIC·Key Data
원본 MAC·BSSID·SSID
IP 주소·포트
사용자명·EAP Identity
암호화 키·자격 증명
절대 epoch
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

## 호환성

필드 프로파일은 `0.6.0`으로 올라갔으며 최상위 분석 JSON 스키마는 계속 `2`입니다. 기존 인벤토리·Finding·타임라인·거래·단말 가명·여정·미응답·EAPOL 순서 결과를 유지합니다.

## 아직 지원하지 않는 기능

- Counter 관계만으로 동일 Handshake 또는 실제 재전송 확정
- 키 설치·암호학적 성공 확정
- PCAPNG Interface Statistics Block 기반 드롭 통계
- 로밍·RSSI·채널·데이터율 기반 RF 분석
- Aruba·ClearPass 맞춤 점검 안내
- 단일 오프라인 한국어 HTML 보고서
- 실제 사내 Aruba·ClearPass 캡처 검증
- 상용 코드 서명

## 릴리스 자산

- `WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`
