# 변경 기록

## 0.12.0-alpha.1 — 2026-09-05

### 추가

- Wireshark 4.6.8 `eapol.keydes.replay_counter` 전용 최소 추출 프로파일
- M1/M2 및 M3/M4 Counter 동일·불일치 관계
- M1→M3 Counter 증가·동일·감소 관계
- 반복 M1~M4의 같은 Counter·다른 Counter 관계
- `expected-relations-observed`, `relation-mismatch-observed`, `multiple-values-observed`, `partial`, `insufficient-events`, `unavailable`
- GUI `[11. EAPOL Replay Counter 관계]`
- 최상위 JSON 스키마 2의 `eapol_replay_relations` 추가 결과
- 고유 64비트 Counter를 사용하는 Portable 실제 내장 TShark 검증

### 개인정보·키 정보 보호

- Replay Counter 원문을 공개 이벤트·GUI·JSON·로그에 기록하지 않음
- 일반 분석·레거시·단말 가명 프로파일에서 Counter 원문 차단
- 기존 분석과 동일한 캡처 SHA-256 및 TShark 매니페스트 재검증
- Nonce·MIC·Key Data·Payload 추출 금지 유지
- `raw_replay_counters_serialized=false`
- `replay_counter_values_persisted=false`
- `same_handshake_confirmed=false`
- `retransmission_confirmed=false`
- `key_installation_confirmed=false`
- `cryptographic_success_confirmed=false`
- `root_cause_confirmed=false`

### 검증

- Windows 전체 테스트 340개 실행, 339개 통과, 플랫폼 제약 테스트 1개 명시적 건너뜀
- 오프라인 소스 감사 59개 파일 통과
- 저장소 감사 156개 추적 파일 통과
- Python·Wireshark 미설치 Portable 전체 실분석 통과
- 후보 ZIP 크기 98,539,557바이트
- 후보 ZIP SHA-256 `0273bbc000d3fc0b19ca4d4109c756fcf4c43d61945e09ba3f1ede09501ba3eb`

### 오탐 방지

- 일반적인 Counter 관계가 보여도 하나의 동일 Handshake로 확정하지 않음
- 같은 메시지와 같은 Counter가 반복돼도 실제 재전송으로 확정하지 않음
- 관계 불일치를 키 설치 실패·AP·단말·RF 장애의 근본 원인으로 확정하지 않음
- 필드·프레임·근거 일부 누락은 `unavailable` 또는 `partial`로 제한

## 0.11.0-alpha.1 — 2026-09-05

- 비식별 EAPOL-Key M1~M4 메시지 순서 관찰
- 같은 메시지 번호 반복 및 802.11 Retry 비트 프레임
- `DEVICE-N ↔ AP-N` 단일 근거 연결
- 동일 Handshake·키 설치·암호학적 성공·근본 원인 미확정

## 0.10.0-alpha.1 — 2026-09-05

- 캡처 관찰 가능성과 미응답 해석 경계
- 응답 미관찰·캡처 경계·패킷 잘림·불완전 입력 구분
- 캡처 시작·종료·무손실·양방향 미증명

## 0.9.0-alpha.1 — 2026-09-05

- `DEVICE-N`에 안전하게 연결된 거래의 단말 관찰 여정
- 실제 근거 프레임 순서와 첫 실패·마지막 성공 방향 단계

## 0.8.0-alpha.1 — 2026-09-04

- 분석 실행별 `DEVICE-N`·`AP-N` HMAC 가명
- 원본 MAC·BSSID·HMAC 키·토큰 비직렬화

## 0.7.0-alpha.1 — 2026-09-04

- EAP·RADIUS·DHCP·DNS·TCP 비식별 거래 시도

## 0.6.0-alpha.1 — 2026-09-04

- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 타임라인

## 0.5.0-alpha.1 — 2026-09-04

- 접속 단계 상관분석과 근거 기반 Finding

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark 실제 프로토콜 인벤토리

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
