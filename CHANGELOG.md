# 변경 기록

## 0.11.0-alpha.1 — 2026-09-05

### 추가

- 비식별 EAPOL-Key M1·M2·M3·M4 메시지 번호 순서 관찰
- `EAPOL-HS-N` 로컬 관찰 ID와 `DEVICE-N ↔ AP-N` 근거
- M1→M2→M3→M4 첫 관찰 순서
- 미관찰·반복 메시지 번호와 같은 프레임의 802.11 Retry 비트
- `sequence-observed`, `message-repetition-observed`, `out-of-order`, `incomplete` 상태
- 진행 중 새 M1과 M4 이후 새 메시지의 관찰 창 분리
- GUI `[10. EAPOL 4-Way Handshake 메시지 순서]`
- 기존 최상위 JSON 스키마 2의 `eapol_handshakes` 추가 결과
- Radiotap/IEEE 802.11 M1→M2→M3→반복 M3→M4 Portable 실제 TShark 게이트

### 개인정보·판정 안전성

- Replay Counter·Nonce·MIC·Key Data와 키 원문 미사용·미직렬화
- 원본 MAC·BSSID·SSID 미직렬화
- 단말 프레임 근거와 단일 AP 가명이 있을 때만 관찰에 포함
- 시간 근접성만으로 단말·AP를 연결하지 않음
- AP 후보가 둘 이상인 로밍 단말은 보수적으로 모호 처리
- 단말 근거 프레임이 일부 생략되면 전체 완료 차단
- `replay_counter_correlation_available=false`
- `same_handshake_confirmed=false`
- `key_installation_confirmed=false`
- `cryptographic_success_confirmed=false`
- `root_cause_confirmed=false`
- 메시지 번호 반복을 실제 동일 Handshake 재전송으로 확정하지 않음

### 호환성

- 최상위 분석 JSON `schema_version = 2` 유지
- 기존 Finding·타임라인·거래·단말 가명·여정·관찰 가능성 결과 유지
- Python·Wireshark 미설치 PC용 Win64 Portable 유지

### 제한

- Replay Counter 관계 기반 상관분석은 아직 지원하지 않음
- 프레임별 비식별 DEVICE/AP 대응은 아직 지원하지 않음
- PCAPNG 드롭 통계·로밍·RF·HTML 보고서는 아직 지원하지 않음
- 상용 코드 서명 인증서는 없음

## 0.10.0-alpha.1 — 2026-09-04

- 캡처 구조·이벤트·거래 완전성 교차 검증
- 미완료 거래의 응답 미관찰·캡처 경계·잘림·입력 불완전 구분
- 응답 부재만으로 장애 확정 금지
- `capture_start_proven=false`, `capture_end_proven=false`
- `capture_loss_excluded=false`, `directionality_proven=false`

## 0.9.0-alpha.1 — 2026-09-04

- `DEVICE-N`에 안전하게 연결된 거래의 단말 관찰 여정
- 실제 근거 프레임 순서, 첫 실패 관찰 단계와 마지막 성공 방향 단계
- 근거 없는 RADIUS 시간 추정 연결 금지

## 0.8.0-alpha.1 — 2026-09-04

- 분석 실행별 `DEVICE-N`·`AP-N` HMAC 가명
- 원본 MAC·BSSID·HMAC 키·내부 토큰 비직렬화
- 단일 L2 근거가 있는 거래만 보수적으로 연결

## 0.7.0-alpha.1 — 2026-09-04

- EAP·RADIUS·DHCP·DNS·TCP 비식별 거래 시도
- 종료 응답 뒤 별칭 재사용 시 시도 분리
- TCP SYN/SYN-ACK를 3-Way Handshake 완료로 과장하지 않음

## 0.6.0-alpha.1 — 2026-09-04

- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 타임라인
- 캡처 시작 기준 상대 시간과 로컬 별칭

## 0.5.0-alpha.1 — 2026-09-04

- 접속 단계 상관분석과 명시적 실패 Finding
- Association 거부, EAP Failure, Access-Reject, DHCP NAK, DNS 오류, TCP RST

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark 실제 필드 호환성 검사와 프로토콜 인벤토리

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
