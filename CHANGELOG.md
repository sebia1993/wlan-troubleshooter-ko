# 변경 기록

## 0.10.0-alpha.1 — 2026-09-04

### 추가

- 캡처 구조·이벤트 타임라인·거래 보고서 완전성 교차 검증
- EAP·RADIUS·DHCP·DNS·TCP 요청·응답 계열 이벤트 관찰 범위
- 미완료 거래의 `response-not-observed`, `capture-boundary-risk`, `packet-truncation-risk`, `insufficient-analysis-input` 평가
- 첫·마지막 프레임 경계 위험
- 잘린 패킷, 상세 이벤트 생략과 거래 근거 생략 위험
- GUI `[9. 캡처 관찰 가능성과 미응답 해석]`
- 기존 최상위 JSON 스키마 2를 유지하는 `capture_observability` 결과
- 런타임 생성 미응답 DNS PCAP의 Portable 실제 분석 게이트

### 오탐 방지

- `capture_start_proven=false`
- `capture_end_proven=false`
- `capture_loss_excluded=false`
- `directionality_proven=false`
- `absence_can_confirm_failure=false`
- 개별 미완료 거래 `absence_is_failure=false`
- 파일 전체 처리와 양방향·무손실·장애 구간 전체 포함을 구분
- 요청·응답 계열 이벤트가 모두 보여도 모든 방향의 완전 수집으로 확정하지 않음
- 응답 미관찰을 서버·방화벽·ClearPass·DHCP·DNS 장애로 확정하지 않음

### Portable 검증

- 중간 DNS Query 미응답을 `response-not-observed`로 분류
- 마지막 프레임 DNS Query 미응답을 `capture-boundary-risk`로 분류
- 원본 IP·MAC·DNS 질의명·거래 ID·절대 시간·경로 비노출
- 분석 전후 Portable 배포 폴더 무변경

### 제한

- 캡처 프로그램·SPAN·무선 드라이버의 실제 드롭 카운터 수집은 아직 지원하지 않음
- 캡처 시작·종료가 장애 구간을 포함했는지 자동 증명하지 않음
- 응답 미관찰을 실제 미응답으로 확정하지 않음
- EAPOL 4-Way Handshake·로밍·RF·HTML 보고서는 아직 지원하지 않음

## 0.9.0-alpha.1 — 2026-09-04

- 분석 실행별 `DEVICE-N`에 안전하게 연결된 거래의 단말 관찰 여정
- 실제 근거 프레임 순서, 첫 실패 관찰 단계와 마지막 성공 방향 단계
- 단계별 성공·실패·혼재·미완료 상태와 Wireshark 필터
- 근거 없는 RADIUS 시간 추정 연결 금지
- `device_identity_confirmed=false`, `cross_protocol_session_confirmed=false`, `root_cause_confirmed=false`

## 0.8.0-alpha.1 — 2026-09-04

- 분석 실행별 `DEVICE-N`·`AP-N` HMAC 가명
- 단일 L2 근거가 있는 거래의 보수적 단말 연결
- 원본 MAC·BSSID·HMAC 키·토큰 비직렬화
- 별도 `device-identities` TShark 프로파일과 캡처 지문 재검증

## 0.7.0-alpha.1 — 2026-09-04

- EAP·RADIUS·DHCP·DNS·TCP 비식별 프로토콜 거래 시도
- 종료 응답 뒤 같은 별칭 재사용 시 `A1`, `A2`로 분리
- TCP SYN/SYN-ACK를 3-Way Handshake 완료로 과장하지 않음

## 0.6.0-alpha.1 — 2026-09-04

- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 타임라인
- 캡처 시작 기준 상대 시간과 로컬 순번 별칭
- Portable Ethernet·PPP EAP·IEEE 802.11 실제 분석 검증

## 0.5.0-alpha.1 — 2026-09-04

- 접속 단계 상관분석과 근거 기반 Finding
- Association 거부, EAP Failure, Access-Reject, DHCP NAK, DNS 오류와 TCP RST 판정

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark 실제 필드 호환성 검사와 저장 캡처 프로토콜 인벤토리

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서 기반

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
