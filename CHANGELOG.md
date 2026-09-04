# 변경 기록

## 0.8.0-alpha.1 — 2026-09-04

### 추가

- 분석 실행별 `DEVICE-N`·`AP-N` 가명화
- 공개 이벤트 프로파일과 분리된 `device-identities` 전용 TShark 프로파일
- 전용 프로파일에 한정한 `eth.src`, `eth.dst`, `wlan.sa`, `wlan.da`, `wlan.bssid` 허용
- 분석 실행마다 새 32바이트 HMAC-SHA-256 키 생성
- 802.11 관리 프레임·EAP 방향·DHCP 클라이언트 근거 기반 단말 최초 등록
- 알려진 단말이 하나만 포함된 후속 DNS·TCP·TLS·ARP 프레임 할당
- 거래 근거 프레임이 하나의 단말만 가리킬 때 거래 시도 연결
- GUI `[7. 분석 실행별 단말·AP 가명]` 영역
- Portable Ethernet `DEVICE-1` 및 IEEE 802.11 `DEVICE-1`·`AP-1` 개인정보 검증 게이트
- 가명화 개인정보 경계 ADR 0004

### 개인정보 보호

- 원문 L2 주소·HMAC digest·가명화 비밀키·대응표 직렬화 금지
- 가명화 비밀키의 파일·로그·환경변수 저장 금지
- 실행 간 동일 별칭 보장 금지
- IP·IPv6·SSID·사용자명·DNS 질의명·포트·Payload를 가명화 프로파일에서도 제외
- 결과 플래그 `raw_identifiers_serialized=false`
- 결과 플래그 `alias_secret_persisted=false`
- 결과 플래그 `aliases_stable_across_runs=false`

### 오탐 방지

- 일반 DNS·TCP 주소만으로 새 단말 가명 미생성
- 브로드캐스트·멀티캐스트·전부 0인 주소 제외
- 한 프레임에 둘 이상의 알려진 단말이 있으면 모호함으로 유지
- 단말 L2 근거가 없는 RADIUS 거래를 시간만으로 연결하지 않음
- 각 단말 결과에 `device_identity_confirmed=false`
- 각 단말 결과에 `cross_protocol_session_confirmed=false`

### 호환성

- 기존 분석 JSON 스키마 버전 2 유지
- `device_sessions`를 하위 호환 가능한 추가 결과로 제공
- 기존 인벤토리·Finding·타임라인·거래 시도 의미 유지

### 제한

- Python·TShark 메모리 버퍼에 원문 L2 주소가 분석 중 일시적으로 존재할 수 있음
- 실행 간 단말 추적과 여러 캡처 파일 결합은 지원하지 않음
- `DEVICE-N` 내부의 여러 접속 시간 구간 분리는 아직 지원하지 않음
- RADIUS·4-Way Handshake·로밍·RF·HTML 보고서는 후속 단계
- 애플리케이션 EXE 상용 코드 서명 인증서는 없음

## 0.7.0-alpha.1 — 2026-09-04

- EAP·RADIUS·DHCP·DNS·TCP 비식별 프로토콜 거래 시도 요약
- 종료 응답 뒤 재사용된 로컬 별칭의 `A1`, `A2` 시도 분리
- 보수적 거래 완결성, 근거 프레임과 다음 점검 항목

## 0.6.0-alpha.1 — 2026-09-04

- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 비식별 이벤트 타임라인
- 캡처 시작 기준 상대 시간과 로컬 순번 별칭
- Portable Ethernet·PPP EAP·IEEE 802.11 실제 분석 검증

## 0.5.0-alpha.1 — 2026-09-04

- 접속 단계 상관분석과 근거 기반 Finding
- Association 거부, EAP Failure, Access-Reject, DHCP NAK, DNS 오류와 TCP RST 판정

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark의 실제 필드 호환성 검사와 저장 캡처 프로토콜 인벤토리

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서 기반

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
