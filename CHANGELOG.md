# 변경 기록

## 0.9.0-alpha.1 — 2026-09-04

### 추가

- Phase 4E `DEVICE-N` 가명과 Phase 4D 거래 시도를 결합하는 단말별 관찰 여정
- EAP·RADIUS·DHCP·DNS·TCP 단계별 거래 상태 집계
- 실제 근거 프레임 순서에 따른 관찰 단계 순서
- 첫 실패 관찰 단계와 마지막 성공 방향 단계
- 단계별 연결 거래 ID, 근거 프레임과 Wireshark `frame.number` 필터
- `progress-observed`, `failure-observed`, `mixed`, `partial-progress`, `incomplete`, `no-linked-transactions` 여정 상태
- GUI `[8. 단말 가명별 관찰 여정]` 영역
- 최종 Portable EXE의 `DEVICE-1` EAP·DHCP·DNS·TCP 여정 실분석 게이트

### 개인정보·상관 안전성

- 원본 L2·L3 주소, SSID, 사용자명, DNS 질의명, 포트와 거래 ID를 여정 입력에서 제외
- 단말 가명 보고서의 원문 직렬화·키 저장·실행 간 별칭 고정 플래그가 모두 `false`인지 확인
- 연결 객체의 근거 프레임과 원 거래 근거가 정확히 일치하지 않으면 실패-폐쇄 처리
- 근거가 생략된 거래를 단말 여정에 연결하지 않음
- 생략 거래가 미연결·빈 근거로 정제된 경우에만 여정에서 안전하게 제외
- RADIUS처럼 단말 L2 근거가 없는 거래를 시간 근접성만으로 연결하지 않음
- `device_identity_confirmed=false`
- `cross_protocol_session_confirmed=false`
- `root_cause_confirmed=false`
- 첫 실패 관찰 단계를 근본 원인 위치로 표현하지 않음

### 판정 보완

- 동일 단계의 성공 방향과 실패 결과를 `mixed`로 유지
- 혼재 단계도 성공 방향이 실제 관찰된 경우 마지막 성공 방향 단계에 반영
- 캡처 일부·거래 미할당·모호 연결이 있으면 전체 완료로 과장하지 않음

### Windows 격리 보완 포함

- TShark 임시파일 사용으로 바뀌는 Windows Archive·시간·디렉터리 크기를 객체 교체로 오인하지 않음
- 장치 ID·파일 ID·객체 종류·링크 수·Reparse Point 보안 검사는 유지
- 실행 후 격리 경로 무잔류 검사는 유지

### 제한

- 여정은 동일 사용자 신원이나 하나의 완전한 교차 프로토콜 세션을 확정하지 않음
- 캡처 누락과 실제 미응답 자동 구분은 아직 지원하지 않음
- 동일 단말 4-Way Handshake·로밍·RF 근본 원인 분석은 아직 지원하지 않음
- 최종 오프라인 HTML 보고서와 상용 코드 서명은 아직 지원하지 않음

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
