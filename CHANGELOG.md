# 변경 기록

## 0.7.0-alpha.1 — 2026-09-04

### 추가

- EAP·RADIUS·DHCP·DNS·TCP 비식별 프로토콜 거래 시도 요약
- 같은 로컬 별칭이 종료 응답 뒤 재사용될 때 `A1`, `A2` 시도 번호로 분리
- `complete`, `success-observed`, `failure-observed`, `mixed`, `incomplete` 상태
- 관찰 이벤트·미관찰 순서 요소·첫/마지막 프레임·상대 지속시간·근거 필터
- 프로토콜별 초급 엔지니어 다음 점검 항목
- 거래 별칭 50,000개, 거래별 이벤트 200,000개, 근거 프레임 64개 상한
- GUI의 `[6. 비식별 거래 시도 요약]` 영역
- Portable EAP·RADIUS·DHCP·DNS·TCP 실제 거래 시도 검증 게이트

### 판정 안전성

- 모든 거래에 `root_cause_confirmed=false` 고정
- 모든 거래에 `device_session_confirmed=false` 고정
- TCP SYN/SYN-ACK만으로 3-Way Handshake 완료를 표시하지 않음
- 프로토콜별 거래를 서로 연결해 동일 단말 접속으로 단정하지 않음
- 일부 캡처나 이벤트 보관 생략이 있으면 보고서 전체 완료 표시 차단
- 미완료 거래를 서버·방화벽·ClearPass 장애로 확정하지 않음

### 호환성

- 기존 분석 JSON 스키마 버전 2 유지
- `transaction_sessions`를 하위 호환 가능한 추가 결과로 제공
- 기존 Phase 4C 타임라인과 Finding의 필드·의미 유지

### 제한

- 단말별 익명 세션 분리와 서로 다른 프로토콜 거래 연결은 아직 지원하지 않음
- 동일 단말의 EAPOL 4-Way Handshake 완결성은 아직 지원하지 않음
- 로밍·RF 근본 원인과 최종 HTML 보고서는 아직 지원하지 않음
- 애플리케이션 EXE 상용 코드 서명 인증서는 없음

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
