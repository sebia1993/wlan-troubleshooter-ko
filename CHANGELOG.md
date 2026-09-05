# 변경 기록

## 0.13.0-alpha.1 — 2026-09-05

### 추가

- PCAPNG Interface Statistics Block bounded 로컬 파서
- 섹션별 little-endian·big-endian 처리
- `isb_ifrecv`, `isb_ifdrop`, `isb_filteraccept`, `isb_osdrop`, `isb_usrdeliv`
- Interface Description Block 선언 순서 기반 `IFACE-N`
- 여러 ISB의 Counter 관찰 횟수·첫·마지막 보고값
- 증가·감소·변화 없음·단일 관찰 구분
- GUI `[12. PCAPNG 인터페이스 통계]`
- 최상위 JSON 스키마 2의 `pcapng_interface_statistics`
- TShark가 없는 소스 실행 모드의 독립 통계 보고서
- 민감 문자열과 두 ISB를 포함하는 Portable 실제 PCAPNG 게이트

### 보안·개인정보

- 기존 `validate_capture`로 통계 분석 전후 경로·형식·크기·SHA-256 재검증
- 인터페이스 이름·설명·GUID·장치 경로 미직렬화
- 하드웨어·운영체제·캡처 앱·필터·주석 문자열 미직렬화
- ISB 절대 Timestamp·starttime·endtime 미직렬화
- 원본 MAC·IP·파일명·절대경로 미직렬화
- `struct`만 오프라인 바이너리 파서용 표준 라이브러리로 감사 허용

### 과장 방지

- 드롭 Counter 0을 캡처 무손실로 해석하지 않음
- ISB 부재를 캡처 무손실로 해석하지 않음
- 양수 드롭을 특정 패킷 누락이나 RF·AP·단말·SPAN 장애로 확정하지 않음
- 여러 누적 스냅샷을 합산하지 않음
- Counter 감소를 재시작·초기화·wrap으로 확정하지 않음
- `capture_loss_excluded=false`
- `specific_packet_loss_confirmed=false`
- `root_cause_confirmed=false`

## 0.12.0-alpha.1 — 2026-09-05

- Replay Counter 전용 최소 TShark 프로파일
- M1/M2·M3/M4 같음·불일치 관계와 M1→M3 증가 관계
- 반복 메시지 같은 Counter·다른 Counter 관계
- Counter 원문 비직렬화·비저장
- 동일 Handshake·실제 재전송·키 설치·암호학적 성공 미확정

## 0.11.0-alpha.1 — 2026-09-05

- 비식별 EAPOL-Key M1~M4 메시지 순서 관찰
- 같은 메시지 번호 반복과 802.11 Retry 비트 프레임
- `DEVICE-N ↔ AP-N` 단일 근거 연결
- 동일 Handshake·키 설치·암호학적 성공·근본 원인 미확정

## 0.10.0-alpha.1 — 2026-09-05

- 캡처 관찰 가능성과 미응답 해석 경계
- 응답 미관찰·캡처 경계·패킷 잘림·불완전 입력 구분
- 캡처 시작·종료·무손실·양방향 미증명

## 0.9.0-alpha.1 — 2026-09-05

- 분석 실행별 `DEVICE-N`에 안전하게 연결된 거래의 단말 관찰 여정
- 실제 근거 프레임 순서와 첫 실패·마지막 성공 방향 단계

## 0.8.0-alpha.1 — 2026-09-04

- 분석 실행별 `DEVICE-N`·`AP-N` HMAC 가명
- 원본 MAC·BSSID·HMAC 키·내부 토큰 비직렬화

## 0.7.0-alpha.1 — 2026-09-04

- EAP·RADIUS·DHCP·DNS·TCP 비식별 거래 시도

## 0.6.0-alpha.1 — 2026-09-04

- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 타임라인

## 0.5.0-alpha.1 — 2026-09-04

- 접속 단계 상관분석과 명시적 실패 Finding

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark 실제 프로토콜 인벤토리

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
