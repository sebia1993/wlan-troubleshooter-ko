# 변경 기록

## 0.4.0-alpha.1 — 2026-09-04

### 추가

- 내장 TShark의 실제 `-n -G fields` 필드 호환성 검사
- 검증된 저장 PCAP·PCAPNG에 대한 고정 `-T fields` 실행
- Radiotap·802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS·ICMP·QUIC 존재 프레임 인벤토리
- 그룹별 프레임 수와 처음·마지막 프레임 번호 표시
- 스크롤 가능한 한국어 결과 화면, 진행 표시와 분석 취소
- Portable 비대화형 로컬 분석 JSON 출력
- 최종 Portable ZIP에서 합성 ARP·DNS PCAP을 실제 내장 TShark로 분석하는 통합 검증

### 보안

- 모든 TShark 프로세스 생성을 검토된 단일 함수로 제한
- stdout 64MiB·stderr 1MiB·실행시간·패킷 수 상한
- stderr 원문 폐기와 사용자 오류 비노출
- TShark 번들·캡처 SHA-256 실행 전후 재검증
- 빈 config·plugin·extcap·data·temp 격리 환경과 종료 후 무잔류 검사
- IP·MAC·SSID·사용자명·DNS 질의명·Payload를 추출 필드에서 제외

### 제한

- 프로토콜 존재·미관찰은 접속 성공·실패 또는 장애 원인의 증거가 아님
- 이벤트 상관분석, 장애 Finding과 HTML 보고서는 아직 지원하지 않음
- 애플리케이션 EXE 상용 코드 서명 인증서는 없음

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포
- 내장 CPython 3.13·Tcl/Tk·TShark 4.6.8과 전체 무결성 검증

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서·프로토콜 인벤토리 정규화 기반

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
