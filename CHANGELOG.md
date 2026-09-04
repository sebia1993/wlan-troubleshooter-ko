# 변경 기록

## 0.6.0-alpha.1 — 2026-09-04

### 추가

- 기존 `connection-events` 프로파일을 32개 고정 메타데이터 필드로 확장
- 802.11 인증·Association·Reassociation·Disassociation·Deauthentication·Retry 이벤트
- EAPOL Start·Logoff·Key와 확인 가능한 4-Way Handshake 메시지 번호 1~4 관찰
- EAP Request·Response·Success·Failure 이벤트
- RADIUS Access-Request·Challenge·Accept·Reject·Accounting 이벤트
- DHCP Discover·Offer·Request·ACK·NAK·Decline·Release·Inform 이벤트
- DNS Query·정상 Response·오류 Response 이벤트
- ARP Request·Reply, TCP SYN·SYN/ACK·RST·Retransmission, TLS Handshake 이벤트
- 캡처 시작 기준 상대 시간, 프레임 번호와 `frame.number == N` 근거 필터
- 원본 거래 ID 대신 EAP·RADIUS·DHCP·DNS·TCP 로컬 순번 별칭
- 단계별 성공 결과·실패 결과·혼재·순서 요소·관련 트래픽·미관찰·판단 불가 요약
- 상세 이벤트 2,000개 보관 상한과 유형별 전체 집계
- 최종 Portable에서 합성 Ethernet 및 IEEE 802.11 PCAP을 실제 내장 TShark로 분석하는 통합 게이트

### 변경

- 프로토콜 인벤토리, Finding과 타임라인을 동일한 한 번의 TShark fields 출력에서 생성
- 필드 프로파일 버전을 `0.4.0`으로 갱신
- 패키지 버전을 `0.6.0a1`, Phase를 `4C`로 갱신
- GUI를 시간순 이벤트·상관 별칭·단계별 관찰 결과까지 확장

### 보안·오탐 방지

- IP·MAC·SSID·BSSID·사용자명·DNS 질의명·호스트명·포트·Payload를 출력 필드에서 제외
- 절대 epoch 시간과 원본 거래 ID·스트림 번호를 결과에 기록하지 않음
- 여러 단말·세션이 섞인 캡처를 하나의 접속으로 자동 결합하지 않음
- EAPOL 메시지 번호 1~4가 모두 보여도 동일 단말의 한 번의 교환으로 확정하지 않음
- TCP 재전송만으로 RF·서버 장애를 확정하지 않음

### 제한

- 단말별 익명 세션 분리와 완전한 EAP·RADIUS·4-Way Handshake 결합은 아직 지원하지 않음
- 미응답과 캡처 누락을 자동으로 확정 구분하지 않음
- 로밍·RF 근본 원인과 최종 HTML 보고서는 아직 지원하지 않음
- 애플리케이션 EXE 상용 코드 서명 인증서는 없음

## 0.5.0-alpha.1 — 2026-09-04

- 접속 단계 상관분석과 근거 기반 Finding
- Association 거부, EAP Failure, Access-Reject, DHCP NAK, DNS 오류와 TCP RST 판정
- Portable DNS NXDOMAIN·TCP RST 실제 분석 검증

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark의 실제 `-n -G fields` 필드 호환성 검사
- 저장 PCAP·PCAPNG의 프로토콜 존재 인벤토리
- 그룹별 프레임 수와 처음·마지막 프레임 번호

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포
- 내장 CPython 3.13·Tcl/Tk·TShark 4.6.8과 전체 무결성 검증

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서·프로토콜 인벤토리 정규화 기반

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
