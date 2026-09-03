# 변경 기록

## 0.5.0-alpha.1 — 2026-09-04

### 추가

- `connection-events` 고정 TShark 필드 프로파일
- 무선 연결·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP 접속 단계 요약
- Association/Reassociation 거부, EAP Failure, RADIUS Access-Reject, DHCP NAK, DNS 오류 응답, TCP RST의 명시적 실패 Finding
- Deauthentication/Disassociation과 다수 TCP 재전송의 참고 Finding
- 전체 캡처와 최소 후속 시간이 확인된 경우에만 생성되는 DHCP·DNS·TCP 미응답 `판단 불가` Finding
- Finding별 근거 프레임, 프레임 번호 Display Filter와 초급자용 다음 점검 항목
- 스크롤 가능한 단계·Finding 한국어 GUI
- 최종 Portable EXE에서 실제 DNS NXDOMAIN·TCP RST 패킷을 처리하는 통합 검증

### 보안·판정 안전성

- IP·MAC·SSID·BSSID·사용자명·DNS 질의명·Payload를 기본 결과에서 제외
- DHCP·DNS 거래 ID와 TCP·UDP 내부 스트림 번호를 상관분석 메모리에서만 사용
- 명시적 실패 응답과 근본 원인 확정을 구분
- 일부 캡처에서 미응답 Finding 생성 차단
- 응답 미관찰은 전체 캡처에서도 `판단 불가`로 유지
- TCP 재전송만으로 RF 장애를 확정하지 않음

### 제한

- EAPOL 4-Way Handshake 메시지 1~4 완성도 판정은 지원하지 않음
- BSSID·채널·RSSI 기반 로밍·RF 상관분석은 지원하지 않음
- 최종 오프라인 HTML 보고서는 아직 지원하지 않음
- 애플리케이션 EXE 상용 코드 서명 인증서는 없음

## 0.4.0-alpha.1 — 2026-09-04

- 내장 TShark의 실제 `-n -G fields` 필드 호환성 검사
- 저장 PCAP·PCAPNG의 프로토콜 존재 인벤토리
- 그룹별 프레임 수와 처음·마지막 프레임 번호
- Portable ARP·DNS 실제 TShark 통합 검증

## 0.3.0-alpha.1 — 2026-09-04

- Python·Wireshark 미설치 PC용 Win64 Portable 배포
- 내장 CPython 3.13·Tcl/Tk·TShark 4.6.8과 전체 무결성 검증

## 0.2.0-alpha.2 — 2026-09-03

- TShark 필드 카탈로그·고정 프로파일·fields 파서·프로토콜 인벤토리 정규화 기반

## 0.2.0-alpha.1 — 2026-09-03

- PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
