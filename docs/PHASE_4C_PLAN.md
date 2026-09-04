# Phase 4C 실행 계획 — 비식별 무선 접속 이벤트 타임라인

## 목적

Phase 4B의 접속 단계 Finding을 확장하여, 저장된 PCAP·PCAPNG에서 관찰된 명시적 프로토콜 이벤트를 시간순으로 정리합니다. 결과는 초급 네트워크 엔지니어가 Wireshark에서 근거 프레임을 다시 확인할 수 있어야 하며, 원본 단말·사용자·서버 식별정보를 포함하지 않아야 합니다.

## 분석 흐름

```text
캡처 안전성·구조 점검
→ 고정 TShark 필드 카탈로그 확인
→ connection-events 프로파일로 한 번만 캡처 해석
→ 프로토콜 존재 인벤토리
→ Phase 4B 접속 단계 Finding
→ Phase 4C 비식별 이벤트 타임라인
```

Finding과 타임라인을 위해 캡처를 각각 다시 실행하지 않습니다. 동일한 fields 출력에서 두 결과를 결정론적으로 생성합니다.

## 이벤트 범위

- IEEE 802.11 인증·Association·Reassociation·Disassociation·Deauthentication·Retry
- EAPOL Start·Logoff·EAP Packet·Key와 확인 가능한 메시지 번호 1~4
- EAP Request·Response·Success·Failure
- RADIUS Access-Request·Challenge·Accept·Reject·Accounting
- DHCP Discover·Offer·Request·ACK·NAK·Decline·Release·Inform
- DNS Query·정상 Response·오류 Response
- ARP Request·Reply
- TCP SYN·SYN/ACK·RST·Retransmission 표시
- TLS ClientHello·ServerHello·Certificate·Finished

## 결과 모델

각 이벤트는 다음 정보만 제공합니다.

- 캡처 시작 기준 상대 밀리초
- 프레임 번호
- 이벤트 유형과 한국어 표시명
- 명시적인 상태·사유·응답 코드
- 캡처 내부 로컬 상관 별칭
- `frame.number == N` 근거 필터

절대 epoch 시간은 직렬화하지 않습니다. EAP Identifier, RADIUS Identifier, DHCP Transaction ID, DNS ID, UDP·TCP Stream은 원문 대신 `EAP-1`, `RADIUS-1`, `DHCP-1`, `DNS-1`, `TCP-1` 형태의 순번 별칭으로 변환합니다.

## 단계 상태

- `success-observed`: 명시적 성공 결과 관찰
- `failure-observed`: 명시적 실패 결과 관찰
- `mixed`: 성공·실패가 모두 관찰됨
- `sequence-observed`: 필요한 메시지 번호 집합이 관찰됨
- `activity-observed`: 관련 요청·응답 일부만 관찰됨
- `not-observed`: 현재 캡처에서 이벤트 미관찰
- `unavailable`: 선택 필드가 없어 판단 불가

이 상태는 캡처 전체의 관찰 요약이며 단일 단말 접속 결과로 자동 해석하지 않습니다.

## 개인정보 경계

다음 필드는 추출·출력하지 않습니다.

- IPv4·IPv6 주소
- Ethernet·802.11 MAC 주소
- SSID·BSSID
- 사용자명·EAP Identity·RADIUS User-Name
- DNS 질의명·호스트명
- TCP·UDP 포트
- Raw Payload·파일·쿠키·Authorization·자격 증명
- 원본 파일명·절대경로

원본 거래 ID와 스트림 번호는 메모리의 상관 처리에만 사용합니다.

## 오탐 방지

- 명시적 결과 코드는 패킷 이벤트 관찰 사실이며 근본 원인 확정이 아닙니다.
- 프로토콜 미관찰과 패킷 부재를 장애로 판정하지 않습니다.
- 여러 단말의 성공·실패가 섞이면 `mixed`로 표시합니다.
- EAPOL Key 메시지 번호 1~4가 모두 있어도 동일 단말의 한 번의 4-Way Handshake라고 확정하지 않습니다.
- TCP Retransmission만으로 RF·서버 장애를 확정하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널을 판정하지 않습니다.

## 자원 제한

- 캡처 처리 상한: 100,000프레임
- TShark stdout 상한: 64MiB
- TShark stderr 상한: 1MiB
- 기본 실행 제한시간: 180초
- 상세 이벤트 보관 상한: 2,000건
- GUI 상세 표시 상한: 120건

이벤트 보관 상한을 넘으면 상세 목록만 생략하고 유형별 전체 집계는 유지합니다.

## 검증

### 단위 검증

- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 정규화
- 성공·실패 혼재와 선택 필드 누락 처리
- 역순 시간·중복 프레임·잘못된 길이 거부
- 상세 이벤트 보관 상한과 전체 집계 유지
- 결과에서 절대 시간·원본 거래 ID·식별정보 비노출
- TShark 승인 필드·고정 argv 정책

### Portable 실제 통합 검증

최종 ZIP을 압축 해제하고 Python 환경변수와 일반 Python PATH를 제거한 상태에서 `WlanTroubleshooterKO.exe`를 실행합니다.

- 합성 Ethernet 16프레임: EAPOL 외피·RADIUS·DHCP·DNS·ARP·TCP 이벤트
- 합성 IEEE 802.11 8프레임: 인증·Association·EAP·Deauthentication 이벤트
- EAP Request·Response·Success는 실제 무선 데이터 프레임의 EAPOL/EAP 구조에서 검증
- 결과 경로·파일명·IP·MAC·원본 거래 ID·절대 epoch 비노출
- 분석 전후 Portable 폴더 무변경

## 완료 기준

- Windows 전체 단위 테스트·자체 점검·소스 감사·저장소 감사 통과
- Win64 Portable 실제 Ethernet·802.11 통합 게이트 통과
- GUI와 비대화형 JSON에서 타임라인 확인 가능
- `v0.6.0-alpha.1` 프리릴리즈 게시

## 다음 단계

다음 단계에서는 원본 MAC·SSID를 결과에 노출하지 않으면서 동일 단말의 프레임을 프로세스 내부 가명으로 분리하는 방식을 설계합니다. 세션 분리가 검증된 뒤 EAP·RADIUS·DHCP·DNS·TCP 거래를 단말별로 결합하고, 이후 오프라인 HTML 보고서와 확인 명령·조치 순서를 추가합니다.
