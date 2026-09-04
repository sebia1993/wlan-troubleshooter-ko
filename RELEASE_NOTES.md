# v0.6.0-alpha.1 — 비식별 무선 접속 이벤트 타임라인 프리뷰

이번 릴리즈는 기존 접속 단계 Finding을 **802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 시간순 이벤트 타임라인**으로 확장합니다. Python과 Wireshark를 별도로 설치할 필요가 없습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.6.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- 802.11 인증·Association·Reassociation 요청과 응답
- Disassociation·Deauthentication 사유 코드와 Retry 표시
- EAPOL Start·Logoff·Key 및 확인 가능한 메시지 번호 1~4
- EAP Request·Response·Success·Failure
- RADIUS Access-Request·Challenge·Accept·Reject·Accounting
- DHCP Discover·Offer·Request·ACK·NAK·Decline·Release·Inform
- DNS Query·정상 응답·오류 응답
- ARP Request·Reply
- TCP SYN·SYN/ACK·RST·Retransmission 표시
- TLS ClientHello·ServerHello·Certificate·Finished
- 단계별 성공 결과·실패 결과·혼재·관련 트래픽·미관찰·판단 불가 상태
- 프레임 번호, 상대 시간, 결과 코드와 `frame.number == N` 근거 필터
- 반복 이벤트 보관 상한과 유형별 전체 요약

프로토콜 인벤토리, 기존 Finding과 새 타임라인은 캡처를 반복 실행하지 않고 동일한 한 번의 고정 TShark fields 출력에서 생성합니다.

## 비식별 상관 별칭

EAP Identifier, RADIUS Identifier, DHCP Transaction ID, DNS ID와 TShark TCP Stream 번호는 원문으로 출력하지 않습니다. 같은 캡처 안에서만 사용하는 다음 순번 별칭으로 바꿉니다.

```text
EAP-1
RADIUS-1
DHCP-1
DNS-1
TCP-1
```

절대 epoch 시간도 결과에 기록하지 않고 첫 프레임 기준 상대 밀리초만 표시합니다.

## 결과 해석 주의

이 릴리즈는 명시적인 프로토콜 결과를 관찰하지만 최종 장애 원인을 자동 확정하지 않습니다.

```text
EAP Success 관찰 ≠ 전체 접속 성공 확정
RADIUS Access-Accept 관찰 ≠ 서비스 정상 확정
RADIUS Access-Reject 관찰 ≠ ClearPass 자체 장애 확정
DHCP ACK 관찰 ≠ 이후 네트워크 정상 확정
TCP RST 관찰 ≠ 서버·방화벽·애플리케이션 중 원인 확정
TCP Retransmission 관찰 ≠ RF 또는 서버 장애 확정
프로토콜 미관찰 ≠ 해당 단계 장애
```

기본 결과에는 단말 식별자를 사용하지 않으므로 여러 단말과 여러 접속을 하나의 세션으로 자동 결합하지 않습니다. 성공과 실패가 함께 보이면 혼재로 표시합니다. EAPOL Key 메시지 번호 1~4가 모두 보여도 동일 단말의 한 번의 4-Way Handshake라고 확정하지 않습니다.

## 데이터 보호

- AI·LLM·Ollama·MCP·외부 API 없음
- 런타임 HTTP·소켓·온라인 DNS 조회 없음
- 텔레메트리·오류 자동 전송·자동 업데이트 없음
- 원본 PCAP 업로드·외부 전송 없음
- IP·MAC·SSID·BSSID·사용자명·DNS 질의명·호스트명·포트 출력 없음
- Payload·파일·쿠키·Authorization·자격 증명 출력 없음
- 원본 거래 ID·스트림 번호·절대 epoch 출력 없음
- 원본 파일명·절대경로·TShark 표준 오류 원문 표시 없음
- 실시간·원격 캡처 없음

## 실행 안전성

TShark는 승인된 고정 인자와 필드만 사용합니다. 출력 크기, 처리 패킷 수, 상세 이벤트 수와 실행시간에 상한이 있으며 사용자 취소가 가능합니다. TShark 번들과 캡처 파일은 실행 전후 SHA-256을 다시 확인하고 호출마다 빈 설정·플러그인·extcap·임시 디렉터리를 사용합니다.

## Portable 통합 검증

릴리즈 빌드는 Python 환경변수와 일반 Python PATH를 제거한 상태에서 최종 `WlanTroubleshooterKO.exe`를 실행합니다.

첫 번째 합성 Ethernet PCAP에서는 EAP Request·Response·Success, RADIUS Access-Request·Access-Accept, DHCP Discover·Offer·Request·ACK, DNS Query·정상 Response, ARP Request·Reply와 TCP SYN·SYN/ACK·RST를 확인합니다.

두 번째 IEEE 802.11 PCAP에서는 무선 인증 요청·성공 응답, Association 요청·성공 응답, EAP Request·Response·Success와 Deauthentication을 확인합니다.

두 분석 모두 결과 JSON에 캡처 경로·파일명·IP·MAC·원본 거래 ID·절대 epoch가 포함되지 않는지, 분석 전후 Portable 폴더가 변경되지 않는지도 검사합니다.

## 아직 지원하지 않는 기능

- MAC·SSID를 결과에 노출하지 않는 단말별 익명 세션 분리
- 동일 단말의 완전한 EAP·RADIUS·4-Way Handshake 상관분석
- 응답 미관찰과 캡처 누락의 자동 확정 구분
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 판정
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 한국어 HTML 보고서
- 애플리케이션 EXE 상용 코드 서명

## 릴리즈 자산

- `WlanTroubleshooterKO-v0.6.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.6.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
