# v0.5.0-alpha.1 — 접속 단계 상관분석·근거 Finding 프리뷰

이번 릴리즈부터 내장 TShark가 프로토콜 존재 여부뿐 아니라 무선 연결, EAP, RADIUS, DHCP, DNS, ARP와 TCP의 **명시적인 성공·실패 응답**을 접속 단계별로 정리합니다. Python과 Wireshark를 별도로 설치할 필요가 없습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.5.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- 무선 연결·802.1X·EAP·RADIUS·DHCP·DNS·ARP·TCP 단계별 상태 요약
- Association/Reassociation 거부 상태 코드 Finding
- EAP Failure와 RADIUS Access-Reject Finding
- DHCP NAK와 DNS 오류 응답 Finding
- TCP RST Finding
- Deauthentication/Disassociation과 TCP 재전송 참고 Finding
- Finding별 근거 프레임 번호와 Wireshark 재확인 필터
- 초급 엔지니어용 다음 점검 항목
- 스크롤 가능한 한국어 결과와 분석 취소

## Finding 등급의 의미

- **확정:** 해당 실패 응답·오류 코드·Reset 패킷이 실제로 관찰됨
- **참고:** 현상은 관찰됐지만 정상 동작이나 여러 원인에서도 발생 가능
- **판단 불가:** 요청 뒤 응답을 확인하지 못했으나 캡처 누락 가능성 때문에 장애로 단정할 수 없음

`확정`은 해당 패킷 이벤트가 확정됐다는 뜻입니다. 근본 원인 전체가 확정됐다는 뜻은 아닙니다. 예를 들어 Access-Reject는 확정적으로 관찰할 수 있지만 계정, 인증서, 정책 중 어떤 항목이 거부 원인인지는 ClearPass 로그에서 확인해야 합니다.

## 미응답 처리

DHCP·DNS·TCP 요청 뒤 응답이 보이지 않아도 서버 장애로 확정하지 않습니다. 다음 조건을 모두 만족할 때만 `판단 불가` Finding을 생성합니다.

- 사전 점검 프레임 수와 TShark 처리 프레임 수가 같음
- 요청 프레임이 실제로 관찰됨
- 같은 거래·스트림에서 응답이 보이지 않음
- 캡처 끝까지 최소 후속 시간이 확보됨

일부 캡처나 짧은 캡처에서는 미응답 Finding을 만들지 않습니다.

## 데이터 보호

- AI·LLM·Ollama·MCP·외부 API 없음
- 런타임 HTTP·소켓·온라인 DNS 조회 없음
- 텔레메트리·오류 자동 전송·자동 업데이트 없음
- 원본 PCAP 업로드·외부 전송 없음
- 실시간·원격 캡처 없음
- IP·MAC·SSID·BSSID·사용자명·DNS 질의명·Payload 출력 없음
- DHCP·DNS 거래 ID와 TCP·UDP 스트림 번호 출력 없음
- 파일명·절대경로·TShark 표준 오류 원문 표시 없음

상관분석에 필요한 내부 ID는 메모리에서만 사용하고 결과에는 기록하지 않습니다.

## 실행 안전성

TShark는 승인된 고정 인자만 사용합니다. 처리 패킷 수, 출력 크기와 실행시간에 상한이 있으며 사용자가 분석을 취소할 수 있습니다. TShark 번들과 캡처 파일은 실행 전후 SHA-256을 재검증하고, 호출마다 빈 설정·플러그인·extcap·임시 디렉터리를 사용합니다.

## Portable 실제 통합 검증

릴리즈 빌드는 Python PATH를 제거한 상태에서 최종 `WlanTroubleshooterKO.exe`를 실행합니다. 테스트 중 생성한 실제 Ethernet PCAP에는 다음 패킷이 포함됩니다.

- ARP Request
- DNS Query
- DNS NXDOMAIN Response
- TCP SYN
- TCP RST/ACK

내장 TShark가 5개 프레임을 모두 처리하고 다음을 확인한 뒤에만 릴리즈를 게시합니다.

- ARP·DNS·TCP 프로토콜 그룹 관찰
- `DNS-ERROR-RESPONSE` 확정 Finding
- `TCP-RST` 확정 Finding
- 각 Finding의 근거 프레임과 Display Filter
- 결과 JSON에 캡처 경로·파일명·IP·DNS 질의명이 없음
- 분석 전후 Portable 배포 폴더 파일 목록이 동일함

## 아직 지원하지 않는 기능

- EAPOL 4-Way Handshake 메시지 1~4 완성도 판정
- BSSID·채널·RSSI 기반 로밍·RF 장애 상관분석
- 단말·AP·서버별 세션 선택
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 HTML 보고서
- 애플리케이션 EXE 상용 코드 서명

## 릴리즈 자산

- `WlanTroubleshooterKO-v0.5.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.5.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
