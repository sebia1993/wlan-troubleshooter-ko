# v0.4.0-alpha.1 — 내장 TShark 프로토콜 인벤토리 프리뷰

이번 릴리즈부터 내장 TShark가 실제 저장 PCAP·PCAPNG를 읽어 프로토콜 존재 인벤토리를 생성합니다. Python과 Wireshark를 별도로 설치할 필요가 없습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- PCAP·PCAPNG 구조 사전 점검 후 내장 TShark 자동 실행
- TShark 필드 카탈로그와 고정 최소 필드의 실제 호환성 확인
- Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP, QUIC 존재 프레임 집계
- 프로토콜별 관찰 프레임 수와 처음·마지막 프레임 번호
- 전체·일부·판단 불가 상태와 잘린 프레임 경고
- 진행 표시, 스크롤 결과와 분석 취소

## 데이터 보호

- AI·LLM·Ollama·MCP·외부 API 없음
- 런타임 HTTP·소켓·DNS 조회 없음
- 텔레메트리·오류 자동 전송·자동 업데이트 없음
- 원본 PCAP 업로드·외부 전송 없음
- IP·MAC·SSID·사용자명·DNS 질의명·Payload 추출 없음
- 파일명·절대경로·TShark 표준 오류 원문 표시 없음
- 실시간·원격 캡처 없음

## 실행 안전성

TShark는 승인된 고정 인자만 사용합니다. 출력 크기, 처리 패킷 수와 실행시간에 상한이 있으며 사용자 취소가 가능합니다. TShark 파일과 캡처 파일은 실행 전후 SHA-256을 다시 확인하고, 호출마다 빈 설정·플러그인·extcap·임시 디렉터리를 사용합니다.

## Portable 통합 검증

릴리즈 빌드는 Python PATH를 제거한 상태에서 최종 `WlanTroubleshooterKO.exe`를 실행합니다. 실행 중 생성한 실제 ARP·DNS PCAP을 내장 TShark가 처리하고, 결과에 ARP와 DNS가 각각 관찰되는지 확인한 뒤에만 릴리즈를 게시합니다. 결과 JSON에 캡처 경로·파일명·패킷 IP가 포함되지 않는 것도 함께 확인합니다.

## 결과 해석 주의

이 버전은 장애 원인 판정기가 아니라 프로토콜 존재 인벤토리입니다.

```text
프로토콜 관찰됨 ≠ 단계 성공
프로토콜 미관찰 ≠ 해당 단계 장애
```

캡처 위치·시점·방향·잘림 때문에 필요한 패킷이 보이지 않을 수 있습니다.

## 아직 지원하지 않는 기능

- EAP·RADIUS·DHCP·DNS·TCP 이벤트 상관분석
- 인증·IP 할당·이름 조회·연결 실패 Finding
- 4-Way Handshake와 로밍 장애 판정
- 한국어 조치 안내와 최종 오프라인 HTML 보고서
- 애플리케이션 EXE 상용 코드 서명

## 릴리즈 자산

- `WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
