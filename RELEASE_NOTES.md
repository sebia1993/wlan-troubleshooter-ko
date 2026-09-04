# v0.7.0-alpha.1 — 비식별 프로토콜 거래 시도 요약 프리뷰

이번 릴리즈는 Phase 4C 이벤트 타임라인을 확장하여 EAP·RADIUS·DHCP·DNS·TCP 이벤트를 **비식별 거래 시도 단위**로 요약합니다. Python과 Wireshark를 별도로 설치할 필요가 없습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.7.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- EAP Request·Response·Success·Failure 거래 시도
- RADIUS Access-Request·Challenge·Accept·Reject 거래 시도
- DHCP Discover·Offer·Request·ACK·NAK 거래 시도
- DNS Query·정상·오류 Response 거래 시도
- TCP SYN·SYN/ACK·RST·Retransmission 거래 시도
- 같은 로컬 별칭이 종료 응답 뒤 재사용되면 `A1`, `A2`로 시도 분리
- 관찰 이벤트와 완결성 기준에서 미관찰된 순서 요소
- 첫·마지막 프레임, 상대 지속시간과 고정 Wireshark 근거 필터
- 프로토콜별 다음 점검 항목
- GUI의 비식별 거래 시도 요약 영역

## 거래 상태

- **필요 순서 완료 관찰:** 요청부터 명시적인 성공 결과까지 필요한 순서가 관찰됨
- **성공 결과만 관찰:** 성공 응답은 있지만 거래 시작 부분이 보이지 않음
- **실패 결과 관찰:** Failure·Reject·NAK·DNS 오류·TCP RST가 관찰됨
- **성공·실패 혼재:** 같은 로컬 별칭 시도에서 성공과 실패가 함께 보임
- **최종 결과 미확인:** 요청 또는 중간 이벤트만 관찰됨

프로토콜별 완료 기준은 다음과 같습니다.

```text
EAP      Request → Response → Success
RADIUS   Access-Request → Access-Accept
DHCP     Discover → Offer → Request → ACK
DNS      Query → 정상 Response
TCP      최종 ACK를 구분하지 않으므로 완전한 3-Way Handshake 완료로 표시하지 않음
```

## 보수적 판정 경계

각 거래 결과에는 다음 값이 고정됩니다.

```text
root_cause_confirmed = false
device_session_confirmed = false
```

즉, RADIUS Reject·DHCP NAK·DNS 오류·TCP RST가 실제로 관찰돼도 계정·정책·서버·방화벽 중 무엇이 근본 원인인지는 추가 로그로 확인해야 합니다.

서로 다른 `EAP-1`, `RADIUS-1`, `DHCP-1`, `DNS-1`, `TCP-1`을 동일 단말의 하나의 접속으로 자동 연결하지 않습니다. 원본 단말 식별정보 없이 여러 사용자의 패킷을 잘못 결합하는 것을 방지하기 위한 제한입니다.

TCP SYN/SYN-ACK는 성공 방향 응답으로 표시하지만 최종 ACK를 식별하지 않으므로 3-Way Handshake 완료로 확정하지 않습니다. TCP Retransmission만으로 RF·서버·방화벽 장애를 확정하지 않습니다.

## 데이터 보호

Phase 4D는 Phase 4C가 만든 다음 비식별 값만 사용합니다.

```text
correlation_alias
frame_number
relative_time_ms
event_type
```

다음 값은 GUI와 기본 JSON에 포함하지 않습니다.

- IPv4·IPv6 주소
- Ethernet·802.11 MAC 주소
- SSID·BSSID
- 사용자명·EAP Identity·RADIUS User-Name
- DNS 질의명·호스트명
- TCP·UDP 포트
- 원본 EAP·RADIUS·DHCP·DNS 거래 ID
- 원본 TCP·UDP Stream 번호
- 절대 epoch
- Raw Payload·파일·쿠키·Authorization·자격 증명
- 캡처 파일명·절대경로
- TShark 표준 오류 원문

AI·LLM·Ollama·MCP·외부 API, 런타임 HTTP·소켓·온라인 DNS 조회, 텔레메트리, 오류 자동 전송과 자동 업데이트는 없습니다.

## 자원 제한

- 거래 별칭 최대 50,000개
- 한 거래 시도 이벤트 최대 200,000개
- 거래 시도별 근거 프레임 최대 64개
- 상세 이벤트가 생략되거나 캡처가 일부이면 거래 보고서 전체를 일부 결과로 표시
- 잘못된 별칭·프로토콜·프레임·상대 시간·개수는 실패-폐쇄 처리

## Portable 실제 통합 검증

릴리즈 빌드는 Python 환경변수와 일반 Python PATH를 제거한 상태에서 최종 `WlanTroubleshooterKO.exe`를 실행합니다.

- DNS NXDOMAIN: 실패 결과 거래
- TCP SYN→RST: 실패 결과 거래
- PPP EAP Request→Response→Success: 완료 거래
- RADIUS Access-Request→Access-Accept: 완료 거래
- DHCP Discover→Offer→Request→ACK: 완료 거래
- DNS Query→정상 Response: 완료 거래
- TCP SYN→SYN/ACK: 성공 응답 관찰, 완료로 과장하지 않음
- 별도 TCP RST: 실패 결과 거래

모든 거래의 근본 원인·단말 세션 확정 값이 `false`인지, 결과에 경로·파일명·IP·MAC·원본 거래 ID·절대 시간이 없는지, 분석 전후 Portable 폴더가 변경되지 않는지도 검사합니다.

## 호환성

기존 분석 JSON 스키마 버전 2를 유지합니다. `transaction_sessions`는 기존 인벤토리·Finding·타임라인을 변경하지 않는 추가 결과입니다.

## 아직 지원하지 않는 기능

- MAC·SSID를 결과에 노출하지 않는 단말별 익명 세션 분리
- 서로 다른 프로토콜 거래를 동일 단말 접속으로 연결
- 동일 단말의 EAPOL 4-Way Handshake 메시지 1~4 완결성 판정
- 응답 미관찰과 캡처 누락·단방향 수집의 자동 구분
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 판정
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 한국어 HTML 보고서
- 애플리케이션 EXE 상용 코드 서명

## 릴리즈 자산

- `WlanTroubleshooterKO-v0.7.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.7.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
