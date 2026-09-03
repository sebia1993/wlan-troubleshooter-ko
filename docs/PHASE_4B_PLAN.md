# Phase 4B 실행 계획 — 접속 단계 상관분석과 근거 기반 Finding

## 승인 배경

2026년 9월 4일 사용자는 Phase 4A 프로토콜 존재 인벤토리 이후 남은 개발을 계속하도록 지시했습니다. Phase 4B는 AI나 외부 조회 없이, 저장된 PCAP·PCAPNG에서 명시적으로 관찰된 요청·응답과 실패 코드를 접속 단계별로 정리합니다.

## 목표

초급 네트워크 엔지니어가 다음 질문에 답할 수 있도록 합니다.

- 무선 연결·802.1X·EAP·RADIUS·DHCP·DNS·ARP·TCP 중 어느 단계가 보였는가?
- 명시적인 성공 또는 실패 응답이 있었는가?
- 결론을 뒷받침하는 프레임 번호는 무엇인가?
- Wireshark에서 어떤 Display Filter로 근거를 다시 확인할 수 있는가?
- 다음으로 어떤 장비·서버·정책을 확인해야 하는가?

## 구현 범위

- Association/Reassociation 응답의 상태 코드
- Deauthentication/Disassociation의 사유 코드 관찰
- EAP Success·Failure
- RADIUS Access-Accept·Access-Reject
- DHCP ACK·NAK와 거래 ID 기반 요청·응답 묶음
- DNS 정상·오류 응답과 스트림·거래 ID 기반 질의·응답 묶음
- ARP Reply 관찰
- TCP SYN·SYN/ACK·ACK 3-way Handshake, RST, 재전송 관찰
- 접속 단계별 `성공 응답 관찰 / 실패 응답 관찰 / 불완전 / 미관찰 / 판단 불가`
- Finding별 등급, 요약, 근거 프레임, 프레임 번호 Display Filter, 다음 점검 항목
- 스크롤 가능한 한국어 GUI와 식별정보 없는 비대화형 JSON

## 판정 등급

| 등급 | 의미 |
|---|---|
| 확정 | 패킷에 명시적인 실패 응답·오류 코드·Reset이 실제로 기록됨 |
| 유력 | 여러 독립 근거가 같은 원인을 지지할 때만 사용하며 현재 규칙에서는 사용하지 않음 |
| 참고 | 현상은 관찰됐지만 정상 동작이나 다른 원인에서도 발생할 수 있음 |
| 판단 불가 | 요청 뒤 응답을 보지 못했지만 캡처 누락 가능성 때문에 장애로 확정할 수 없음 |

`확정`은 해당 패킷 이벤트가 확정됐다는 뜻이며 전체 근본 원인을 확정한다는 뜻이 아닙니다. 예를 들어 TCP RST는 확정적으로 관찰할 수 있지만, RST의 원인이 서버·방화벽·응용프로그램 중 무엇인지는 추가 확인이 필요합니다.

## 미응답 안전 기준

패킷이 보이지 않았다는 사실만으로 장애를 만들지 않습니다. DHCP·DNS·TCP의 응답 미관찰 Finding은 다음 조건을 모두 만족할 때만 생성합니다.

1. Phase 2A 프레임 수와 TShark 처리 프레임 수가 같음
2. 요청 프레임이 명시적으로 관찰됨
3. 같은 거래·스트림에서 응답이 관찰되지 않음
4. 캡처 끝까지 충분한 후속 시간이 존재함
5. 결과 등급은 `판단 불가`로 유지

후속 시간 기준은 DHCP 5초, DNS 2초, TCP SYN 3초입니다. 이 기준은 서버 장애 확정 임계값이 아니라 짧은 캡처에서 성급한 미응답 표시를 줄이기 위한 최소 안전 조건입니다.

## 데이터 보호

Phase 4B는 상관분석에 필요한 다음 메타데이터를 메모리에서만 사용합니다.

- 프레임 번호·시각·길이·프로토콜 계층
- 802.11 종류·상태·사유 코드
- EAPOL·EAP·RADIUS 코드와 내부 상관 ID
- DHCP 거래 ID와 메시지 종류
- DNS 거래 ID·응답 여부·응답 코드·내부 스트림 번호
- ARP Opcode
- TCP 내부 스트림 번호·SYN·ACK·RST·재전송 표시

다음 값은 기본 결과와 GUI에 포함하지 않습니다.

- IP·MAC·SSID·BSSID
- 사용자명·RADIUS User-Name
- DNS 질의 이름·호스트명
- Raw Payload·쿠키·Authorization·자격 증명
- 캡처 파일명·절대경로
- DHCP·DNS 거래 ID와 TCP·UDP 내부 스트림 번호
- TShark 표준 오류 원문

## 확정 Finding

- `WLAN-ASSOC-REJECT`: Association/Reassociation 상태 코드가 0이 아님
- `EAP-FAILURE`: EAP Code 4
- `RADIUS-ACCESS-REJECT`: RADIUS Code 3
- `DHCP-NAK`: DHCP Message Type 6
- `DNS-ERROR-RESPONSE`: DNS 응답 RCODE가 0이 아님
- `TCP-RST`: TCP Reset 플래그가 설정됨

## 참고 Finding

- `WLAN-DISCONNECT`: Deauthentication 또는 Disassociation 관찰
- `TCP-RETRANSMISSION-MANY`: 재전송 표시가 3개 프레임 이상 관찰됨

재전송은 RF 장애 확정 근거로 사용하지 않습니다.

## 구현하지 않는 범위

- EAPOL 4-Way Handshake 메시지 1~4 완성도 판정
- 단말·AP·서버 주소별 세션 선택 UI
- 로밍 전후 BSSID·채널·RSSI 변화 상관분석
- ClearPass 정책·Role·VLAN 원인 판정
- 패킷 Payload나 인증정보 표시
- 장비 로그인·설정 변경·자동 복구
- AI·외부 API·온라인 OUI·WHOIS·GeoIP
- 최종 HTML 보고서

## 검증 기준

- 합성 TSV에서 성공·실패·혼합·불완전·미관찰·판단 불가 상태 검증
- 명시적 실패마다 규칙 ID·등급·근거 프레임·Display Filter·다음 점검 항목 검증
- 부분 캡처에서 미응답 Finding이 생성되지 않는지 검증
- 결과 직렬화에 내부 거래 ID·스트림·IP·파일 경로가 없는지 검증
- 최종 Portable EXE를 Python PATH 없이 실행
- 실제 내장 TShark로 합성 DNS NXDOMAIN과 TCP RST 캡처 분석
- `DNS-ERROR-RESPONSE`, `TCP-RST`가 `확정`으로 생성되는지 검증
- 분석 전후 Portable 배포 폴더가 변경되지 않는지 검증
- Windows 전체 단위 테스트·소스 감사·저장소 감사 통과

## 다음 단계

Phase 4C에서는 EAPOL 4-Way Handshake, 802.11 인증·Association·해제 흐름과 로밍 시점을 더 세밀하게 분석합니다. 이후에는 확정된 Finding과 근거를 단일 오프라인 HTML 보고서로 내보내는 단계를 진행합니다.
