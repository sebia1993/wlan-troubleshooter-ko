# Phase 4D 실행 계획 — 비식별 프로토콜 거래 시도 요약

## 배경

Phase 4C는 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트를 시간순으로 표시합니다. 그러나 초급 엔지니어는 같은 프로토콜의 요청·중간 응답·최종 결과를 다시 조합해야 합니다.

Phase 4D는 타임라인이 이미 생성한 비식별 로컬 별칭만 사용해 EAP·RADIUS·DHCP·DNS·TCP 거래를 시도 단위로 묶습니다. 원본 주소·포트·사용자·SSID·거래 ID·TCP Stream 번호는 새로 추출하거나 결과에 기록하지 않습니다.

## 사용자 목표

각 거래 시도에 대해 다음 질문에 답합니다.

- 거래가 어느 프레임에서 시작하고 끝났는가?
- 요청부터 정상 최종 결과까지 필요한 순서가 관찰됐는가?
- 명시적인 실패·거부·오류·Reset이 관찰됐는가?
- 캡처가 중간부터 시작되었을 가능성이 있는가?
- Wireshark에서 어떤 프레임을 다시 확인해야 하는가?
- 다음으로 어떤 장비·서버 로그를 확인해야 하는가?

## 입력 경계

Phase 4D가 받는 값은 Phase 4C 타임라인의 다음 네 가지뿐입니다.

```text
correlation_alias
frame_number
relative_time_ms
event_type
```

허용 별칭은 다음 형식뿐입니다.

```text
EAP-N
RADIUS-N
DHCP-N
DNS-N
TCP-N
```

별칭과 이벤트 프로토콜이 다르면 실패-폐쇄 처리합니다. 예를 들어 `DNS-1`에 `eap_request`가 연결된 입력은 거부합니다.

## 거래 시도 분리

같은 원본 프로토콜 ID가 캡처 안에서 재사용될 수 있으므로 하나의 별칭을 무조건 한 거래로 보지 않습니다. 명시적인 종료 이벤트 뒤에 같은 별칭이 다시 나타나면 다음과 같이 시도 번호를 붙입니다.

```text
DNS-1-A1
DNS-1-A2
EAP-2-A1
EAP-2-A2
```

종료 이벤트는 다음과 같습니다.

- EAP: Success 또는 Failure
- RADIUS: Access-Accept 또는 Access-Reject
- DHCP: ACK 또는 NAK
- DNS: 정상 Response 또는 오류 Response
- TCP: RST

TCP SYN/ACK는 성공 방향의 관찰 근거이지만 최종 ACK를 식별하지 않으므로 거래 종료나 3-Way Handshake 완료로 사용하지 않습니다.

## 프로토콜별 완결성 기준

### EAP

- 필요 순서 완료 관찰: Request → Response → Success
- 실패 결과 관찰: Failure
- 성공 결과만 관찰: Success는 있으나 앞 단계 일부가 없음
- 최종 결과 미확인: Request 또는 Response만 있음

### RADIUS

- 필요 순서 완료 관찰: Access-Request → Access-Accept
- 실패 결과 관찰: Access-Reject
- Access-Challenge만으로 성공 또는 실패를 확정하지 않음

### DHCP

- 필요 순서 완료 관찰: Discover → Offer → Request → ACK
- 실패 결과 관찰: NAK
- ACK만 보인 갱신·부분 캡처는 성공 결과만 관찰로 제한

### DNS

- 필요 순서 완료 관찰: Query → 정상 Response
- 실패 결과 관찰: 오류 Response
- Query만 보이면 최종 결과 미확인

### TCP

- SYN → SYN/ACK를 성공 방향의 응답 관찰로 표시
- RST를 실패 결과 관찰로 표시
- 최종 ACK를 구분하지 않으므로 3-Way Handshake 완료 상태는 생성하지 않음
- Retransmission만으로 RF·서버·방화벽 장애를 확정하지 않음

## 상태

| 상태 | 의미 |
|---|---|
| `complete` | 요청부터 명시적인 성공 결과까지 필요한 순서가 관찰됨 |
| `success-observed` | 성공 결과 또는 성공 방향 응답은 있지만 시작부터의 모든 요소는 없음 |
| `failure-observed` | 명시적인 Failure·Reject·NAK·DNS 오류·RST가 관찰됨 |
| `mixed` | 같은 비식별 별칭 시도에서 성공과 실패가 함께 관찰됨 |
| `incomplete` | 관련 요청·중간 이벤트는 있지만 최종 결과를 확인하지 못함 |

모든 거래 시도는 다음 값을 고정합니다.

```text
root_cause_confirmed = false
device_session_confirmed = false
```

즉, 프로토콜 이벤트는 확인할 수 있지만 전체 근본 원인이나 동일 단말 접속은 확정하지 않습니다.

## 결과

각 거래 시도는 다음 내용을 제공합니다.

- 시도 ID와 프로토콜
- 상태와 초급자용 설명
- 관찰 이벤트 종류
- 완결성 기준에서 미관찰된 순서 요소
- 첫 프레임·마지막 프레임
- 상대 지속시간
- 근거 프레임과 `frame.number` Display Filter
- 다음 점검 항목

근거 프레임은 시도당 최대 64개를 표시하며 초과 수를 별도로 기록합니다.

## 개인정보 보호

다음 값은 Phase 4D에서 사용하거나 출력하지 않습니다.

```text
IPv4·IPv6 주소
Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 EAP·RADIUS·DHCP·DNS 거래 ID
원본 TCP·UDP Stream 번호
절대 epoch
Raw Payload·쿠키·Authorization·자격 증명
캡처 파일명·절대경로
TShark 표준 오류 원문
```

## 오탐 방지

- 거래 미완료를 서버·방화벽·ClearPass 장애로 확정하지 않습니다.
- 캡처 시작 전 요청 또는 캡처 종료 후 응답 가능성을 유지합니다.
- 성공 거래가 있어도 무선 연결 전체나 사용자 서비스 정상 상태를 확정하지 않습니다.
- 서로 다른 프로토콜 별칭을 동일 단말 접속으로 연결하지 않습니다.
- 성공과 실패가 같은 시도에 있으면 재시도·ID 재사용·캡처 결합 가능성을 고려해 `mixed`로 표시합니다.
- 일부 캡처 또는 이벤트 보관 상한 초과 시 보고서 전체를 일부 결과로 표시합니다.

## 자원 제한

- 거래 별칭 최대 50,000개
- 한 거래 시도 이벤트 최대 200,000개
- 시도별 근거 프레임 최대 64개
- 이벤트 종류와 별칭의 고정 정규식 검증
- 프레임·상대 시간 순서 역전과 개수 불일치 거부

## 자동 검증

### 단위 테스트

- EAP 정상 완료와 RADIUS Reject 분리
- 동일 DNS 별칭의 정상·오류 시도 분리
- DHCP DORA 완료와 ACK만 있는 부분 캡처 구분
- TCP SYN/SYN-ACK를 3-Way Handshake 완료로 과장하지 않는지 확인
- TCP RST 뒤 새로운 SYN을 다음 시도로 분리
- 식별자 없는 결정론적 직렬화
- 부분 캡처와 이벤트 생략 처리
- 잘못된 별칭·프로토콜·프레임·시간·개수 거부

### Portable 실제 패킷 검증

Python·Wireshark가 없는 실행 환경을 재현하고 최종 EXE에서 다음을 검사합니다.

- DNS NXDOMAIN 거래: `failure-observed`
- TCP SYN→RST 거래: `failure-observed`
- PPP EAP Request→Response→Success: `complete`
- RADIUS Access-Request→Access-Accept: `complete`
- DHCP Discover→Offer→Request→ACK: `complete`
- DNS Query→정상 Response: `complete`
- TCP SYN→SYN/ACK: `success-observed`, `complete` 금지
- 별도 TCP RST: `failure-observed`
- 모든 거래의 근본 원인·단말 세션 확정 값이 `false`
- 결과의 경로·파일명·IP·MAC·원본 ID·절대 시간 비노출
- 분석 전후 Portable 폴더 무변경

## 완료 기준

- Windows 전체 단위 테스트·자체 점검·소스 감사·저장소 감사 통과
- Win64 Portable 실제 거래 시도 통합 게이트 통과
- GUI와 비대화형 JSON에서 거래 시도 요약 제공
- `v0.7.0-alpha.1` Win64 Portable 프리릴리즈 게시

## 다음 단계

Phase 4D는 프로토콜별 거래까지만 묶습니다. 다음 단계에서는 원본 MAC·SSID를 결과에 노출하지 않으면서 동일 단말의 프레임을 프로세스 내부 가명으로 분리하는 방식을 설계합니다. 로컬 가명화 키의 수명·저장 금지·역추적 위험을 별도 ADR로 검토한 후에만 서로 다른 EAP·RADIUS·DHCP·DNS·TCP 거래를 단말 접속 흐름으로 연결합니다.
