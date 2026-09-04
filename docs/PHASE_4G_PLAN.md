# Phase 4G 실행 계획 — 캡처 관찰 가능성과 미응답 해석 경계

## 배경

Phase 4F까지는 명시적인 성공·실패 패킷과 단말 가명별 관찰 여정을 제공합니다. 그러나 요청이 보이고 응답이 보이지 않는 거래는 실제 장애일 수도 있고 다음 캡처 한계 때문일 수도 있습니다.

```text
캡처가 요청 뒤에 시작됨
캡처가 응답 전에 종료됨
SPAN·미러링에서 한 방향 누락
무선 채널 이탈
캡처 프로그램 내부 드롭
Snap Length에 의한 패킷 잘림
분석 패킷·이벤트 상한
```

Phase 4G는 패킷 부재를 장애 증거로 승격하지 않고, 현재 파일에서 관찰 가능한 범위와 해석 제한을 명시합니다.

## 목표

- 캡처 구조·이벤트·거래 결과가 모두 완전한지 교차 확인
- EAP·RADIUS·DHCP·DNS·TCP 요청·응답 계열 이벤트 관찰 여부 제공
- 미완료 거래가 캡처 첫·마지막 프레임에 닿는지 표시
- 잘린 패킷·상세 이벤트 생략·거래 근거 생략 위험 표시
- 현재 프레임 범위에서 단순히 응답을 못 봤는지 구분
- 어느 경우에도 응답 부재를 확정 장애로 표현하지 않음

## 입력

이미 공개 가능한 다음 결과만 사용합니다.

```text
CaptureStructure
EventTimeline
TransactionSessionReport
```

원본 주소·SSID·사용자명·DNS 질의명·포트·거래 ID·Payload를 입력받지 않습니다.

## 전역 완전성

`analysis_input_complete=true`가 되려면 다음 조건을 모두 만족해야 합니다.

```text
캡처 구조 scan_complete = true
이벤트 타임라인 complete = true
거래 시도 보고서 complete = true
상세 이벤트 생략 수 = 0
구조 점검 패킷 수 = 이벤트 분석 프레임 수
타임라인 이벤트 수 = 거래 보고서 원본 이벤트 수
```

이 값이 true여도 캡처가 장애 전부터 시작됐거나 장애 후까지 지속됐는지, 모든 방향을 봤는지, 패킷 손실이 없는지는 증명하지 않습니다.

## 프로토콜 관찰 범위

각 프로토콜에 대해 요청 계열과 응답 계열 이벤트를 구분합니다.

### EAP

```text
요청: eap_request
응답·결과: eap_response, eap_success, eap_failure
```

### RADIUS

```text
요청: radius_access_request
응답·결과: radius_access_challenge, radius_access_accept, radius_access_reject
```

### DHCP

```text
클라이언트 요청 계열: Discover, Request, Decline, Release, Inform
서버 응답 계열: Offer, ACK, NAK
```

### DNS

```text
요청: Query
응답: 정상 Response, 오류 Response
```

### TCP

```text
요청 방향 근거: SYN
응답·종료 근거: SYN/ACK, RST
```

요청·응답 계열이 모두 관찰돼도 `directionality_proven=false`를 유지합니다. 일부 거래에서 양쪽 계열이 보인다는 사실과 캡처 인프라가 모든 방향을 수집했다는 사실은 다릅니다.

## 미완료 거래 평가

### `response-not-observed`

다음 조건에서 사용합니다.

- 구조·이벤트·거래 분석이 모두 완전함
- 패킷 잘림 없음
- 이벤트·거래 근거 생략 없음
- 거래가 첫 프레임이나 마지막 관찰 프레임에 닿지 않음
- 명시적 최종 응답이 없음

의미는 “현재 보관된 중간 프레임 범위에서 응답을 관찰하지 못했다”이며 실패 확정이 아닙니다.

### `capture-boundary-risk`

거래의 첫 프레임이 캡처 첫 프레임이거나 마지막 프레임이 분석된 마지막 프레임일 때 사용합니다.

```text
capture-start-boundary-risk
capture-end-boundary-risk
```

캡처 시작 전 요청이나 캡처 종료 후 응답 가능성을 배제하지 않습니다.

### `packet-truncation-risk`

사전 점검에서 잘린 패킷이 하나 이상 관찰된 경우 사용합니다. 잘림과 해당 거래의 직접 인과관계는 확정하지 않지만 상위 프로토콜 필드 누락 가능성을 표시합니다.

### `insufficient-analysis-input`

다음 중 하나가 있으면 사용합니다.

```text
캡처 구조 일부 처리
이벤트 타임라인 일부 처리
거래 보고서 일부 처리
상세 이벤트 생략
거래 근거 프레임 생략
```

## 절대 금지되는 결론

다음 값은 항상 false입니다.

```text
capture_start_proven
capture_end_proven
capture_loss_excluded
directionality_proven
absence_can_confirm_failure
absence_is_failure
```

응답 미관찰만으로 다음을 확정하지 않습니다.

```text
ClearPass 장애
AD 장애
DHCP 서버 장애
DNS 서버 장애
방화벽 차단
서버 포트 미수신
무선 RF 손실
```

## 결과

전역 결과:

- 구조·타임라인·거래 완전성
- 점검 패킷·분석 프레임 수
- 잘린 패킷과 상세 이벤트 생략 수
- 프로토콜별 요청·응답 계열 관찰
- 캡처 시작·종료·손실·방향 증명 여부
- 응답 미관찰의 실패 확정 가능 여부

미완료 거래별 결과:

- 거래 시도 ID와 프로토콜
- 평가와 한국어 설명
- 첫·마지막 프레임
- 근거 프레임과 Wireshark 필터
- 위험 플래그
- 요청·응답 계열 관찰 여부
- 응답 부재의 실패 확정 여부

## 개인정보 보호

다음 값은 결과에 포함하지 않습니다.

```text
IPv4·IPv6 주소
원본 MAC·BSSID
SSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 거래 ID·Stream 번호
HMAC 키·내부 토큰
절대 epoch
Raw Payload·자격 증명
캡처 파일명·절대경로
TShark stderr 원문
```

## 자원 제한과 실패-폐쇄 처리

- 거래 시도 최대 50,000개
- 거래 근거 프레임 최대 64개
- 이벤트 수·프레임 수 교차 검증
- 중복 거래 ID·잘못된 프로토콜·프레임 범위·개수 불일치 거부
- 근본 원인 확정 값이 true인 입력 거부

## 자동 검증

### 단위 테스트

- 중간 DNS Query 미응답 → `response-not-observed`
- 첫·마지막 프레임 거래 → `capture-boundary-risk`
- 잘린 패킷 → `packet-truncation-risk`
- 일부 처리·이벤트 생략·근거 생략 → `insufficient-analysis-input`
- 완료 거래는 미응답 평가에서 제외
- 요청·응답 계열 관찰이 양방향 수집 증명으로 승격되지 않음
- 결정론적 직렬화와 식별정보 비노출
- 개수·프레임·확정 플래그 불일치 거부

### Portable 실제 패킷 검증

런타임 생성 PCAP:

```text
#1 ARP Request
#2 DNS Query — 응답 미관찰
#3 ARP Reply
#4 DNS Query — 마지막 프레임, 응답 미관찰
```

예상 결과:

```text
DNS-1-A1 = response-not-observed
DNS-2-A1 = capture-boundary-risk
DNS-2-A1 risk = capture-end-boundary-risk
absence_is_failure = false
absence_can_confirm_failure = false
```

외부 Python·Wireshark 없이 최종 EXE로 분석하고 결과의 경로·IP·MAC·DNS 질의명·원본 ID·절대 시간 비노출과 배포 폴더 무변경을 확인합니다.

## 완료 기준

- Windows 전체 단위 테스트·자체 점검·소스 감사·저장소 감사 통과
- GUI와 비대화형 JSON에 관찰 가능성 결과 제공
- Portable 미응답·경계 위험 실제 분석 통과
- 기존 Finding·거래·DEVICE-N·여정 게이트 유지
- `v0.10.0-alpha.1` Win64 Portable 프리릴리스 게시

## 다음 단계

Phase 4G 이후에는 PCAPNG Interface Statistics Block, 캡처 도구의 드롭 카운터와 타임스탬프 범위를 활용할 수 있는지 검토합니다. 그 다음 동일 단말 EAPOL 4-Way Handshake, 로밍·Radiotap RF 분석, Aruba·ClearPass 맞춤 안내와 오프라인 HTML 보고서를 진행합니다.
