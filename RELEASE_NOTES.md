# v0.10.0-alpha.1 — 캡처 관찰 가능성과 미응답 해석 프리뷰

이번 릴리스는 기존 단말 가명별 관찰 여정에 **캡처 관찰 가능성과 미응답 해석 경계**를 추가합니다. 요청이 보이고 응답이 보이지 않는 상황을 서버·방화벽·ClearPass·DHCP·DNS 장애로 자동 확정하지 않습니다.

Python과 Wireshark를 별도로 설치할 필요가 없습니다. AI·LLM·외부 API·인터넷 조회·텔레메트리·자동 업데이트도 사용하지 않습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.10.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- 구조 점검·이벤트 타임라인·거래 보고서 완전성 교차 확인
- EAP·RADIUS·DHCP·DNS·TCP 요청 계열과 응답 계열 이벤트 관찰 범위
- 중간 프레임의 응답 미관찰과 캡처 파일 경계 위험 구분
- 잘린 패킷, 이벤트 상세 생략과 거래 근거 생략 위험 표시
- 미완료 거래별 근거 프레임과 Wireshark `frame.number` 필터
- GUI `[9. 캡처 관찰 가능성과 미응답 해석]`
- 기존 최상위 JSON `schema_version = 2`를 유지하는 `capture_observability` 추가 결과

## 미완료 거래 평가

| 평가 | 의미 |
|---|---|
| `response-not-observed` | 현재 보관된 중간 프레임 범위에서 명시적인 최종 응답을 관찰하지 못함 |
| `capture-boundary-risk` | 거래가 첫 프레임 또는 마지막 관찰 프레임에 닿아 캡처 전·후 패킷 가능성이 있음 |
| `packet-truncation-risk` | 잘린 패킷 때문에 응답 또는 상위 프로토콜 필드가 누락됐을 수 있음 |
| `insufficient-analysis-input` | 구조·이벤트·거래 분석 일부 또는 상세 근거 생략 때문에 해석 불가 |

모든 경우 다음 값은 `false`입니다.

```text
absence_is_failure
capture_loss_excluded
directionality_proven
```

## 전역 캡처 경계

파일을 끝까지 읽었더라도 다음을 증명하지 않습니다.

```text
capture_start_proven = false
capture_end_proven = false
capture_loss_excluded = false
directionality_proven = false
absence_can_confirm_failure = false
```

이는 다음 가능성을 현재 파일만으로 배제할 수 없기 때문입니다.

- 장애 발생 전 요청이 이미 지나감
- 캡처 종료 후 응답이 도착함
- SPAN·미러링·무선 채널에서 일부 패킷이 누락됨
- 캡처 프로그램 내부 드롭이 발생함
- 송신 또는 수신 한 방향만 관찰됨
- Snap Length 때문에 상위 필드가 잘림
- 패킷·이벤트 처리 상한으로 일부만 분석됨

요청 계열과 응답 계열 이벤트가 모두 관찰돼도 모든 방향과 모든 패킷을 수집했다는 뜻은 아닙니다.

## Portable 실제 통합검증

릴리스 빌드는 Python 환경변수와 일반 Python PATH를 제거한 상태에서 최종 `WlanTroubleshooterKO.exe`를 실행합니다.

런타임 생성 PCAP에는 다음 네 프레임이 들어갑니다.

```text
#1 ARP Request
#2 DNS Query — 응답 없음
#3 ARP Reply
#4 DNS Query — 파일 마지막 프레임, 응답 없음
```

예상 결과:

```text
DNS-1-A1
assessment = response-not-observed
risk_flags = []
absence_is_failure = false
```

```text
DNS-2-A1
assessment = capture-boundary-risk
risk_flags = [capture-end-boundary-risk]
absence_is_failure = false
```

추가 검증:

- DNS 요청 계열 관찰 `true`, 응답 계열 관찰 `false`
- 양방향 수집 증명 `false`
- 캡처 시작·종료 시점 증명 `false`
- 캡처 손실 배제 `false`
- 응답 미관찰만으로 실패 확정 `false`
- 원본 IP·MAC·DNS 질의명·거래 ID·절대 시간·파일 경로 비노출
- 분석 전후 Portable 배포 폴더 무변경
- 외부 Python·Wireshark 미사용

기존 Finding, 이벤트 타임라인, 거래 시도, `DEVICE-N`·`AP-N` 가명과 단말 관찰 여정 게이트도 함께 통과해야 릴리스됩니다.

## 개인정보 및 오프라인 경계

Phase 4G는 이미 비식별화된 구조·이벤트·거래 메타데이터만 사용합니다. 다음 값은 결과에 기록하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 거래 ID·Stream 번호
HMAC 키·HMAC 내부 토큰
절대 epoch
Raw Payload·자격 증명
원본 파일명·절대경로
TShark stderr 원문
```

## 호환성

기존 분석 JSON의 최상위 `schema_version = 2`를 유지합니다. `capture_observability`는 기존 인벤토리·Finding·타임라인·거래·단말 가명·여정 결과를 변경하지 않는 추가 항목입니다.

## 아직 지원하지 않는 기능

- 캡처 프로그램·SPAN·무선 드라이버의 실제 패킷 드롭 카운터 수집
- 캡처 시작·종료가 장애 구간을 완전히 포함했는지 자동 증명
- 응답 미관찰을 실제 미응답으로 확정
- 동일 단말의 EAPOL 4-Way Handshake 메시지 1~4 완결성 판정
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 단일 오프라인 한국어 HTML 보고서
- 실제 사내 Aruba·ClearPass 캡처 검증
- 애플리케이션 EXE 상용 코드 서명

## 릴리스 자산

- `WlanTroubleshooterKO-v0.10.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.10.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
