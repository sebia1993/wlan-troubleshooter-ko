# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 전송하지 않고 로컬에서 분석하여, 초급 네트워크 엔지니어에게 **캡처 품질, 접속 단계, 명시적 실패, 비식별 거래, 분석 실행별 단말·AP 가명, 단말별 관찰 여정과 미응답 해석 경계**를 한국어로 안내하는 도구입니다.

AI·LLM·Ollama·외부 API·인터넷 조회·텔레메트리·자동 업데이트를 사용하지 않습니다.

## 가장 쉬운 실행 방법

`v0.10.0-alpha.1` 릴리스에서 다음 파일을 받습니다.

```text
WlanTroubleshooterKO-v0.10.0-alpha.1-win64-portable.zip
```

1. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
2. `WlanTroubleshooterKO.exe`를 실행합니다.
3. `PCAP 또는 PCAPNG 파일 선택`을 누릅니다.
4. 사전 점검부터 캡처 관찰 가능성과 미응답 해석까지 확인합니다.

ZIP 내부에서 EXE를 바로 실행하지 않습니다. Python, Wireshark, Node.js, 관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 분석 결과 구성

### 1. 캡처 사전 점검

- PCAP·PCAPNG 형식과 바이트 순서
- 인터페이스 수와 Link Type
- Snap Length와 패킷 레코드 수
- 잘린 패킷과 일부 처리 여부
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부
- 현재 캡처에서 확인할 수 없는 항목

### 2. 프로토콜 존재 인벤토리

내장 TShark가 Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP와 QUIC의 프레임 수 및 처음·마지막 프레임을 표시합니다.

프로토콜이 관찰됐다는 사실만으로 성공을 확정하지 않고, 보이지 않았다는 사실만으로 장애를 확정하지 않습니다.

### 3. 접속 단계 요약

다음 단계를 `성공 응답 관찰`, `실패 응답 관찰`, `성공·실패 혼합`, `진행 중 또는 불완전`, `관찰되지 않음`, `판단 불가`로 구분합니다.

```text
무선 연결
802.1X·EAPOL
EAP 인증
RADIUS 인증 서버
DHCP 주소 할당
DNS 이름 조회
ARP 주소 확인
TCP 연결
```

### 4. 근거 기반 Finding

명시적인 패킷 결과가 있을 때만 Finding을 만듭니다.

| Finding | 패킷 근거 |
|---|---|
| 무선 연결 거부 | Association/Reassociation 상태 코드가 0이 아님 |
| EAP 인증 실패 | EAP Failure |
| RADIUS 인증 거부 | Access-Reject |
| DHCP 주소 거부 | DHCP NAK |
| DNS 오류 | 응답 RCODE가 0이 아님 |
| TCP 연결 재설정 | TCP RST |

Finding에는 설명, 근거 프레임, `frame.number` Display Filter와 다음 점검 항목이 포함됩니다. Deauthentication·Disassociation과 TCP 재전송은 참고 근거로만 사용합니다.

### 5. 비식별 이벤트 타임라인

802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트를 캡처 시작 기준 상대 시간 순으로 정리합니다.

```text
+1,245ms · 프레임 #44 · DHCP ACK · DHCP-1
Wireshark 필터: frame.number == 44
```

절대 시각과 원본 거래 ID는 결과에 기록하지 않습니다.

### 6. 비식별 프로토콜 거래 시도

동일 프로토콜의 요청·중간 이벤트·최종 응답을 시도 단위로 묶습니다.

```text
EAP-1-A1
RADIUS-1-A1
DHCP-1-A1
DNS-1-A1
TCP-1-A1
```

| 프로토콜 | 완료 관찰 기준 |
|---|---|
| EAP | Request → Response → Success |
| RADIUS | Access-Request → Access-Accept |
| DHCP | Discover → Offer → Request → ACK |
| DNS | Query → 정상 Response |
| TCP | 최종 ACK를 안전하게 구분하지 않으므로 완료 확정 안 함 |

거래 상태는 `complete`, `success-observed`, `failure-observed`, `mixed`, `incomplete`로 구분합니다.

### 7. 분석 실행별 단말·AP 가명

원본 MAC·BSSID를 공개 결과에 기록하지 않고 현재 분석 실행에서만 유효한 가명을 만듭니다.

```text
DEVICE-1
DEVICE-2
AP-1
AP-2
```

가명화 원칙:

- 실행마다 운영체제 CSPRNG로 32바이트 비밀키 생성
- HMAC-SHA-256 내부 토큰 사용
- 원본 MAC·BSSID, HMAC 토큰과 비밀키 미직렬화
- 키를 파일·로그·레지스트리·환경변수에 저장하지 않음
- 다른 실행의 같은 `DEVICE-N`과 비교 불가
- 단일 단말 L2 근거가 있는 프레임과 거래만 연결
- RADIUS처럼 단말 L2 근거가 없는 거래는 시간만으로 연결하지 않음
- 모호하거나 불완전한 근거는 미할당 유지

일반 DNS·TCP·TLS·ARP 주소만으로 새 `DEVICE-N`을 만들지 않습니다. 802.11 관리 프레임, 직접 EAPOL/EAP 방향과 DHCP 클라이언트 방향처럼 단말 역할이 명확한 근거에서만 최초 등록합니다.

### 8. 단말 가명별 접속 관찰 여정

`DEVICE-N`에 이미 안전하게 연결된 거래만 모아 실제 근거 프레임 순서로 관찰 여정을 만듭니다.

```text
DEVICE-1
관찰 단계: DHCP → DNS → TCP
첫 실패 관찰 단계: TCP
마지막 성공 방향 단계: TCP
```

각 여정은 연결 거래, 단계별 상태, AP 가명, 근거 프레임과 Wireshark 필터를 제공합니다.

| 여정 상태 | 의미 |
|---|---|
| `progress-observed` | 연결된 단계에서 성공 방향 진행이 관찰됨 |
| `failure-observed` | 한 개 이상 단계에서 명시적 실패가 관찰됨 |
| `mixed` | 같은 단계 또는 여정에 성공과 실패가 함께 있음 |
| `partial-progress` | 성공 방향 단계와 최종 결과 미확인 단계가 함께 있음 |
| `incomplete` | 연결 거래는 있지만 명시적 최종 결과가 없음 |
| `no-linked-transactions` | 단말 가명은 있지만 안전하게 연결된 거래가 없음 |

단말 여정은 동일 사용자 신원이나 하나의 완전한 교차 프로토콜 세션을 확정하지 않습니다. `첫 실패 관찰 단계`는 실패 패킷이 처음 보인 위치이며 근본 원인의 위치가 아닙니다.

### 9. 캡처 관찰 가능성과 미응답 해석

Phase 4G는 `응답이 보이지 않았다`는 사실과 `장애가 확인됐다`는 결론을 분리합니다.

불완전 거래는 다음 중 하나로 표시합니다.

| 상태 | 의미 |
|---|---|
| `response-not-observed` | 현재 보관된 중간 프레임 범위에서 최종 응답을 관찰하지 못함 |
| `capture-boundary-risk` | 거래가 첫 프레임 또는 마지막 관찰 프레임에 닿아 캡처 전·후 패킷 가능성이 있음 |
| `packet-truncation-risk` | 잘린 패킷 때문에 상위 프로토콜 응답 필드가 누락됐을 수 있음 |
| `insufficient-analysis-input` | 일부 처리, 이벤트 생략 또는 거래 근거 생략으로 해석할 수 없음 |

예시:

```text
DNS-1-A1
평가: 응답 미관찰
근거: frame.number == 2
응답 부재를 장애로 확정: 아니오
```

```text
DNS-2-A1
평가: 캡처 종료 경계 위험
위험 요소: capture-end-boundary-risk
응답 부재를 장애로 확정: 아니오
```

프로토콜별 요청·응답 계열 이벤트가 모두 보이더라도 양방향 전체 수집을 증명하지 않습니다.

다음 값은 항상 `false`입니다.

```text
capture_start_proven
capture_end_proven
capture_loss_excluded
directionality_proven
absence_can_confirm_failure
absence_is_failure
```

파일을 끝까지 읽었다는 사실만으로 다음을 알 수는 없습니다.

- 장애 발생 전부터 캡처했는지
- 장애 종료 후까지 캡처했는지
- 미러링·무선 채널·캡처 프로그램에서 패킷을 잃지 않았는지
- 송신과 수신 방향을 모두 보았는지

따라서 DNS Query만 보이거나 TCP SYN만 보이는 경우 서버·방화벽·ClearPass·DHCP·DNS 장애로 자동 확정하지 않습니다.

## 중요한 해석 원칙

```text
EAP Success 관찰 ≠ 전체 접속 성공 확정
RADIUS Access-Accept 관찰 ≠ 사용자 서비스 정상 확정
RADIUS Access-Reject 관찰 ≠ ClearPass 자체 장애 확정
DHCP ACK 관찰 ≠ 이후 통신 정상 확정
TCP SYN/ACK 관찰 ≠ 3-Way Handshake 완료 확정
TCP RST 관찰 ≠ 서버·방화벽·애플리케이션 중 원인 확정
TCP Retransmission 관찰 ≠ RF 장애 확정
프로토콜 미관찰 ≠ 해당 단계 장애
첫 실패 관찰 단계 ≠ 근본 원인 발생 위치
응답 미관찰 ≠ 응답 시스템 장애 확정
```

## 개인정보·사내 데이터 보호

다음 값은 GUI와 기본 JSON에 포함하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 EAP·RADIUS·DHCP·DNS 거래 ID
원본 TCP·UDP Stream 번호
HMAC 키·HMAC 내부 토큰
절대 epoch
Raw Payload·파일 내용
쿠키·Authorization·자격 증명
원본 파일명·절대경로
TShark 표준 오류 원문
```

원본 L2 주소는 전용 TShark stdout과 Python 파싱 메모리에 분석 중 일시적으로 존재할 수 있습니다. 보장 범위는 디스크·로그·JSON·GUI·릴리스 자산·외부 네트워크에 남기지 않는 것입니다.

## 실행 안전장치

- 프로젝트에 포함된 고정 TShark만 사용
- 시스템 Wireshark·TShark 자동 사용 금지
- TShark 전체 파일 크기·SHA-256 실행 전후 검증
- 캡처 형식·크기·SHA-256을 각 분석 단계 전후 검증
- `-n` 이름 해석 비활성화
- 저장 캡처 `-r`, 패킷 상한 `-c`, 고정 fields만 허용
- 실시간·원격 캡처와 사용자 임의 옵션 차단
- 빈 설정·플러그인·extcap·임시 디렉터리 사용
- stdout·stderr 동시 처리와 크기·시간 상한
- 분석 취소 지원
- 임시 작업공간 자동 삭제
- Symlink·Junction·Reparse Point 우회 차단

## 자원 제한

- 고정 분석 프로파일 최대 100,000프레임
- 상세 이벤트 최대 2,000건
- 거래 시도 최대 50,000개
- 단말·AP 가명 각각 최대 20,000개
- 거래 근거 프레임 최대 64개
- 여정 근거 프레임 최대 96개
- TShark stdout 기본 64MiB
- TShark stderr 기본 1MiB
- 기본 실행 제한시간 180초

근거가 생략되거나 일부 처리된 경우 결과를 더 보수적으로 낮추며 장애 확정으로 승격하지 않습니다.

## SHA-256 확인

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.10.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

릴리스의 같은 이름 `.sha256` 파일과 출력값을 비교합니다. EXE에는 아직 상용 코드 서명 인증서가 없어 Windows가 `알 수 없는 게시자` 경고를 표시할 수 있습니다.

## 아직 지원하지 않는 기능

- `DEVICE-N`을 실제 사용자·자산 신원으로 확정
- 여러 프로토콜 거래가 하나의 완전한 사용자 세션임을 확정
- 캡처 프로그램·SPAN·무선 채널의 실제 패킷 드롭 통계 수집
- 응답 미관찰을 실제 미응답으로 확정하는 기능
- 동일 단말의 EAPOL 4-Way Handshake 메시지 1~4 완결성 판정
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 단일 오프라인 한국어 HTML 보고서
- 실제 사내 Aruba·ClearPass 캡처 검증
- 네트워크 어댑터 비활성·Outbound 차단·EDR 환경 검증
- 상용 코드 서명 인증서 적용

세부 경계는 `docs/PHASE_4G_PLAN.md`, 단말 가명화 경계는 `docs/adr/0004-analysis-scoped-device-pseudonyms.md`, 실제 검증 상태는 `IMPLEMENTATION_STATUS.md`를 확인합니다.
