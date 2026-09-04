# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 전송하지 않고 로컬에서 분석하여, 초급 네트워크 엔지니어에게 **접속 단계, 확인된 실패 응답, 시간순 이벤트, 프로토콜 거래 시도와 분석 실행별 단말·AP 가명**을 쉬운 한국어로 안내하는 도구입니다.

AI로 원인을 생성하지 않습니다. 프로그램 런타임에는 외부 API, 인터넷 통신, 텔레메트리, 자동 업데이트와 온라인 조회가 없습니다.

## 가장 쉬운 실행 방법

`v0.8.0-alpha.1` 릴리즈에서 다음 파일을 받습니다.

```text
WlanTroubleshooterKO-v0.8.0-alpha.1-win64-portable.zip
```

1. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
2. 압축을 푼 폴더의 `WlanTroubleshooterKO.exe`를 실행합니다.
3. `PCAP 또는 PCAPNG 파일 선택`을 누릅니다.
4. 사전 점검, Finding, 이벤트·거래 시도와 `DEVICE-N`·`AP-N` 결과를 확인합니다.

ZIP 안에서 EXE를 바로 실행하지 않습니다. Python, Wireshark, Node.js, 관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 분석 결과 구성

### 1. 캡처 사전 점검

- PCAP·PCAPNG 형식과 바이트 순서
- 인터페이스 수와 Link Type
- Snap Length와 패킷 레코드 수
- 잘린 패킷과 일부 스캔 여부
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부
- 현재 캡처에서 확인 가능한 항목과 확인할 수 없는 항목

### 2. 프로토콜 존재 인벤토리

내장 TShark가 Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP와 QUIC의 프레임 수 및 처음·마지막 프레임을 표시합니다.

### 3. 접속 단계 요약

다음 단계를 `성공 응답 관찰`, `실패 응답 관찰`, `성공·실패 혼합`, `진행 중 또는 불완전`, `관찰되지 않음`, `판단 불가`로 구분합니다.

```text
무선 연결
802.1X 시작·키 교환
EAP 인증
RADIUS 인증 서버
DHCP 주소 할당
DNS 이름 조회
ARP 주소 확인
TCP 연결
```

### 4. 근거 기반 Finding

명시적인 패킷 실패 코드가 있는 경우 다음 Finding을 생성합니다.

| Finding | 명시적 근거 |
|---|---|
| 무선 연결 거부 | Association/Reassociation 상태 코드가 0이 아님 |
| EAP 인증 실패 | EAP Failure, Code 4 |
| RADIUS 인증 거부 | Access-Reject, Code 3 |
| DHCP 주소 거부 | DHCP NAK, Message Type 6 |
| DNS 오류 | 응답 RCODE가 0이 아님 |
| TCP 연결 재설정 | TCP RST 플래그가 설정됨 |

Finding에는 등급, 설명, 근거 프레임, `frame.number` Display Filter와 다음 점검 항목이 포함됩니다. Deauthentication·Disassociation과 TCP 재전송은 `참고`로만 표시합니다.

### 5. 비식별 이벤트 타임라인

802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트를 캡처 시작 기준 상대 시간 순으로 표시합니다.

```text
+1,245ms · 프레임 #44 · DHCP ACK · 상관 별칭 DHCP-1 · 코드 5
Wireshark 필터: frame.number == 44
```

상관 별칭은 원본 거래 ID나 TShark Stream 번호가 아니라 해당 분석 안에서만 사용하는 순번입니다.

### 6. 비식별 프로토콜 거래 시도

동일 프로토콜의 이벤트를 다음과 같이 시도 단위로 묶습니다.

```text
EAP-1-A1
RADIUS-1-A1
DHCP-1-A1
DNS-1-A1
TCP-1-A1
```

| 프로토콜 | 필요 순서 완료 기준 |
|---|---|
| EAP | Request → Response → Success |
| RADIUS | Access-Request → Access-Accept |
| DHCP | Discover → Offer → Request → ACK |
| DNS | Query → 정상 Response |
| TCP | 최종 ACK를 안전하게 구분하지 않으므로 완전 완료 상태를 만들지 않음 |

거래는 `필요 순서 완료 관찰`, `성공 결과만 관찰`, `실패 결과 관찰`, `성공·실패 혼재`, `최종 결과 미확인`으로 구분합니다.

### 7. 분석 실행별 단말·AP 가명

Phase 4E는 원본 MAC·BSSID를 보고서에 표시하지 않고 다음 임시 가명을 만듭니다.

```text
DEVICE-1
DEVICE-2
AP-1
AP-2
```

예시:

```text
DEVICE-1
프레임: #5~#88
확인 근거: 802.11 Association 요청 · DHCP 클라이언트 송신
관찰 프로토콜: wlan · eapol · eap · dhcp · dns · tcp
관찰 AP 가명: AP-1
연결된 거래 시도: EAP-1-A1 · DHCP-1-A1 · DNS-1-A1 · TCP-1-A1
Wireshark 필터: frame.number == 5 || frame.number == 8 || ...
```

`DEVICE-1`과 `AP-1`은 **현재 분석 실행에서만** 의미가 있습니다. 프로그램을 종료하고 같은 캡처를 다시 분석해도 동일 대상을 같은 번호로 보장하지 않습니다.

## 단말 가명 생성 기준

서버·게이트웨이·AP를 단말로 잘못 분류하지 않기 위해 일반 DNS·TCP 주소만으로 새 `DEVICE-N`을 만들지 않습니다. 다음처럼 단말 방향이 명확한 패킷에서만 최초 등록합니다.

- 802.11 Authentication·Association·Reassociation 요청 송신자
- 해당 관리 응답 수신자
- BSSID를 제외한 802.11 EAP/EAPOL Supplicant 주소
- Ethernet EAP Request 수신자와 EAP Response 송신자
- EAP Success·Failure 수신자
- EAPOL Start·Logoff 송신자
- DHCP Discover·Request·Decline·Release·Inform 송신자

한 번 단말로 확인된 주소가 후속 DNS·TCP·TLS·ARP 프레임에 단 하나만 나타날 때만 해당 프레임과 거래 시도를 같은 `DEVICE-N`에 연결합니다.

## 모호함 처리

```text
한 프레임에 알려진 단말이 0개
→ 미할당

한 프레임에 알려진 단말이 1개
→ 해당 DEVICE-N에 연결 가능

한 프레임에 알려진 단말이 2개 이상
→ 모호함, 자동 연결하지 않음
```

RADIUS처럼 단말 L2 주소가 보이지 않는 서버 간 트래픽은 시간만 가깝다는 이유로 단말에 연결하지 않습니다.

## 가명화 개인정보 경계

가명화는 기존 공개 이벤트 출력과 분리된 `device-identities` 프로파일에서만 수행합니다.

허용하는 원문 L2 필드:

```text
eth.src
eth.dst
wlan.sa
wlan.da
wlan.bssid
```

원문 주소는 분석 중 메모리에서만 읽고, 실행마다 새로 생성한 32바이트 비밀키로 HMAC-SHA-256 처리합니다. 결과 객체에는 HMAC 결과도 넣지 않고 순번 가명만 남깁니다.

```text
raw_identifiers_serialized = false
alias_secret_persisted = false
aliases_stable_across_runs = false
```

다음 값은 GUI와 기본 JSON에 포함하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC 주소
원본 BSSID·SSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 EAP·RADIUS·DHCP·DNS 거래 ID
원본 TCP·UDP Stream 번호
절대 epoch 시간
HMAC digest와 가명화 키
Raw Payload·파일 내용
쿠키·Authorization·자격 증명
원본 파일명·절대경로
TShark 표준 오류 원문
```

TShark stdout과 Python 파싱 메모리에는 원문 L2 주소가 분석 중 일시적으로 존재할 수 있습니다. 따라서 메모리 덤프 공격까지 포함한 원문 주소 완전 비노출을 주장하지 않습니다. 디스크·로그·JSON·HTML·외부 전송에 원문을 남기지 않는 것이 현재 보장 범위입니다.

## 반드시 지켜야 할 해석 원칙

```text
DEVICE-1 = 실제 사용자 신원 아님
DEVICE-1 = 자산 번호 아님
AP-1 = 실제 AP 이름·위치 아님
같은 DEVICE-1에 여러 거래 연결 = 하나의 전체 접속 확정 아님
다른 분석의 DEVICE-1 = 같은 단말이라는 뜻 아님
RADIUS 미할당 = RADIUS 장애라는 뜻 아님
TCP 재전송 = RF 장애 확정 아님
패킷 미관찰 = 해당 단계 장애 확정 아님
```

각 단말 결과에는 다음 값이 고정됩니다.

```text
device_identity_confirmed = false
cross_protocol_session_confirmed = false
```

## 실행 안전장치

- 프로젝트에 포함된 고정 TShark만 사용
- 시스템 Wireshark·TShark 자동 사용 금지
- TShark 전체 파일 크기·SHA-256 실행 전후 검증
- 캡처 형식·크기·SHA-256 실행 전후 검증
- `-n` 이름 해석 비활성화
- 저장 캡처 `-r`, 패킷 상한 `-c`, 고정 fields만 허용
- 실시간·원격 캡처와 사용자 임의 옵션 차단
- 빈 설정·플러그인·extcap·임시 디렉터리 사용
- stdout·stderr 동시 처리와 크기·시간 상한
- 상세 이벤트·거래·가명 수 상한
- TShark stderr 원문 폐기
- 분석 취소 지원
- 종료 후 임시 작업공간 자동 삭제

## SHA-256 확인

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.8.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

릴리즈의 같은 이름 `.sha256` 파일과 출력값을 비교합니다. EXE에는 아직 상용 코드 서명 인증서가 없어 Windows가 `알 수 없는 게시자` 경고를 표시할 수 있습니다.

## 아직 지원하지 않는 기능

- `DEVICE-N` 내부에서 여러 접속 시도를 시간 구간별로 분리
- 서로 다른 프로토콜 거래를 하나의 완전한 단말 접속으로 확정
- RADIUS 서버 거래를 단말 세션에 안전하게 연결
- 동일 단말의 EAPOL 4-Way Handshake 메시지 1~4 완결성 판정
- 응답 미관찰과 캡처 누락·단방향 수집의 자동 구분
- BSSID·채널·RSSI 기반 로밍·RF 장애 상관분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 확인 절차
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 캡처 검증과 상용 코드 서명

세부 경계는 `docs/PHASE_4E_PLAN.md`와 `docs/adr/0004-analysis-scoped-device-pseudonyms.md`, 실제 검증 상태는 `IMPLEMENTATION_STATUS.md`를 확인합니다.
