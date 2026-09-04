# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 전송하지 않고 로컬에서 분석하여, 초급 네트워크 엔지니어에게 **접속 단계, 확인된 실패 응답, 근거 프레임, 다음 점검 항목과 시간순 이벤트**를 쉬운 한국어로 안내하는 도구입니다.

AI로 원인을 생성하지 않습니다. 프로그램 런타임에는 외부 API, 인터넷 통신, 텔레메트리, 자동 업데이트와 온라인 조회가 없습니다.

## 가장 쉬운 실행 방법

`v0.6.0-alpha.1` 릴리즈에서 다음 파일을 받습니다.

```text
WlanTroubleshooterKO-v0.6.0-alpha.1-win64-portable.zip
```

1. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
2. 압축을 푼 폴더의 `WlanTroubleshooterKO.exe`를 실행합니다.
3. `PCAP 또는 PCAPNG 파일 선택`을 누릅니다.
4. 사전 점검, 프로토콜 인벤토리, 접속 단계, Finding과 이벤트 타임라인을 확인합니다.

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

내장 TShark가 실제 캡처를 읽고 Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP와 QUIC의 프레임 수 및 처음·마지막 프레임을 표시합니다.

### 3. 접속 단계 요약

다음 단계를 각각 `성공 응답 관찰`, `실패 응답 관찰`, `성공·실패 혼합`, `진행 중 또는 불완전`, `관찰되지 않음`, `판단 불가`로 구분합니다.

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

패킷에 명시적인 실패 코드가 기록된 경우 다음 Finding을 생성합니다.

| Finding | 명시적 근거 |
|---|---|
| 무선 연결 거부 | Association/Reassociation 상태 코드가 0이 아님 |
| EAP 인증 실패 | EAP Failure, Code 4 |
| RADIUS 인증 거부 | Access-Reject, Code 3 |
| DHCP 주소 거부 | DHCP NAK, Message Type 6 |
| DNS 오류 | 응답 RCODE가 0이 아님 |
| TCP 연결 재설정 | TCP RST 플래그가 설정됨 |

각 Finding에는 등급, 단계, 한국어 설명, 근거 프레임 번호, `frame.number` Display Filter와 다음 점검 항목이 포함됩니다. Deauthentication·Disassociation과 TCP 재전송은 다른 상황에서도 발생할 수 있어 `참고`로만 표시합니다.

### 5. 비식별 이벤트 타임라인

동일한 고정 TShark 출력에서 다음 이벤트를 캡처 시작 기준 상대 시간 순으로 정리합니다.

| 범주 | 표시 이벤트 |
|---|---|
| IEEE 802.11 | 인증 요청·응답, Association/Reassociation 요청·응답, Deauthentication, Disassociation, Retry |
| EAPOL | Start, Logoff, EAP Packet, Key, 확인 가능한 메시지 번호 1~4 |
| EAP | Request, Response, Success, Failure |
| RADIUS | Access-Request, Access-Challenge, Access-Accept, Access-Reject, Accounting |
| DHCP | Discover, Offer, Request, ACK, NAK, Decline, Release, Inform |
| DNS | Query, 정상 Response, 오류 Response |
| ARP | Request, Reply |
| TCP | SYN, SYN/ACK, RST, Retransmission 표시 |
| TLS | ClientHello, ServerHello, Certificate, Finished |

각 이벤트에는 상대 시간, 프레임 번호, 한국어 이벤트명, 명시적 코드, 로컬 상관 별칭과 재확인용 `frame.number == N` 필터만 표시합니다.

```text
+1,245ms · 프레임 #44 · DHCP ACK · 상관 별칭 DHCP-1 · 코드 5
Wireshark 필터: frame.number == 44
```

상관 별칭은 원본 거래 ID나 스트림 번호가 아닙니다.

```text
EAP-1
RADIUS-1
DHCP-1
DNS-1
TCP-1
```

## 해석 원칙

```text
EAP Success 관찰 ≠ 전체 접속 성공 확정
RADIUS Access-Accept 관찰 ≠ 사용자 서비스 정상 확정
RADIUS Access-Reject 관찰 ≠ ClearPass 자체 장애 확정
DHCP ACK 관찰 ≠ 이후 통신 정상 확정
TCP RST 관찰 ≠ 서버·방화벽·애플리케이션 중 원인 확정
TCP Retransmission 관찰 ≠ RF 장애 확정
프로토콜 미관찰 ≠ 해당 단계 장애
```

기본 결과에는 단말 식별자를 사용하지 않습니다. 여러 단말과 여러 접속이 섞인 캡처를 하나의 세션으로 자동 결합하지 않으며, 성공과 실패가 함께 보이면 혼재 상태로 표시합니다. EAPOL Key 메시지 번호 1~4가 모두 보여도 동일 단말의 한 번의 4-Way Handshake라고 확정하지 않습니다.

DHCP·DNS·TCP 요청 뒤 응답이 보이지 않은 경우에도 캡처 누락 가능성이 있으므로 `판단 불가`로 유지합니다. 일부 프레임만 처리했거나 후속 시간이 짧으면 미응답 Finding 자체를 만들지 않습니다.

## 데이터 보호

상관분석에 필요한 거래 ID와 내부 스트림 번호는 메모리에서만 사용하고 즉시 로컬 순번 별칭으로 변환합니다. 다음 값은 GUI와 기본 JSON에 포함하지 않습니다.

```text
IPv4·IPv6 주소
Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
DHCP·DNS·EAP·RADIUS 원본 거래 ID
TCP·UDP 내부 스트림 번호
절대 epoch 시간
Raw Payload·파일 내용
쿠키·Authorization·자격 증명
원본 파일명·절대경로
TShark 표준 오류 원문
```

## 실행 안전장치

- 프로젝트에 포함된 고정 TShark만 사용
- TShark 전체 파일의 크기·SHA-256을 실행 전후 검증
- 캡처의 형식·크기·SHA-256을 실행 전후 검증
- `-n`으로 네트워크 이름 해석 비활성화
- 저장 캡처 `-r`, 패킷 상한 `-c`와 고정 필드만 허용
- 실시간·원격 캡처와 사용자 임의 옵션 차단
- 빈 설정·플러그인·extcap·임시 디렉터리 사용
- stdout·stderr 동시 처리로 교착 방지
- 출력 크기·실행시간·패킷 수 상한
- 상세 이벤트 2,000개 보관 상한과 유형별 전체 집계 유지
- TShark 표준 오류 원문 폐기
- 분석 취소 지원
- 종료 후 임시 작업공간 자동 삭제

프로토콜 인벤토리, Finding과 타임라인은 캡처를 다시 읽지 않고 동일한 한 번의 고정 fields 출력에서 생성합니다.

## Portable 패키지 구성

```text
WlanTroubleshooterKO.exe       사용자 프로그램
_internal/                     내장 Python 3.13·Tcl/Tk 런타임
vendor/wireshark/tshark.exe    내장 Wireshark 4.6.8 패킷 해석 엔진
vendor/wireshark/manifest.json TShark 전체 파일 무결성 목록
licenses/                      Python·Tcl·Tk·PyInstaller 라이선스
BUILD_INFO.json                버전·공급망·분석 런타임 상태
```

Wireshark GUI, `dumpcap.exe`, Npcap 설치 파일과 extcap 실행 도구는 포함하지 않습니다.

## SHA-256 확인

릴리즈에는 Portable ZIP과 같은 이름의 `.sha256` 파일이 제공됩니다.

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.6.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

출력값이 `.sha256` 파일과 같은지 확인합니다. 애플리케이션 EXE의 상용 코드 서명 인증서는 아직 없으므로 Windows가 `알 수 없는 게시자` 경고를 표시할 수 있습니다.

## 아직 지원하지 않는 기능

- MAC·SSID를 결과에 노출하지 않는 단말별 익명 세션 분리
- 동일 단말의 완전한 EAP·RADIUS·4-Way Handshake 세션 결합
- 응답 미관찰과 캡처 누락의 자동 확정 구분
- BSSID·채널·RSSI 기반 로밍·RF 장애 상관분석
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 한국어 HTML 보고서
- 실시간·원격 캡처
- 장비 로그인·조회·설정 변경
- 온라인 OUI·WHOIS·GeoIP 조회

세부 구현 경계는 `docs/PHASE_4C_PLAN.md`, 실제 검증 상태는 `IMPLEMENTATION_STATUS.md`, 제3자 고지는 `THIRD_PARTY_NOTICES.md`를 확인합니다.
