# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 보내지 않고 로컬에서 분석해, 초급 네트워크 엔지니어에게 캡처 품질, 접속 단계, 명시적 실패, 비식별 거래, 단말·AP 가명, EAPOL-Key 및 PCAPNG 인터페이스 통계를 한국어로 안내하는 도구입니다.

제품 런타임에는 AI·LLM·Ollama·MCP·외부 API·인터넷 조회·텔레메트리·자동 업데이트가 없습니다.

## 실행 방법

`v0.13.0-alpha.1` 릴리스의 다음 파일을 사용합니다.

```text
WlanTroubleshooterKO-v0.13.0-alpha.1-win64-portable.zip
```

1. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
2. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
3. `WlanTroubleshooterKO.exe`를 실행합니다.
4. 로컬 PCAP 또는 PCAPNG를 선택합니다.

Python, Wireshark, Node.js, 관리자 권한과 인터넷 연결은 필요하지 않습니다. ZIP 내부에서 EXE를 바로 실행하지 않습니다.

## 분석 결과

### 1. 캡처 사전 점검

- PCAP·PCAPNG 형식과 바이트 순서
- 인터페이스 수와 Link Type
- Snap Length와 패킷 레코드 수
- 잘린 패킷과 일부 처리 여부
- Radiotap·IEEE 802.11 분석 가능 여부
- 현재 캡처에서 판단할 수 없는 항목

### 2. 프로토콜 인벤토리

내장 TShark로 Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP 및 QUIC의 관찰 프레임 수를 확인합니다.

프로토콜이 관찰됐다는 사실만으로 성공을 확정하지 않고, 보이지 않았다는 사실만으로 장애를 확정하지 않습니다.

### 3. 접속 단계와 Finding

다음 단계를 성공 응답 관찰, 실패 응답 관찰, 혼합, 진행 중·불완전, 미관찰 또는 판단 불가로 구분합니다.

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

명시적 패킷 결과가 있을 때만 다음 Finding을 만듭니다.

| Finding | 패킷 근거 |
|---|---|
| 무선 연결 거부 | Association/Reassociation 상태 코드가 0이 아님 |
| EAP 인증 실패 | EAP Failure |
| RADIUS 인증 거부 | Access-Reject |
| DHCP 주소 거부 | DHCP NAK |
| DNS 오류 | 응답 RCODE가 0이 아님 |
| TCP 연결 재설정 | TCP RST |

Finding에는 한국어 설명, 근거 프레임, `frame.number` Display Filter와 다음 점검 항목이 포함됩니다. 실패 패킷이 보여도 책임 시스템이나 근본 원인은 확정하지 않습니다.

### 4. 비식별 이벤트·거래·단말 여정

원본 거래 ID·주소·사용자명 대신 현재 분석에만 유효한 별칭을 사용합니다.

```text
EAP-1-A1
RADIUS-1-A1
DHCP-1-A1
DNS-1-A1
TCP-1-A1
DEVICE-1
AP-1
```

원본 MAC·BSSID는 실행마다 새로 생성하는 HMAC 키로 내부 처리하고, 키·내부 토큰·원본 주소는 저장하거나 직렬화하지 않습니다. 단일 L2 근거가 있는 거래만 `DEVICE-N`에 연결하며, 시간 근접성만으로 RADIUS나 여러 프로토콜을 같은 사용자 세션으로 확정하지 않습니다.

### 5. 캡처 관찰 가능성과 미응답 해석

```text
response-not-observed
capture-boundary-risk
packet-truncation-risk
insufficient-analysis-input
```

다음 값은 항상 `false`입니다.

```text
capture_start_proven
capture_end_proven
capture_loss_excluded
directionality_proven
absence_can_confirm_failure
absence_is_failure
```

응답이 보이지 않았다는 사실만으로 ClearPass·DHCP·DNS·방화벽·서버·RF 장애를 확정하지 않습니다.

### 6. EAPOL-Key M1~M4 메시지 순서

```text
EAPOL-HS-1 · DEVICE-1 ↔ AP-1
관찰: M1 → M2 → M3 → M3 → M4
반복 메시지 번호: M3
802.11 Retry 비트 프레임: #8
```

M1~M4가 모두 보여도 동일한 한 번의 Handshake, 키 설치, 암호학적 성공 또는 전체 무선 접속 성공을 확정하지 않습니다.

### 7. Replay Counter 비식별 관계

Replay Counter는 전용 최소 TShark 프로파일에서만 분석 중 일시적으로 읽고, 숫자를 GUI·JSON·로그에 기록하지 않습니다.

```text
M1/M2: 같은 Counter 관계 관찰
M3/M4: 같은 Counter 관계 관찰
M1→M3: 후반 Counter 증가 관계 관찰
반복 M3: 같은 Counter 관계 관찰
```

다음 값은 항상 `false`입니다.

```text
raw_replay_counters_serialized
replay_counter_values_persisted
same_handshake_confirmed
retransmission_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

같은 메시지와 같은 Counter가 반복돼도 실제 재전송으로 확정하지 않습니다.

### 8. PCAPNG Interface Statistics Block

PCAPNG의 다음 숫자 Counter만 로컬에서 읽습니다.

```text
isb_ifrecv
isb_ifdrop
isb_filteraccept
isb_osdrop
isb_usrdeliv
```

실제 인터페이스 이름·설명 대신 선언 순서 기반 `IFACE-N`을 사용합니다. 여러 ISB는 누적 스냅샷일 수 있으므로 합산하지 않고 각 Counter의 관찰 횟수, 첫 보고값, 마지막 보고값과 변화 방향만 제공합니다.

상태:

```text
reported-drop-observed
zero-reported-drop-counters
statistics-without-drop-counters
no-interface-statistics
unsupported-capture-format
```

Counter 변화:

```text
not-reported
single-value-observed
counter-increase-observed
counter-decrease-observed
counter-unchanged-observed
```

중요한 해석 원칙:

```text
드롭 Counter 0 ≠ 캡처 무손실 증명
ISB 없음 ≠ 캡처 무손실 증명
양수 드롭 Counter ≠ 특정 패킷 누락 확정
양수 드롭 Counter ≠ RF·AP·단말·SPAN 장애 확정
Counter 감소 ≠ 재시작·초기화·wrap 확정
```

다음 값은 항상 `false`입니다.

```text
raw_interface_identifiers_serialized
absolute_timestamps_serialized
capture_loss_excluded
specific_packet_loss_confirmed
root_cause_confirmed
```

일반 PCAP은 `unsupported-capture-format`으로 표시하지만, 이 상태 역시 캡처 손실이 없다는 뜻은 아닙니다.

## 사내 데이터 보호

GUI·기본 JSON·로그·릴리스 자산에 다음 값을 기록하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 거래 ID·Stream 번호
HMAC 키·내부 토큰
Replay Counter 원문
Nonce·MIC·Key Data
암호화 키·자격 증명
인터페이스 이름·설명·GUID·장치 경로
하드웨어·운영체제·캡처 애플리케이션 문자열
PCAPNG 주석과 캡처 필터
절대 ISB Timestamp
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

원본 L2 주소와 Replay Counter는 분석 중 프로세스 메모리에 일시적으로 존재할 수 있습니다. 현재 보장 범위는 디스크·로그·GUI·JSON·릴리스 자산·외부 네트워크에 남기지 않는 것입니다.

## 실행 안전장치

- 배포본의 고정 TShark만 사용
- 시스템 Wireshark·PATH 대체 실행 금지
- TShark 파일 크기·SHA-256 실행 전후 검증
- 캡처 형식·크기·SHA-256 분석 단계별 재검증
- 이름 해석 비활성화 `-n`
- 저장 캡처 `-r`, 패킷 상한 `-c`, 승인된 fields만 허용
- 실시간·원격 캡처와 사용자 임의 옵션 차단
- 빈 config·plugin·extcap·data·temp 경로 사용
- stdout·stderr 크기·시간 상한
- 임시 작업공간 자동 삭제
- Symlink·Junction·Reparse Point 우회 차단

## SHA-256 확인

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.13.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

릴리스의 같은 이름 `.sha256` 파일과 비교합니다. EXE에는 아직 상용 코드 서명 인증서가 없어 Windows에서 `알 수 없는 게시자` 경고가 표시될 수 있습니다.

## 아직 지원하지 않는 기능

- ISB Counter로 특정 누락 패킷 식별
- 캡처 시작·종료가 장애 전체 구간을 포함했는지 자동 증명
- 응답 미관찰을 실제 미응답으로 확정
- 프레임별 비식별 `DEVICE-N ↔ AP-N` 로밍 연결
- RSSI·채널·데이터율 기반 RF 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 단일 오프라인 한국어 HTML 보고서
- 실제 사내 캡처의 오탐·미탐 검증
- 상용 코드 서명

세부 경계는 `docs/PHASE_4K_PLAN.md`, 가명화 설계는 `docs/adr/0004-analysis-scoped-device-pseudonyms.md`, 검증 상태는 `IMPLEMENTATION_STATUS.md`를 확인합니다.
