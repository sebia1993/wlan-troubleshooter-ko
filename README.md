# wlan-troubleshooter-ko

Windows 11에서 PCAP·PCAPNG를 외부로 전송하지 않고 로컬에서 분석하는 한국어 무선 네트워크 장애 분석기입니다. 초급 네트워크 엔지니어가 캡처 품질, 접속 단계, 명시적 실패, 비식별 거래, `DEVICE-N`·`AP-N`, 단말 관찰 여정, 미응답 해석, EAPOL-Key M1~M4와 Replay Counter 관계를 확인할 수 있습니다.

제품 런타임에는 AI·LLM·Ollama·외부 API·인터넷 조회·텔레메트리·자동 업데이트가 없습니다.

## 실행

`v0.12.0-alpha.1` 릴리스의 다음 파일을 사용합니다.

```text
WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip
```

1. ZIP과 같은 이름의 `.sha256` 파일을 비교합니다.
2. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
3. `WlanTroubleshooterKO.exe`를 실행합니다.
4. PCAP 또는 PCAPNG를 선택합니다.

Python, Wireshark, Node.js, 관리자 권한과 인터넷 연결은 필요하지 않습니다. ZIP 내부에서 EXE를 바로 실행하지 않습니다.

## 분석 결과

### 캡처 사전 점검

- PCAP·PCAPNG 구조와 바이트 순서
- Interface와 Link Type
- Snap Length와 잘린 패킷
- Radiotap·IEEE 802.11·IP 경로 분석 가능 범위
- 일부 처리 여부와 판단할 수 없는 항목

### 프로토콜·접속 단계·Finding

내장 TShark로 Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP와 QUIC 존재 여부를 확인합니다.

명시적인 패킷 결과가 있을 때만 다음 Finding을 만듭니다.

| Finding | 패킷 근거 |
|---|---|
| 무선 연결 거부 | Association/Reassociation 상태 코드가 0이 아님 |
| EAP 인증 실패 | EAP Failure |
| RADIUS 인증 거부 | Access-Reject |
| DHCP 주소 거부 | DHCP NAK |
| DNS 오류 | 응답 RCODE가 0이 아님 |
| TCP 연결 재설정 | TCP RST |

실패 패킷이 보여도 책임 시스템이나 근본 원인은 확정하지 않습니다.

### 비식별 이벤트와 거래 시도

캡처 시작 기준 상대 시간, 로컬 거래 별칭과 근거 프레임만 사용합니다.

```text
EAP-1-A1
RADIUS-1-A1
DHCP-1-A1
DNS-1-A1
TCP-1-A1
```

절대 시각, 원본 거래 ID, IP, 포트, 사용자명과 DNS 질의명은 결과에 기록하지 않습니다.

### 분석 실행별 단말·AP 가명

원본 MAC·BSSID 대신 현재 분석 실행에서만 유효한 가명을 사용합니다.

```text
DEVICE-1
DEVICE-2
AP-1
AP-2
```

- 실행마다 32바이트 CSPRNG 비밀키 생성
- HMAC-SHA-256 내부 토큰 사용
- 원본 주소·HMAC 토큰·키 미직렬화
- 다른 실행의 같은 `DEVICE-N`과 비교 불가
- 단일 L2 근거가 있는 거래만 연결
- RADIUS처럼 단말 근거가 없는 거래를 시간만으로 연결하지 않음

### 단말 가명별 관찰 여정

안전하게 연결된 거래를 실제 근거 프레임 순서로 정리합니다.

```text
DEVICE-1
관찰 단계: EAP → DHCP → DNS → TCP
첫 실패 관찰 단계: TCP
마지막 성공 방향 단계: TCP
```

첫 실패 관찰 단계는 근본 원인 위치가 아니며, 여러 프로토콜이 같은 사용자 세션임을 확정하지 않습니다.

### 캡처 관찰 가능성과 미응답 해석

응답이 보이지 않은 사실과 장애 확정을 분리합니다.

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

파일을 끝까지 읽었더라도 장애 전부터 캡처했는지, 장애 후까지 캡처했는지, 양방향을 모두 봤는지와 패킷 손실이 없었는지는 증명되지 않습니다.

### EAPOL-Key M1~M4 메시지 순서

비식별 EAPOL-Key 이벤트를 `DEVICE-N ↔ AP-N` 관찰로 정리합니다.

```text
EAPOL-HS-1 · DEVICE-1 ↔ AP-1
관찰: M1 → M2 → M3 → M3 → M4
반복 메시지 번호: M3
Retry 비트 프레임: #8
```

상태:

```text
sequence-observed
message-repetition-observed
out-of-order
incomplete
```

M1→M2→M3→M4가 모두 보여도 동일 Handshake, 키 설치, 암호학적 성공이나 전체 무선 접속 성공을 확정하지 않습니다.

### Replay Counter 비식별 관계

Replay Counter는 전용 최소 TShark 프로파일에서만 분석 중 일시적으로 읽고, 숫자를 공개 결과에 기록하지 않습니다.

```text
M1/M2: 같은 Counter 관계 관찰
M3/M4: 같은 Counter 관계 관찰
M1→M3: 후반 Counter 증가 관계 관찰
반복 M3: 같은 Counter 관계 관찰
```

관찰 상태:

```text
expected-relations-observed
relation-mismatch-observed
multiple-values-observed
partial
insufficient-events
unavailable
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

같은 메시지와 같은 Counter 관계가 반복돼도 실제 재전송으로 확정하지 않습니다. 관계 불일치는 캡처 누락이나 여러 교환 혼재 가능성을 포함하므로 AP·단말·RF 장애로 자동 확정하지 않습니다.

## 데이터 보호

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
Replay Counter 원문 숫자
EAPOL Nonce·MIC·Key Data
암호화 키·자격 증명
절대 epoch
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

원본 L2 주소와 Replay Counter는 전용 TShark 출력과 Python 파싱 메모리에 분석 중 일시적으로 존재할 수 있습니다. 현재 보장 범위는 디스크·로그·GUI·JSON·릴리스 자산·외부 네트워크에 남기지 않는 것입니다.

## 실행 안전장치

- 배포본에 고정된 TShark만 사용
- 시스템 Wireshark·PATH 대체 실행 금지
- TShark 파일 크기·SHA-256 실행 전후 확인
- 캡처 형식·크기·SHA-256 단계별 재확인
- Replay 분석도 동일 캡처 지문과 동일 TShark 매니페스트 확인
- `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 고정 fields만 허용
- 실시간·원격 캡처와 사용자 임의 옵션 차단
- Nonce·MIC·Key Data·Payload 추출 금지
- 빈 config·plugin·extcap·data·temp 경로 사용
- stdout·stderr 크기·시간 상한
- 임시 작업공간 자동 삭제
- Symlink·Junction·Reparse Point 우회 차단

## SHA-256 확인

```powershell
Get-FileHash .\WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip -Algorithm SHA256
```

릴리스의 `.sha256` 파일과 비교합니다. EXE에는 아직 상용 코드 서명 인증서가 없어 Windows에서 `알 수 없는 게시자` 경고가 표시될 수 있습니다.

## 아직 지원하지 않는 기능

- Replay 관계만으로 동일 Handshake·실제 재전송 확정
- 키 설치·암호학적 성공 확정
- PCAPNG Interface Statistics Block 기반 캡처 드롭 통계
- 캡처 시작·종료가 장애 구간을 완전히 포함했는지 자동 증명
- 로밍·RSSI·채널·데이터율 기반 RF 근본 원인 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 단일 오프라인 한국어 HTML 보고서
- 실제 사내 Aruba·ClearPass 캡처 검증
- 상용 코드 서명

세부 경계는 `docs/PHASE_4J_PLAN.md`, 가명화 설계는 `docs/adr/0004-analysis-scoped-device-pseudonyms.md`, 검증 상태는 `IMPLEMENTATION_STATUS.md`를 확인합니다.
