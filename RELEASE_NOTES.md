# v0.8.0-alpha.1 — 분석 실행별 단말·AP 가명화 프리뷰

이번 릴리즈는 Phase 4D 거래 시도를 확장하여, 원본 MAC·BSSID를 결과에 표시하지 않고 **현재 분석 실행에서만 유효한 `DEVICE-N`·`AP-N` 가명**을 생성합니다. Python과 Wireshark를 별도로 설치할 필요가 없습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.8.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- 현재 분석에서만 사용하는 `DEVICE-1`, `DEVICE-2` 단말 가명
- 802.11 BSSID용 `AP-1`, `AP-2` 가명
- 단말 가명별 첫·마지막 프레임, 상대 지속시간과 근거 프레임
- 단말 최초 확인 근거와 관찰 프로토콜
- 단 하나의 단말 근거가 있는 EAP·DHCP·DNS·TCP 거래 시도 연결
- 미할당·모호 프레임과 거래 개수 표시
- GUI `[7. 분석 실행별 단말·AP 가명]` 영역
- 전용 Portable 개인정보 검증 게이트

## 단말을 만드는 근거

일반 Ethernet 주소를 모두 단말로 분류하지 않습니다. 다음처럼 방향이 명확한 패킷에서만 단말 가명을 최초 생성합니다.

- 802.11 Authentication·Association·Reassociation 요청 송신자
- 해당 관리 응답 수신자
- BSSID를 제외한 무선 EAP/EAPOL Supplicant 주소
- Ethernet EAP Request 수신자와 EAP Response 송신자
- EAP Success·Failure 수신자
- EAPOL Start·Logoff 송신자
- DHCP Discover·Request·Decline·Release·Inform 송신자

DNS·TCP·TLS·ARP 주소만으로는 새 단말을 만들지 않습니다. 이미 단말로 확인된 주소가 후속 프레임에 정확히 하나만 나타날 때 해당 프레임과 거래를 연결할 수 있습니다.

## 개인정보 처리 방식

기존 공개 `connection-events` 출력에는 MAC·BSSID를 추가하지 않았습니다. 별도의 `device-identities` 프로파일만 다음 L2 필드를 요청합니다.

```text
eth.src
eth.dst
wlan.sa
wlan.da
wlan.bssid
```

분석 실행마다 운영체제 난수로 새 32바이트 비밀키를 만들고 정규화한 L2 주소를 HMAC-SHA-256으로 변환합니다. 내부 매핑에는 HMAC 결과와 순번 가명만 보관하며, 공개 결과에는 HMAC 결과도 포함하지 않습니다.

```text
raw_identifiers_serialized = false
alias_secret_persisted = false
aliases_stable_across_runs = false
```

원문 L2 주소, HMAC digest, 비밀키와 원문-가명 대응표는 JSON·GUI·로그·파일·레지스트리·환경변수에 기록하지 않습니다.

TShark stdout과 Python 파싱 메모리에는 원문 주소가 처리 중 일시적으로 존재할 수 있습니다. 따라서 메모리 포렌식에 대한 완전한 비노출은 주장하지 않습니다. 현재 보장 범위는 원문을 디스크·로그·보고서·외부 네트워크에 남기지 않는 것입니다.

## 모호함을 남기는 기준

- 한 프레임에 알려진 단말이 없으면 `unassigned`
- 한 프레임에 알려진 단말이 정확히 하나면 해당 단말에 연결 가능
- 한 프레임에 알려진 단말이 둘 이상이면 `ambiguous`
- 거래 근거 프레임이 서로 다른 단말을 가리키면 거래를 단말에 연결하지 않음
- RADIUS처럼 단말 L2 주소가 직접 보이지 않는 트래픽을 시간 근접성만으로 연결하지 않음

## 결과 해석 주의

```text
DEVICE-1 ≠ 실제 사용자 신원
DEVICE-1 ≠ 자산 번호
AP-1 ≠ 실제 AP 이름·위치
같은 DEVICE-1에 여러 거래 연결 ≠ 전체 접속 하나 확정
다른 실행의 DEVICE-1 ≠ 같은 단말
RADIUS 미할당 ≠ RADIUS 장애
```

각 단말 가명 결과는 다음 값을 유지합니다.

```text
device_identity_confirmed = false
cross_protocol_session_confirmed = false
```

단말 가명은 현재 캡처에서 같은 L2 주소가 관찰됐다는 근거를 정리하기 위한 임시 분류입니다. 실제 사용자·자산·소유자 또는 완전한 접속 세션을 확인한 결과가 아닙니다.

## 데이터 보호

다음 값은 GUI와 기본 JSON에 포함하지 않습니다.

- IPv4·IPv6 주소
- 원본 Ethernet·802.11 MAC 주소와 BSSID
- SSID
- 사용자명·EAP Identity·RADIUS User-Name
- DNS 질의명·호스트명
- TCP·UDP 포트
- 원본 EAP·RADIUS·DHCP·DNS 거래 ID
- 원본 TCP·UDP Stream 번호
- 절대 epoch
- HMAC digest와 가명화 키
- Raw Payload·파일·쿠키·Authorization·자격 증명
- 캡처 파일명·절대경로
- TShark 표준 오류 원문

AI·LLM·Ollama·MCP·외부 API, 런타임 HTTP·소켓·온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트와 실시간·원격 캡처는 없습니다.

## 실행 안전성

- 고정 매니페스트 TShark만 사용
- 시스템 TShark와 PATH 대체 금지
- 이름 해석 비활성화 `-n`
- 저장 캡처 `-r`, 패킷 상한 `-c`, 고정 fields만 허용
- 전용 가명화 필드는 명시적인 `device-identities` 프로파일에서만 허용
- IP·SSID·사용자명·DNS 이름·포트·Payload는 전용 프로파일에서도 금지
- 실행 전후 TShark 번들과 캡처 SHA-256 재검증
- 빈 config·plugin·extcap·data·temp 환경
- stdout·stderr 동시 처리, 크기·시간 상한과 사용자 취소
- stderr 원문 폐기와 임시 작업공간 자동 삭제

## Portable 실제 검증

릴리즈 빌드는 Python 관련 환경변수와 일반 Python PATH를 제거한 상태에서 최종 EXE를 실행합니다.

### Ethernet 합성 캡처

- DHCP 클라이언트 근거로 `DEVICE-1` 생성
- 같은 단말이 포함된 DHCP·DNS·TCP 거래 시도 연결
- 일반 DNS·TCP 서버 주소를 새 단말로 생성하지 않음
- 원문 Ethernet MAC·IP·DNS 질의명·거래 ID·절대 시간 비노출

### IEEE 802.11 합성 캡처

- Authentication·Association 방향에서 `DEVICE-1` 생성
- BSSID를 별도 `AP-1`로 생성
- 단말과 AP 원문 MAC 비노출

두 분석 모두 개인정보 경계 플래그, 근거 프레임, 분석 전후 Portable 폴더 무변경을 확인한 뒤에만 릴리즈를 게시합니다.

## 호환성

기존 분석 JSON 스키마 버전 2를 유지합니다. `device_sessions`는 기존 인벤토리·Finding·타임라인·거래 시도를 변경하지 않는 추가 결과입니다.

## 아직 지원하지 않는 기능

- 한 `DEVICE-N` 안의 여러 접속 시도를 시간 구간별로 분리
- 서로 다른 프로토콜 거래를 완전한 단말 접속 하나로 확정
- RADIUS 거래의 안전한 단말 연결
- 동일 단말의 EAPOL 4-Way Handshake 완결성 판정
- 응답 미관찰과 캡처 누락·단방향 수집의 자동 구분
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 판정
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 캡처 검증과 상용 코드 서명

## 릴리즈 자산

- `WlanTroubleshooterKO-v0.8.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.8.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
