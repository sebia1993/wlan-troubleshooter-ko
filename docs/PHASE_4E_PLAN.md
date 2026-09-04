# Phase 4E 실행 계획 — 분석 실행별 단말·AP 가명화

## 목적

Phase 4D는 EAP·RADIUS·DHCP·DNS·TCP 거래를 각각 비식별 시도로 묶지만, 서로 다른 거래가 동일 단말에서 발생했는지는 연결하지 않습니다. Phase 4E는 원본 L2 주소를 결과에 노출하지 않으면서 현재 캡처 안에서만 유효한 `DEVICE-N`과 `AP-N`을 생성하고, 근거가 하나의 단말을 가리킬 때만 거래 시도를 연결합니다.

## 사용자 흐름

```text
PCAP·PCAPNG 선택
→ 캡처 구조 점검
→ 프로토콜 인벤토리·Finding·이벤트·거래 시도
→ 전용 L2 메타데이터 추출
→ 현재 실행에서만 DEVICE-N·AP-N 생성
→ 단말별 근거 프레임·관찰 프로토콜·거래 연결 표시
```

Python·Wireshark·AI·인터넷·관리자 권한은 필요하지 않습니다.

## 개인정보 설계

### 전용 프로파일

기존 공개 `connection-events` 프로파일에는 MAC·BSSID를 추가하지 않습니다. `device-identities` 프로파일에서만 다음 L2 필드를 허용합니다.

```text
eth.src
eth.dst
wlan.sa
wlan.da
wlan.bssid
```

다음 필드는 전용 프로파일에서도 금지합니다.

```text
IPv4·IPv6 주소
SSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
Payload·파일·쿠키·Authorization·자격 증명
```

### 가명화 키

- 분석 실행마다 `os.urandom(32)`으로 새 키 생성
- 정규화한 L2 주소를 HMAC-SHA-256으로 변환
- 내부 사전에는 HMAC 결과와 순번 별칭만 보관
- 원문 주소·비밀키·대응표 저장 금지
- 실행 간 별칭 비교 금지
- 결과에 개인정보 경계 플래그 명시

```text
raw_identifiers_serialized = false
alias_secret_persisted = false
aliases_stable_across_runs = false
```

원문 L2 주소는 전용 TShark stdout과 파싱 중 메모리에 일시적으로 존재할 수 있습니다. 메모리 포렌식에 대한 완전한 비노출은 주장하지 않습니다.

## 단말 등록 기준

서버·게이트웨이·AP를 단말로 오인하지 않기 위해 일반 Ethernet 주소만으로 새 `DEVICE-N`을 만들지 않습니다.

다음 방향 근거가 있을 때만 단말을 최초 등록합니다.

- 802.11 Authentication·Association·Reassociation 요청 송신자
- 해당 관리 응답 수신자
- BSSID를 제외한 802.11 EAP/EAPOL Supplicant 주소
- Ethernet EAP Request 수신자
- Ethernet EAP Response 송신자
- EAP Success·Failure 수신자
- EAPOL Start·Logoff 송신자
- DHCP Discover·Request·Decline·Release·Inform 송신자

단말로 한 번 확인된 주소가 후속 DNS·TCP·TLS·ARP 프레임에 단 하나만 나타나면 해당 프레임을 같은 `DEVICE-N`에 할당할 수 있습니다.

## AP 가명

802.11 프레임의 BSSID는 단말 주소와 별도 HMAC 도메인에서 처리합니다.

```text
DEVICE-1
AP-1
```

같은 원본 주소가 잘못 단말과 AP로 모두 나타나더라도 내부 HMAC 키가 같아지지 않도록 도메인을 분리합니다.

## 거래 시도 연결

Phase 4D의 거래 시도는 근거 프레임으로만 단말 가명에 연결합니다.

- 모든 근거 프레임이 하나의 `DEVICE-N`만 가리키면 `linked`
- 근거 프레임이 둘 이상의 단말을 가리키면 `ambiguous`
- 단말 근거가 없으면 `unassigned`

시간 근접성만으로 RADIUS·DHCP·DNS·TCP 거래를 단말에 연결하지 않습니다. RADIUS는 단말 L2 주소가 직접 보이지 않는 경우 미할당으로 남길 수 있습니다.

## 결과 모델

각 단말 가명은 다음 값만 직렬화합니다.

- `DEVICE-N`
- 첫·마지막 프레임과 상대 지속시간
- 할당 프레임 수와 근거 프레임
- 단말 등록 근거 종류
- 관찰된 안전 프로토콜 그룹
- 관찰된 `AP-N`
- 근거가 하나의 단말을 가리킨 거래 시도 ID
- `device_identity_confirmed=false`
- `cross_protocol_session_confirmed=false`

원본 MAC·BSSID·HMAC digest·가명화 키는 직렬화하지 않습니다.

## 오탐 방지

- 브로드캐스트·멀티캐스트·전부 0인 주소는 단말 가명으로 만들지 않음
- 일반 DNS·TCP 주소만으로 새 단말을 만들지 않음
- 한 프레임에 알려진 단말이 둘 이상 있으면 `ambiguous`
- 서로 다른 단말 근거가 포함된 거래 시도는 연결하지 않음
- 같은 `DEVICE-N`에 여러 프로토콜이 보여도 전체 접속 하나가 확정됐다고 표시하지 않음
- `AP-N`은 BSSID 관찰 가명일 뿐 실제 장비 자산·AP 이름을 뜻하지 않음
- 실행 간 `DEVICE-1`·`AP-1`이 같은 대상을 뜻한다고 비교하지 않음

## 자원 제한

- 처리 프레임: 전용 프로파일 최대 100,000개
- 단말 가명: 최대 20,000개
- AP 가명: 최대 20,000개
- 거래 연결: 최대 50,000개
- 단말별 표시 근거 프레임: 최대 64개
- TShark stdout·stderr·시간 제한은 기존 실행 경계와 동일

## 검증 기준

### 단위 검증

- Ethernet EAP·DHCP 방향에서 하나의 `DEVICE-1` 생성
- 알려진 단말의 후속 DNS·TCP 거래 연결
- DNS/TCP 주소만으로 새 단말 미생성
- 802.11 Station과 BSSID를 `DEVICE-1`·`AP-1`로 분리
- 한 프레임의 두 알려진 단말을 모호함으로 처리
- 부분 거래 보고서가 단말 보고서 완료로 과장되지 않음
- 잘못된 MAC·프레임 순서·프로파일·거래 ID 거부
- 직렬화 결과에 원문 주소 없음

### Windows Portable 검증

최종 ZIP을 압축 해제하고 Python 환경변수와 일반 Python PATH를 제거한 상태에서 EXE를 실행합니다.

- 합성 Ethernet 캡처에서 DHCP 근거로 `DEVICE-1` 생성
- 같은 단말의 DHCP·DNS·TCP 거래 시도 연결
- 합성 IEEE 802.11 캡처에서 `DEVICE-1`·`AP-1` 생성
- 개인정보 경계 플래그가 모두 안전 값인지 확인
- 결과에 캡처 경로·파일명·IP·MAC·원본 거래 ID·DNS 질의명·절대 시간 없음
- 분석 전후 Portable 배포 폴더 무변경
- `BUILD_INFO.json`에 가명화 런타임 활성화와 키 미저장 정책 기록

## 완료 기준

- Windows 전체 테스트·자체 점검·소스 감사·저장소 감사 통과
- Portable 실제 Ethernet·IEEE 802.11 가명화 검증 통과
- GUI와 JSON에서 원문 주소 없는 단말·AP 가명 표시
- 기존 분석 JSON 스키마 2 하위 호환 유지
- `v0.8.0-alpha.1` Win64 Portable 프리릴리즈 게시

## 다음 단계

Phase 4F에서는 `DEVICE-N` 근거를 사용해 동일 단말의 접속 구간을 시간 창으로 분리합니다. 단, 서로 다른 프로토콜 거래를 하나의 접속으로 연결하려면 프레임 주소·순서·시간이 모두 일치해야 하며, RADIUS처럼 단말 L2 주소가 직접 보이지 않는 단계는 계속 미할당 또는 판단 불가로 남깁니다. 이후 EAPOL 4-Way Handshake·로밍·RF 분석과 오프라인 HTML 보고서를 순차적으로 구현합니다.
