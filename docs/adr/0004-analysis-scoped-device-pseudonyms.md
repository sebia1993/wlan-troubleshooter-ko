# ADR 0004: 분석 실행별 단말·AP 가명만 사용

- 상태: 승인
- 날짜: 2026-09-04

## 배경

Phase 4D까지는 EAP·RADIUS·DHCP·DNS·TCP 거래를 각각 비식별 별칭으로 묶었지만, 서로 다른 프로토콜 거래가 같은 단말에서 발생했는지는 알 수 없었습니다. 이를 연결하려면 802.11 또는 Ethernet의 L2 주소를 순간적으로 확인해야 합니다.

그러나 MAC 주소와 BSSID는 사내 단말·AP를 식별할 수 있는 정보입니다. 원문 주소, 고정 해시 또는 장기간 재사용되는 가명은 여러 보고서와 캡처를 결합해 단말 이동·사용 패턴을 추적하는 수단이 될 수 있습니다. 따라서 단말별 분석 정확도를 높이더라도 원문 식별정보의 결과 노출과 장기 상관 가능성을 만들지 않아야 합니다.

## 결정

단말·AP 가명은 **현재 분석 실행의 메모리 안에서만** 생성하고 사용합니다.

- 별도의 `device-identities` TShark 프로파일만 원문 L2 주소 필드를 요청할 수 있습니다.
- 허용 원문 주소 필드는 `eth.src`, `eth.dst`, `wlan.sa`, `wlan.da`, `wlan.bssid`로 제한합니다.
- IP·IPv6·SSID·사용자명·EAP Identity·RADIUS User-Name·DNS 질의명·포트·Payload는 가명화 프로파일에도 넣지 않습니다.
- 분석 실행마다 운영체제 CSPRNG에서 32바이트 비밀키를 새로 생성합니다.
- 정규화된 L2 주소는 HMAC-SHA-256 입력으로만 사용하고, 내부 매핑에는 HMAC 결과와 `DEVICE-N` 또는 `AP-N` 순번만 보관합니다.
- 비밀키, 원문 주소, 원문과 가명의 대응표는 파일·로그·JSON·GUI·레지스트리·환경변수에 기록하지 않습니다.
- 분석이 끝난 뒤 동일 캡처를 다시 분석해도 같은 별칭을 보장하지 않습니다.
- 공개 결과에는 `raw_identifiers_serialized=false`, `alias_secret_persisted=false`, `aliases_stable_across_runs=false`를 명시합니다.

Python 객체와 TShark stdout 버퍼에 원문 주소가 일시적으로 존재할 수 있으므로 메모리 포렌식에 대한 완전한 비노출을 주장하지 않습니다. 이 결정은 디스크·로그·보고서·외부 전송에 원문 주소를 남기지 않는 경계입니다.

## 단말 최초 등록 근거

임의의 Ethernet 송수신 주소를 모두 단말로 등록하지 않습니다. 서버, 게이트웨이, AP 또는 다른 단말을 잘못 `DEVICE-N`으로 만들 수 있기 때문입니다.

단말 가명은 다음과 같은 방향성이 명확한 근거가 있을 때만 최초 생성합니다.

- 802.11 Authentication·Association·Reassociation 요청의 송신 주소
- 해당 관리 응답의 수신 주소
- BSSID를 제외한 802.11 EAP/EAPOL Supplicant 주소
- Ethernet EAP Request의 수신 주소, EAP Response의 송신 주소, EAP Success·Failure의 수신 주소
- EAPOL Start·Logoff의 송신 주소
- DHCP Discover·Request·Decline·Release·Inform의 송신 주소

일반 DNS·TCP·TLS·ARP 프레임의 주소만으로는 새 단말을 만들지 않습니다. 한 번 단말로 확인된 주소는 후속 프레임에 단 하나만 나타날 때 그 프레임과 거래 시도를 해당 가명에 연결할 수 있습니다.

## 모호함 처리

- 한 프레임에 둘 이상의 확인된 단말 주소가 있으면 어느 단말의 거래인지 정하지 않고 `ambiguous`로 남깁니다.
- 거래 시도의 근거 프레임들이 서로 다른 단말 가명에 연결되면 해당 거래를 단말에 할당하지 않습니다.
- RADIUS처럼 단말 L2 주소가 직접 보이지 않는 트래픽은 시간만으로 단말에 연결하지 않습니다.
- 서로 다른 프로토콜 거래가 같은 `DEVICE-N`에 연결돼도 전체 사용자 접속 하나가 확정됐다고 표시하지 않습니다.
- 모든 단말 결과는 `device_identity_confirmed=false`, `cross_protocol_session_confirmed=false`를 유지합니다.

## TShark 실행 경계

원문 L2 필드는 기존 `connection-events` 출력에 추가하지 않습니다.

```text
필드 카탈로그 확인
→ 공개 connection-events 출력
→ 인벤토리·Finding·타임라인·거래 시도 생성
→ 전용 device-identities 출력
→ 즉시 HMAC 가명화
→ 공개 DeviceSessionReport 생성
```

- 전용 프로파일도 프로젝트 내장 TShark와 고정 argv만 사용합니다.
- `-n`, 저장 캡처 `-r`, 패킷 상한 `-c`, 고정 fields 형식을 유지합니다.
- 실행 전후 TShark 번들과 캡처 SHA-256을 재검증합니다.
- stdout·stderr 크기, 실행시간과 취소 정책을 기존 분석과 동일하게 적용합니다.
- stderr 원문은 저장하거나 표시하지 않습니다.
- 공개 분석 결과에는 전용 프로파일의 원문 fields 출력이나 원문 필드 값을 포함하지 않습니다.

## 결과

장점:

- 같은 캡처 안에서 단말 중심으로 802.11·EAP·DHCP·DNS·TCP 근거를 묶을 수 있습니다.
- 원문 MAC·BSSID를 보고서와 JSON에 남기지 않습니다.
- 고정 해시를 사용하지 않아 여러 분석 결과를 장기간 결합하기 어렵습니다.
- 근거가 모호한 프레임과 거래를 억지로 단말에 할당하지 않습니다.

제약:

- 실행 간 `DEVICE-1`의 대상이 같다고 비교할 수 없습니다.
- RADIUS 거래는 단말 L2 주소가 없으면 단말 가명에 연결되지 않습니다.
- 메모리 덤프 공격에 대한 원문 주소 완전 비노출은 보장하지 않습니다.
- 여러 캡처 파일에 걸친 단말 추적을 지원하지 않습니다.
- 단말 가명만으로 실제 사용자, 자산 번호 또는 소유자를 식별할 수 없습니다.

## 후속 조건

단말별 EAPOL 4-Way Handshake, 로밍 또는 RF 분석은 다음 조건을 충족한 뒤 별도 단계에서 구현합니다.

- 동일 `DEVICE-N`과 `AP-N` 근거가 프레임마다 일관됨
- 재전송·캡처 누락·다중 인터페이스 혼합을 구분하는 테스트 확보
- 결과에 원문 L2 식별자와 고정 가명이 남지 않는 Portable 검증 통과
- 실제 사내 캡처는 외부 업로드 없이 내부 PC에서만 검증
