# v0.9.0-alpha.1 — 단말 가명별 접속 관찰 여정 프리뷰

이번 릴리스는 Phase 4E의 분석 실행별 `DEVICE-N` 가명과 Phase 4D의 EAP·RADIUS·DHCP·DNS·TCP 거래 시도를 결합하여 **단말 가명별 관찰 여정**을 제공합니다.

Python과 Wireshark를 별도로 설치할 필요가 없습니다. AI·LLM·외부 API·인터넷 조회·텔레메트리·자동 업데이트도 사용하지 않습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.9.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG를 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- `DEVICE-N`에 안전하게 연결된 EAP·RADIUS·DHCP·DNS·TCP 거래 집계
- 실제 근거 프레임 기준 관찰 단계 순서
- 단계별 완료·성공 방향·실패·혼재·미완료 상태
- 첫 실패 관찰 단계와 마지막 성공 방향 단계
- 단말별 관찰 AP 가명
- 단계별 거래 시도 ID, 근거 프레임과 Wireshark 필터
- 미할당·모호 거래와 연결 거래가 없는 단말 집계
- GUI `[8. 단말 가명별 관찰 여정]`

예시:

```text
DEVICE-1
관찰 단계: EAP → DHCP → DNS → TCP
첫 실패 관찰 단계: TCP
마지막 성공 방향 단계: TCP
```

## 거래 연결 기준

단말 여정에는 Phase 4E가 다음 조건으로 이미 연결한 거래만 들어갑니다.

- 연결 상태가 `linked`
- 단말 후보가 정확히 하나임
- 연결 근거 프레임과 원 거래 근거가 정확히 일치함
- 거래 근거가 비어 있지 않음
- 거래 근거 프레임이 생략되지 않음
- 단말의 `linked_attempt_ids`와 연결 결과가 일치함

다음 거래는 여정에 포함하지 않습니다.

- 단말 L2 근거가 없는 `unassigned` 거래
- 둘 이상의 단말 후보가 있는 `ambiguous` 거래
- 근거 프레임이 일부 생략된 거래
- 원 거래와 연결 객체의 근거가 다른 거래

RADIUS처럼 단말 L2 주소가 보이지 않는 거래를 시간 근접성만으로 `DEVICE-N`에 연결하지 않습니다.

## 상태 해석

단계 상태:

```text
complete
success-observed
failure-observed
mixed
partial-progress
incomplete
```

여정 상태:

```text
progress-observed
failure-observed
mixed
partial-progress
incomplete
no-linked-transactions
```

`첫 실패 관찰 단계`는 실패 패킷이 처음 나타난 위치입니다. 근본 원인의 위치나 책임 시스템을 뜻하지 않습니다. `마지막 성공 방향 단계`도 전체 사용자 접속 성공을 뜻하지 않습니다.

## 혼재 거래 처리

동일 단계에 성공 방향 응답과 실패 응답이 함께 있으면 `mixed`로 표시합니다. 예를 들어 같은 단말의 TCP 단계에서 SYN/SYN-ACK 거래와 별도 RST 거래가 함께 관찰되면:

```text
TCP 단계: mixed
첫 실패 관찰 단계: tcp
마지막 성공 방향 단계: tcp
root_cause_confirmed: false
```

성공 방향과 실패 관찰을 모두 보존하되 서버·방화벽·애플리케이션 중 근본 원인을 자동 확정하지 않습니다.

## 생략 근거 처리

거래 근거 프레임이 상한을 넘어 일부 생략된 경우 Phase 4E는 단말 연결용 임시 복사본에서 근거를 비우고 해당 거래를 미연결 상태로 유지합니다.

Phase 4F는 다음만 허용합니다.

- 생략 거래 + 미연결 + 빈 연결 근거: 여정에서 제외
- 생략 거래 + 단말 연결: 거부
- 생략 거래 + 연결 근거 잔존: 거부

따라서 불완전한 근거가 단말 여정으로 승격되지 않습니다.

## 개인정보 및 상관 안전성

Phase 4F는 다음 이미 비식별화된 결과만 사용합니다.

```text
transaction_sessions
device_sessions
```

원본 MAC·BSSID·IP·SSID·사용자명·DNS 질의명·포트·거래 ID를 입력받지 않습니다.

다음 플래그는 항상 `false`입니다.

```text
raw_identifiers_serialized
aliases_stable_across_runs
device_identity_confirmed
cross_protocol_session_confirmed
root_cause_confirmed
```

단말 가명 보고서에서 다음 보호 플래그가 하나라도 바뀌면 여정 생성을 거부합니다.

```text
raw_identifiers_serialized = false
alias_secret_persisted = false
aliases_stable_across_runs = false
```

`DEVICE-1`은 현재 분석 실행에서만 유효합니다. 다른 실행의 `DEVICE-1`과 동일한 장치라는 뜻이 아닙니다.

## Windows 격리 경로 보완

TShark가 전용 임시 디렉터리 안에서 임시파일을 생성·삭제하면 Windows가 Archive·시간·디렉터리 크기 메타데이터를 바꿀 수 있습니다. 이러한 정상 변경은 디렉터리 교체로 오인하지 않습니다.

다음 보안 검사는 계속 유지합니다.

- 장치 ID와 파일 ID
- 객체 종류와 링크 수
- Symlink·Junction·Reparse Point
- 실행 후 격리 디렉터리 무잔류

## Portable 실제 통합검증

릴리스 빌드는 Python 환경변수와 일반 Python PATH를 제거한 상태에서 최종 `WlanTroubleshooterKO.exe`를 실행합니다.

런타임 생성 Ethernet PCAP에서 예상하는 `DEVICE-1` 관찰 여정:

- EAP Request → Response → Success: 완료 관찰
- DHCP Discover → Offer → Request → ACK: 완료 관찰
- DNS Query → 정상 Response: 완료 관찰
- TCP SYN → SYN/ACK: 성공 방향 관찰
- 별도 TCP RST: 실패 관찰
- TCP 단계: 성공·실패 혼재
- 첫 실패 관찰 단계: TCP
- 마지막 성공 방향 단계: TCP
- RADIUS 거래: 단말 근거가 없어 시간 추정 연결하지 않음

추가 검증:

- 원본 주소·SSID·사용자·DNS 질의명·거래 ID·HMAC 키·절대 시간 비노출
- 모든 신원·교차 세션·근본 원인 확정 플래그 `false`
- 분석 전후 Portable 배포 폴더 무변경
- 외부 Python·Wireshark 미사용

## 호환성

기존 분석 JSON의 최상위 `schema_version = 2`를 유지합니다. `device_journeys`는 기존 인벤토리·Finding·타임라인·거래·단말 가명 결과를 변경하지 않는 추가 항목입니다.

## 아직 지원하지 않는 기능

- `DEVICE-N`을 실제 사용자나 자산 신원으로 확정
- 여러 프로토콜 거래가 하나의 완전한 사용자 세션임을 확정
- 캡처 누락과 실제 미응답의 자동 확정 구분
- 동일 단말의 EAPOL 4-Way Handshake 완결성 판정
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 단일 오프라인 한국어 HTML 보고서
- 실제 사내 Aruba·ClearPass 캡처 검증
- 애플리케이션 EXE 상용 코드 서명

## 릴리스 자산

- `WlanTroubleshooterKO-v0.9.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.9.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
