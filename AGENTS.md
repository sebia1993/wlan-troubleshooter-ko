# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 넓히지 않습니다.

## 현재 범위

사용자는 2026년 9월 4일 남은 개발을 계속하도록 승인했습니다. 현재 범위는 `docs/PHASE_4E_PLAN.md`와 ADR 0004의 **분석 실행별 단말·AP 가명화**입니다.

- 기존 공개 `connection-events` 출력에는 원본 MAC·BSSID를 추가하지 않습니다.
- 전용 `device-identities` 프로파일에서만 최소 L2 주소를 읽습니다.
- 원문 주소는 분석 실행별 HMAC 키로 즉시 가명화하고 결과에는 `DEVICE-N`·`AP-N`만 남깁니다.
- 비밀키·원문 주소·HMAC digest·대응표를 저장하거나 로그에 남기지 않습니다.
- 실행 간 별칭을 안정적으로 재사용하지 않습니다.
- 단말 방향 근거가 명확할 때만 새 `DEVICE-N`을 만듭니다.
- 둘 이상의 단말 근거가 있으면 모호함으로 남기고 자동 연결하지 않습니다.
- 서로 다른 프로토콜 거래가 같은 단말에 연결돼도 전체 접속 하나로 확정하지 않습니다.
- 접속 시간 구간·4-Way Handshake·로밍·RF·HTML 보고서는 다음 단계로 남깁니다.
- 가짜 패킷 결과, 임시 성공값과 근거 없는 원인을 만들지 않습니다.

## 기술과 런타임 금지사항

- Python 3.13 표준 라이브러리와 `tkinter/ttk`만 런타임에 사용합니다.
- AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, 온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 추가하지 않습니다.
- 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다.
- GitHub Actions의 공급망 다운로드는 제품 런타임과 분리하며 다운로드 코드를 앱에 넣지 않습니다.

## TShark 실행 경계

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용합니다.
- 시스템 설치본, 레지스트리와 PATH 실행 파일로 대체하지 않습니다.
- 실행 파일과 모든 종속 파일의 크기·SHA-256을 실행 전후 확인합니다.
- 자식 프로세스 생성은 `tshark/runner.py`의 검토된 단일 함수만 허용합니다.
- `shell=False`, stdin 비활성화, Windows 콘솔 숨김을 고정합니다.
- 이름 해석 비활성화 `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 고정 fields 출력만 허용합니다.
- 실시간 `-i`, rpcap, TCP@호스트, 임의 extcap·Lua·필터·필드·사용자 옵션을 금지합니다.
- stdout과 stderr를 동시에 읽고 크기·시간 상한을 적용합니다.
- stderr 원문은 저장·표시하지 않습니다.
- 호출마다 빈 config·plugin·extcap·data·temp 경로를 만들고 종료 후 무잔류를 확인합니다.

## 공개 분석 프로파일

`protocol-inventory`와 `connection-events`에는 IP·MAC·SSID·사용자명·DNS 질의명·포트·Payload 필드를 넣지 않습니다. 이 프로파일의 결과는 기존 비식별 JSON·GUI에 사용됩니다.

## Phase 4E 전용 가명화 프로파일

원본 L2 식별자는 `device-identities` 프로파일에서만 허용합니다.

허용 필드:

```text
eth.src
eth.dst
wlan.sa
wlan.da
wlan.bssid
```

금지 필드:

```text
ip.src·ip.dst·ipv6.src·ipv6.dst
wlan.ssid
EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
Raw Payload·파일·쿠키·Authorization·자격 증명
```

전용 프로파일도 공개 분석과 동일한 고정 argv·격리·무결성·취소·출력 상한을 적용합니다. 일반 `assert_safe_profile_argv` 호출은 원본 L2 필드를 거부해야 하며, 명시적인 `device-identities` 프로파일 문맥에서만 허용합니다.

## 가명화 키와 메모리 경계

- 분석 실행마다 CSPRNG 기반 32바이트 비밀키를 생성합니다.
- 정규화한 L2 주소를 HMAC-SHA-256 입력으로 사용합니다.
- 단말과 AP는 서로 다른 HMAC 도메인을 사용합니다.
- 내부 장기 구조에는 HMAC digest와 순번 가명만 보관합니다.
- 원문 주소·HMAC digest·비밀키·대응표를 결과·로그·파일·환경변수·레지스트리에 기록하지 않습니다.
- 결과에는 `raw_identifiers_serialized=false`, `alias_secret_persisted=false`, `aliases_stable_across_runs=false`를 유지합니다.

원문 주소는 TShark stdout과 Python 파싱 메모리에 일시적으로 존재할 수 있습니다. 메모리 덤프까지 포함한 완전 비노출을 주장하지 않으며, 디스크·로그·보고서·외부 전송 비노출만 현재 보장합니다.

## 단말 최초 등록과 연결

다음 근거만 새 `DEVICE-N` 생성에 사용할 수 있습니다.

- 802.11 Authentication·Association·Reassociation 요청·응답 방향
- BSSID를 제외한 802.11 EAP/EAPOL Supplicant 주소
- Ethernet EAP Request·Response·Success·Failure 방향
- EAPOL Start·Logoff 송신자
- DHCP Discover·Request·Decline·Release·Inform 송신자

일반 DNS·TCP·TLS·ARP 주소만으로는 새 단말을 만들지 않습니다. 이미 확인된 단말 주소가 프레임에 정확히 하나 있을 때만 해당 프레임을 단말에 할당합니다.

## 판정 안전성

- 브로드캐스트·멀티캐스트·전부 0인 주소를 단말로 만들지 않습니다.
- 한 프레임에 확인된 단말이 둘 이상 있으면 `ambiguous`로 남깁니다.
- 거래 근거 프레임이 둘 이상의 단말을 가리키면 해당 거래를 단말에 연결하지 않습니다.
- RADIUS처럼 단말 L2 주소가 없는 트래픽은 시간만으로 연결하지 않습니다.
- 모든 단말은 `device_identity_confirmed=false`, `cross_protocol_session_confirmed=false`를 유지합니다.
- 같은 `DEVICE-N`에 여러 거래가 보여도 사용자 접속 전체나 근본 원인을 확정하지 않습니다.
- 실행 간 같은 `DEVICE-1`을 같은 단말로 비교하지 않습니다.
- TCP 재전송만으로 RF·서버 장애를 확정하지 않습니다.
- 패킷 부재와 프로토콜 미관찰을 장애로 해석하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널을 판단하지 않습니다.
- 근거가 부족하면 미할당·모호함·판단 불가가 우선입니다.

## 결과와 자원 제한

- 전용 프로파일 처리 상한: 100,000프레임
- 단말 가명: 최대 20,000개
- AP 가명: 최대 20,000개
- 거래 연결: 최대 50,000개
- 단말별 근거 프레임: 최대 64개
- 기존 이벤트·거래·stdout·stderr·실행시간 상한 유지

## 검증과 릴리즈

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 검증을 수행합니다.

Portable 검증은 Python PATH 없이 최종 EXE를 실행하고 다음을 확인해야 합니다.

- Ethernet DHCP 근거에서 `DEVICE-1` 생성
- 같은 단말의 DHCP·DNS·TCP 거래 연결
- 일반 DNS·TCP 서버 주소를 새 단말로 만들지 않음
- IEEE 802.11 Station과 BSSID를 `DEVICE-1`·`AP-1`로 분리
- 원문 L2 주소·IP·DNS 질의명·원본 ID·절대 시간 비노출
- 가명화 키·대응표 미저장
- 분석 전후 Portable 폴더 무변경

`v0.8.0-alpha.1`은 분석 실행별 단말·AP 가명 프리릴리즈입니다. 실제 사용자 신원, 자산 식별 또는 완전한 단말 접속 분석기로 표현하지 않으며 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
