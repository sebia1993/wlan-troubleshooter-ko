# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`, `docs/PHASE_4C_PLAN.md`, `docs/PHASE_4D_PLAN.md`, `docs/PHASE_4E_PLAN.md`, `docs/adr/0004-analysis-scoped-device-pseudonyms.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| Phase 3 Win64 Portable 배포 | 구현 완료·Windows 빌드 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스·Portable ZIP 검증 |
| Phase 4A 실제 프로토콜 존재 인벤토리 | 구현 완료·Windows 실분석 통과 | 내장 TShark `-G fields`·`-T fields`, GUI, 취소, 식별자 없는 결과 |
| Phase 4B 접속 단계·근거 Finding | 구현 완료·릴리즈 게시 | 명시적 실패 Finding, 미응답 안전 제한, `v0.5.0-alpha.1` |
| Phase 4C 비식별 이벤트 타임라인 | 구현 완료·릴리즈 게시 | 시간순 이벤트·로컬 별칭·Portable 실제 분석, `v0.6.0-alpha.1` |
| Phase 4D 비식별 프로토콜 거래 시도 | 구현 완료·릴리즈 게시 | 거래 시도 분리·보수적 완결성, `v0.7.0-alpha.1` |
| Phase 4E 분석 실행별 단말·AP 가명 | 구현 완료·최종 Windows/Portable 검증 진행 | 전용 L2 프로파일, HMAC 가명화, DEVICE-N·AP-N, 거래 근거 연결 |
| `v0.8.0-alpha.1` Win64 Portable | 병합 후 게시 예정 | 단말 가명 개인정보 게이트와 릴리즈 자동화 준비 |
| 단말별 접속 시간 구간 분리 | 미착수 | Phase 4F 후보 |
| 최종 오프라인 HTML 보고서 | 미착수 | 세션 상관 정확도 확보 이후 범위 |

## Phase 4E 구현 기능

- 필드 프로파일 버전 `0.5.0`
- 기존 공개 `connection-events` 프로파일의 MAC·BSSID 비포함 유지
- 별도의 `device-identities` 전용 TShark 프로파일
- 전용 프로파일에서만 `eth.src`, `eth.dst`, `wlan.sa`, `wlan.da`, `wlan.bssid` 허용
- IP·IPv6·SSID·사용자명·DNS 질의명·포트·Payload 필드 금지
- 분석 실행마다 CSPRNG 기반 32바이트 비밀키 생성
- 정규화한 L2 주소를 HMAC-SHA-256으로 변환
- 단말과 AP의 HMAC 도메인 분리
- 결과에는 `DEVICE-N`·`AP-N` 순번 가명만 기록
- 원문 주소·HMAC digest·비밀키·대응표 미저장
- 802.11 관리 프레임·EAP 방향·DHCP 클라이언트 방향 기반 단말 최초 등록
- 일반 DNS·TCP 주소만으로 새 단말 미생성
- 알려진 단말이 한 프레임에 정확히 하나일 때 후속 프레임 할당
- 거래 근거 프레임이 하나의 단말만 가리킬 때 거래 시도 연결
- 프레임·거래의 `linked`, `unassigned`, `ambiguous` 구분
- GUI `[7. 분석 실행별 단말·AP 가명]`
- 기존 분석 JSON 스키마 버전 2를 유지하면서 `device_sessions` 추가 결과 제공

## 개인정보 안전 경계

공개 결과에는 다음 상태를 고정합니다.

```text
raw_identifiers_serialized = false
alias_secret_persisted = false
aliases_stable_across_runs = false
device_identity_confirmed = false
cross_protocol_session_confirmed = false
```

원문 L2 주소는 전용 TShark stdout과 Python 파싱 메모리에서 일시적으로 처리될 수 있습니다. 메모리 포렌식에 대한 완전한 비노출은 주장하지 않습니다. 현재 보장 범위는 원문 MAC·BSSID·HMAC digest·비밀키·대응표를 디스크·로그·JSON·GUI·릴리즈 자산·외부 네트워크에 남기지 않는 것입니다.

## 오탐 방지

- 브로드캐스트·멀티캐스트·전부 0인 주소는 단말 가명으로 만들지 않습니다.
- DNS·TCP·TLS·ARP 주소만으로는 새 단말을 만들지 않습니다.
- 한 프레임에 확인된 단말이 둘 이상 있으면 모호함으로 남깁니다.
- 거래 근거 프레임이 서로 다른 단말을 가리키면 거래를 단말에 연결하지 않습니다.
- RADIUS처럼 단말 L2 주소가 직접 보이지 않는 트래픽을 시간만으로 연결하지 않습니다.
- 같은 `DEVICE-N`에 여러 프로토콜 거래가 연결돼도 사용자 접속 전체를 확정하지 않습니다.
- 다른 분석 실행의 같은 가명 번호를 같은 단말로 비교하지 않습니다.
- 패킷 부재와 프로토콜 미관찰을 장애로 해석하지 않습니다.

## TShark 실행 구조

```text
필드 카탈로그 확인
→ 공개 connection-events 출력
→ 인벤토리·Finding·타임라인·거래 시도
→ 전용 device-identities 출력
→ 분석 실행별 HMAC 가명화
→ 공개 DeviceSessionReport
```

전체 분석에서는 TShark 프로세스를 세 번 사용합니다. 두 fields 실행 모두 동일한 내장 TShark 번들·캡처 SHA-256, 고정 argv, 이름 해석 비활성화, 빈 설정·플러그인·extcap 환경, 출력·시간 제한과 취소 정책을 사용합니다.

## 자원 제한

- 전용 가명화 프로파일 최대 100,000프레임
- 단말 가명 최대 20,000개
- AP 가명 최대 20,000개
- 거래 연결 최대 50,000개
- 단말별 근거 프레임 최대 64개
- 기존 이벤트·거래·stdout·stderr·실행시간 상한 유지

## 자동 검증 범위

- Ethernet EAP·DHCP 방향에서 단말 최초 등록
- 알려진 단말의 후속 DNS·TCP 거래 연결
- DNS/TCP 주소만으로 새 단말 미생성
- 802.11 Station과 BSSID의 DEVICE/AP 분리
- 둘 이상의 알려진 단말이 있는 프레임의 모호 처리
- 부분 거래 보고서의 완료 과장 방지
- 잘못된 프로파일·MAC·프레임 순서·거래 ID 거부
- 공개 이벤트 argv의 원문 L2 필드 차단
- 전용 가명화 argv의 명시적 프로파일 문맥 요구
- JSON의 원문 MAC·HMAC digest·가명화 키 비노출
- Portable BUILD_INFO의 가명화 런타임과 비저장 정책
- 최종 Portable EXE의 Ethernet `DEVICE-1`
- 최종 Portable EXE의 IEEE 802.11 `DEVICE-1`·`AP-1`
- 개인정보·원본 ID·캡처 경로 비노출과 Portable 폴더 무변경

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리즈 빌드 서버에서만 수행합니다.

## 아직 지원하지 않는 기능

- 한 `DEVICE-N` 안에서 여러 접속 시도를 시간 구간별로 분리
- 서로 다른 EAP·RADIUS·DHCP·DNS·TCP 거래를 완전한 단말 접속 하나로 확정
- RADIUS 서버 거래의 안전한 단말 연결
- 동일 단말의 EAPOL 4-Way Handshake 메시지 1~4 완결성 판정
- 응답 미관찰과 캡처 누락·단방향 수집의 자동 구분
- BSSID·채널·RSSI 기반 로밍·RF 장애 상관분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태 검증
- 상용 코드 서명 인증서를 이용한 애플리케이션 EXE 서명

현재 브랜치는 **분석 실행별 단말·AP 가명 프리뷰**이며 실제 사용자 식별 또는 완성형 단말별 WLAN 근본 원인 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
