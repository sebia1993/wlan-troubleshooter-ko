# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`, `docs/PHASE_4C_PLAN.md`, `docs/PHASE_4D_PLAN.md`, `docs/PHASE_4E_PLAN.md`, `docs/PHASE_4F_PLAN.md`, `docs/PHASE_4G_PLAN.md`, `docs/adr/0004-analysis-scoped-device-pseudonyms.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·검증 통과 | Tkinter, 입력 검증, 임시공간, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·검증 통과 | PCAP·PCAPNG bounded scan, Link Type, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·검증 통과 | 필드 카탈로그, 고정 프로파일, TSV 파서 |
| Phase 3 Win64 Portable | 구현 완료·검증 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스 |
| Phase 4A 프로토콜 인벤토리 | 구현 완료·릴리스 게시 | 실제 내장 TShark 프로토콜 존재 집계 |
| Phase 4B 접속 단계·Finding | 구현 완료·릴리스 게시 | 명시적 실패 Finding과 보수적 판정 |
| Phase 4C 이벤트 타임라인 | 구현 완료·릴리스 게시 | 상대 시간·로컬 거래 별칭·근거 프레임 |
| Phase 4D 프로토콜 거래 시도 | 구현 완료·릴리스 게시 | EAP·RADIUS·DHCP·DNS·TCP 시도별 완결성 |
| Phase 4E 분석 실행별 단말·AP 가명 | 구현 완료·릴리스 게시 | `DEVICE-N`, `AP-N`, HMAC 키 미저장, 단일 근거 연결 |
| Windows 격리 디렉터리 Hotfix | 구현 완료·검증 통과 | 일반 메타데이터 변경 허용, 객체·Reparse Point 검사 유지 |
| Phase 4F 단말 가명별 관찰 여정 | 구현 완료·Portable 재검증 진행 | 실제 프레임 순서, 첫 실패·마지막 성공 방향 단계 |
| `v0.9.0-alpha.1` Win64 Portable | Phase 4F 병합 후 게시 예정 | 교정된 DEVICE-N DHCP·DNS·TCP 실제 여정 게이트 |
| Phase 4G 캡처 관찰 가능성 | 구현 완료·Windows/Portable 검증 진행 | 미응답·경계·잘림·불완전 입력 구분 |
| `v0.10.0-alpha.1` Win64 Portable | Phase 4G 병합 후 게시 예정 | 미응답 DNS·캡처 종료 경계 실제 분석 게이트 |
| 캡처 드롭 통계·시간 범위 | 미착수 | PCAPNG ISB 등 다음 후보 범위 |
| 동일 단말 EAPOL 4-Way Handshake | 미착수 | 관찰 가능성 모델 이후 범위 |
| 로밍·RF 관찰 | 미착수 | Radiotap 전용 후속 범위 |
| 최종 오프라인 HTML 보고서 | 미착수 | 상관 정확도 안정화 이후 범위 |

## Phase 4F 상태

PR #10은 `main` Hotfix 이력을 포함하도록 정리됐고 mergeable 상태입니다. 교정된 최신 브랜치에서 Windows 일반 검증은 통과했습니다.

- Windows Server 2025
- CPython 3.13.15 x64
- 전체 테스트 275개 실행, 274개 통과
- Windows 열린 파일 교체 제약 테스트 1개 명시적 건너뜀
- 런타임 의존성 0개
- 제품 네트워크 기능 없음

초기 Portable 게이트는 Ethernet 합성 캡처에서 실제로 해석되지 않는 EAP 단계를 요구해 실패했습니다. EAP 본문은 PPP 합성 캡처에서 별도로 실제 검증되므로, 단말 여정 게이트는 실제 Ethernet 해석 범위인 DHCP → DNS → TCP로 교정했습니다.

교정된 Portable 검증 목표:

```text
DEVICE-1
DHCP 단계 = complete
DNS 단계 = complete
TCP 단계 = mixed
첫 실패 관찰 단계 = tcp
마지막 성공 방향 단계 = tcp
EAP·RADIUS 시간 추정 연결 금지
```

## Phase 4G 구현 기능

- 캡처 구조·이벤트 타임라인·거래 보고서 완전성 교차 검증
- EAP·RADIUS·DHCP·DNS·TCP 요청·응답 계열 이벤트 관찰 범위
- 미완료 거래별 `response-not-observed`, `capture-boundary-risk`, `packet-truncation-risk`, `insufficient-analysis-input`
- 첫 프레임과 마지막 관찰 프레임 경계 위험
- 잘린 패킷, 상세 이벤트 생략과 거래 근거 생략 위험
- 근거 프레임과 Wireshark `frame.number` 필터
- GUI `[9. 캡처 관찰 가능성과 미응답 해석]`
- 기존 최상위 JSON `schema_version = 2` 유지
- `capture_observability` 추가 결과
- 소스 실행 모드에서는 `capture_observability = null`

## Phase 4G 판정 경계

다음 값은 항상 `false`입니다.

```text
capture_start_proven
capture_end_proven
capture_loss_excluded
directionality_proven
absence_can_confirm_failure
absence_is_failure
```

- 파일을 끝까지 읽어도 장애 발생 전부터 캡처했거나 장애 후까지 캡처했다는 사실을 증명하지 않습니다.
- 요청·응답 계열 이벤트가 모두 보여도 모든 네트워크 방향과 모든 패킷을 수집했다는 뜻이 아닙니다.
- 응답 미관찰을 ClearPass·AD·DHCP·DNS·방화벽·서버·RF 장애로 확정하지 않습니다.
- 잘린 패킷이 있으면 상위 프로토콜 필드 누락 가능성을 표시하지만 해당 거래와의 직접 인과관계를 확정하지 않습니다.
- 일부 처리 또는 이벤트·근거 생략이 있으면 `insufficient-analysis-input`이 우선입니다.

## Phase 4G Portable 검증

런타임 생성 PCAP:

```text
#1 ARP Request
#2 DNS Query — 중간 프레임, 응답 미관찰
#3 ARP Reply
#4 DNS Query — 마지막 프레임, 응답 미관찰
```

예상 결과:

```text
DNS-1-A1 = response-not-observed
DNS-2-A1 = capture-boundary-risk
DNS-2-A1 risk = capture-end-boundary-risk
absence_is_failure = false
absence_can_confirm_failure = false
```

Python 환경변수와 일반 Python PATH를 제거한 최종 EXE에서 실행하며 다음을 검사합니다.

- 원본 IP·MAC·DNS 질의명·거래 ID·절대 시간·경로 비노출
- 캡처 시작·종료·손실·방향 미증명
- 분석 전후 Portable 폴더 무변경
- 기존 Finding·타임라인·거래·DEVICE-N·여정 게이트 유지

## 개인정보·데이터 반출 방지

Phase 4G 모델에는 원본 주소·SSID·사용자·호스트·포트·거래 ID가 입력되지 않습니다. 결과에는 다음 값을 기록하지 않습니다.

```text
IPv4·IPv6 주소
원본 Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 거래 ID·Stream 번호
HMAC 키와 내부 토큰
절대 epoch
Raw Payload·파일·쿠키·Authorization·자격 증명
캡처 파일명·절대경로
TShark stderr 원문
```

AI·외부 API·런타임 네트워크·텔레메트리·자동 업데이트·실시간 캡처·장비 접속은 없습니다.

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리스 빌드 서버에서만 수행합니다.

## 아직 지원하지 않는 기능

- 캡처 프로그램·SPAN·무선 드라이버의 실제 드롭 카운터 수집
- 캡처 시작·종료가 장애 구간을 완전히 포함했는지 자동 증명
- 응답 미관찰을 실제 미응답으로 확정
- 동일 단말 EAPOL 4-Way Handshake 메시지 1~4 완결성
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단·EDR 환경 검증
- 상용 코드 서명 인증서를 이용한 EXE 서명

현재 Phase 4G 브랜치는 **캡처 관찰 가능성과 미응답 해석 프리뷰**입니다. 응답 미관찰을 실제 장애로 확정하는 제품으로 표현하지 않습니다.
