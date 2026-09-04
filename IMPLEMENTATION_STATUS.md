# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`, `docs/PHASE_4C_PLAN.md`, `docs/PHASE_4D_PLAN.md`, `docs/PHASE_4E_PLAN.md`, `docs/PHASE_4F_PLAN.md`, `docs/adr/0004-analysis-scoped-device-pseudonyms.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·검증 통과 | PCAP·PCAPNG bounded scan, Link Type, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·검증 통과 | 필드 카탈로그, 고정 프로파일, TSV 파서 |
| Phase 3 Win64 Portable | 구현 완료·검증 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스 |
| Phase 4A 프로토콜 인벤토리 | 구현 완료·릴리스 게시 | 실제 내장 TShark 프로토콜 존재 집계 |
| Phase 4B 접속 단계·Finding | 구현 완료·릴리스 게시 | 명시적 실패 Finding과 보수적 미응답 처리 |
| Phase 4C 이벤트 타임라인 | 구현 완료·릴리스 게시 | 상대 시간·로컬 거래 별칭·근거 프레임 |
| Phase 4D 프로토콜 거래 시도 | 구현 완료·릴리스 게시 | EAP·RADIUS·DHCP·DNS·TCP 시도별 완결성 |
| Phase 4E 분석 실행별 단말·AP 가명 | 구현 완료·릴리스 게시 | `DEVICE-N`, `AP-N`, HMAC 키 미저장, 단일 근거 연결 |
| Windows 격리 디렉터리 Hotfix | 구현 완료·검증 통과 | 일반 메타데이터 변경 허용, 객체·Reparse Point 검사 유지 |
| Phase 4F 단말 가명별 관찰 여정 | 구현 완료·최종 Portable 검증 진행 | 안전하게 연결된 거래의 단계별 관찰 여정 |
| `v0.9.0-alpha.1` Win64 Portable | PR 병합 후 게시 예정 | DEVICE-N EAP·DHCP·DNS·TCP 실제 여정 게이트 포함 |
| 캡처 완전성·실제 미응답 구분 | 미착수 | 다음 Phase 범위 |
| 동일 단말 EAPOL 4-Way Handshake | 미착수 | 완전성 모델 또는 별도 Phase 범위 |
| 로밍·RF 관찰 | 미착수 | Radiotap 전용 후속 범위 |
| 최종 오프라인 HTML 보고서 | 미착수 | 상관 정확도 안정화 이후 범위 |

## Phase 4F 구현 기능

- Phase 4D `transaction_sessions`와 Phase 4E `device_sessions`만 입력으로 사용
- `linked`이며 단말 후보가 하나인 거래만 `DEVICE-N` 여정에 포함
- 연결 객체의 근거 프레임과 원 거래 근거의 완전 일치 검증
- 비어 있거나 일부 생략된 근거의 단말 여정 연결 차단
- 생략 근거 거래가 미연결·빈 근거로 정제된 경우에만 안전하게 제외
- `unassigned`·`ambiguous` 거래의 여정 제외와 별도 집계
- EAP·RADIUS·DHCP·DNS·TCP 단계별 거래 상태 집계
- 실제 프레임 순서 기반 관찰 단계 순서
- 첫 실패 관찰 단계와 마지막 성공 방향 단계
- 동일 단계 성공 방향·실패 혼재 보존
- 단계별 거래 시도 ID·근거 프레임·Wireshark 필터
- `progress-observed`, `failure-observed`, `mixed`, `partial-progress`, `incomplete`, `no-linked-transactions`
- GUI `[8. 단말 가명별 관찰 여정]`
- 기존 분석 JSON 스키마 2를 유지하는 `device_journeys` 추가 결과

## Phase 4F 판정 경계

- 여정은 같은 `DEVICE-N`에 안전하게 연결된 거래의 관찰 묶음입니다.
- `DEVICE-N`은 현재 실행에서만 유효하며 다른 실행의 같은 번호와 비교할 수 없습니다.
- 첫 실패 관찰 단계는 근본 원인의 위치가 아닙니다.
- 마지막 성공 방향 단계는 전체 접속 성공을 뜻하지 않습니다.
- RADIUS처럼 단말 L2 근거가 없는 거래를 시간 근접성으로 연결하지 않습니다.
- TCP SYN/SYN-ACK만으로 3-Way Handshake 완료를 확정하지 않습니다.
- 성공 방향·실패가 함께 있으면 `mixed`로 표시합니다.
- 패킷·프로토콜 미관찰을 장애로 확정하지 않습니다.

다음 값은 항상 `false`입니다.

```text
raw_identifiers_serialized
alias_secret_persisted
aliases_stable_across_runs
device_identity_confirmed
cross_protocol_session_confirmed
root_cause_confirmed
```

## 개인정보·데이터 반출 방지

Phase 4F에는 원본 주소·SSID·사용자·호스트·포트·거래 ID가 입력되지 않습니다. 결과에는 다음 값을 기록하지 않습니다.

```text
IPv4·IPv6 주소
Ethernet·802.11 MAC 주소
SSID·BSSID
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 EAP·RADIUS·DHCP·DNS 거래 ID
원본 TCP·UDP Stream 번호
HMAC 키와 내부 토큰
절대 epoch
Raw Payload·파일·쿠키·Authorization·자격 증명
캡처 파일명·절대경로
TShark 표준 오류 원문
```

AI·외부 API·런타임 네트워크·텔레메트리·자동 업데이트·실시간 캡처·장비 접속은 없습니다.

## 생략 근거와 실패-폐쇄 처리

- 원 거래 근거 최대 64개, 단계·여정 근거 최대 96개
- 근거가 생략된 거래는 Phase 4E 연결용 복사본에서 근거를 비우고 미연결 처리
- 생략 거래 + 미연결 + 빈 연결 근거만 안전한 제외 상태로 허용
- 생략 거래가 `DEVICE-N`에 연결되거나 연결 근거를 유지하면 거부
- 단말 가명 보고서의 개인정보 보호 플래그가 바뀌면 거부
- 연결 근거와 원 거래 근거가 다르면 거부
- 잘못된 가명·중복 거래·연결 누락·프레임 범위 오류를 거부

## Windows 격리 경로 보완

TShark의 임시파일 생성·삭제 때문에 Windows 디렉터리의 Archive·시간·크기가 바뀌어도 객체 교체로 오인하지 않습니다. 다음 검사는 계속 유지합니다.

- 장치 ID·파일 ID/inode
- 객체 종류·링크 수
- Symlink·Junction·Reparse Point
- 실행 후 격리 디렉터리 무잔류

## Windows 일반 검증

PR #10의 기능 검증 기준 커밋 `107b4881449f739b836894ff1cee89cf517f121a`에서 다음 결과를 확인했습니다.

- Microsoft Windows Server 2025
- CPython 3.13.15 x64
- 오프라인 소스 감사 52개 파일 통과
- 저장소 감사 126개 Git 추적 파일 통과
- 전체 테스트 275개 실행
- 274개 통과
- Windows 열린 파일 교체 제약 테스트 1개 명시적 건너뜀
- Phase 4F 자체 점검 통과
- 런타임 의존성 0개
- 제품 네트워크 기능 없음

문서 갱신 후 최신 커밋에서 Windows CI와 Portable 검증을 다시 수행합니다.

## Portable 실제 분석 목표

최종 EXE를 외부 Python·Wireshark가 없는 환경에서 실행하여 런타임 생성 Ethernet PCAP을 확인합니다.

- `DEVICE-1` EAP·DHCP·DNS·TCP 관찰 순서
- EAP Request·Response·Success 완료
- DHCP DORA 완료
- DNS 정상 거래 완료
- TCP SYN/SYN-ACK 성공 방향 거래
- 별도 TCP RST 실패 거래
- TCP 단계 `mixed`
- 첫 실패 관찰 단계 `tcp`
- 마지막 성공 방향 단계 `tcp`
- RADIUS 시간 추정 연결 금지
- 원본 식별정보·가명화 키·절대 시간 비노출
- 모든 신원·교차 세션·근본 원인 확정 플래그 `false`
- 분석 전후 Portable 폴더 무변경

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리스 빌드 서버에서만 수행합니다.

## 아직 지원하지 않는 기능

- `DEVICE-N`을 실제 사용자·자산 신원으로 확정
- 여러 프로토콜 거래가 하나의 완전한 사용자 세션임을 확정
- 캡처 누락과 실제 미응답의 자동 확정 구분
- 동일 단말 EAPOL 4-Way Handshake 메시지 1~4 완결성
- BSSID·채널·RSSI 기반 로밍·RF 근본 원인 분석
- Aruba Controller·ClearPass Role·VLAN 구체 점검 안내
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단·EDR 환경 검증
- 상용 코드 서명 인증서를 이용한 EXE 서명

현재 브랜치는 **단말 가명별 접속 관찰 여정 프리뷰**입니다. 동일 사용자 신원이나 완성형 WLAN 근본 원인 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
