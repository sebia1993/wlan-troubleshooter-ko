# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`, `docs/PHASE_4C_PLAN.md`, `docs/PHASE_4D_PLAN.md`, `docs/PHASE_4E_PLAN.md`, `docs/PHASE_4F_PLAN.md`, `docs/PHASE_4G_PLAN.md`, `docs/PHASE_4I_PLAN.md`, `docs/adr/0004-analysis-scoped-device-pseudonyms.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0~4E | 구현 완료·릴리스 게시 | 오프라인 기반, 캡처 점검, Finding, 타임라인, 거래, `DEVICE-N`·`AP-N` |
| Phase 4F 단말 가명별 관찰 여정 | 구현 완료·`v0.9.0-alpha.1` 게시 | 실제 프레임 순서, 첫 실패·마지막 성공 방향 단계 |
| Phase 4G 캡처 관찰 가능성 | 구현 완료·Portable 재검증 진행 | 미응답·경계·잘림·불완전 입력 구분 |
| `v0.10.0-alpha.1` | 미게시 | Phase 4G Portable 전체 게이트 통과 후 게시 |
| Phase 4I EAPOL-Key M1~M4 순서 | 구현 완료·Windows CI 통과·Portable 검증 대기 | 순서·반복·역순·일부 관찰, `DEVICE-N ↔ AP-N` |
| `v0.11.0-alpha.1` | 미게시 | Phase 4I Portable 실제 TShark 게이트 통과 후 게시 |
| Replay Counter 관계 분석 | 미착수 | Phase 4I 이후 후보 |
| 로밍·RF·HTML 보고서 | 미착수 | 후속 Phase 범위 |

## Phase 4G 공통 기반 상태

Phase 4G 일반 Windows 검증은 성공했습니다.

```text
Windows Server 2025
CPython 3.13.15 x64
소스 감사 54개 파일 통과
저장소 감사 137개 추적 파일 통과
전체 테스트 295개 실행
294개 통과
Windows 열린 파일 교체 제약 1개 명시적 건너뜀
런타임 의존성 0개
제품 네트워크 기능 없음
```

Portable 전체 검증은 `verify_device_sessions.ps1`에서 비대화형 분석 종료 코드 2로 중단되어 아직 통과하지 않았습니다. 기존 로그가 정확한 Ethernet·Wireless 구간과 제품 오류를 표시하지 않아, 다음 실행부터 다음 정보만 안전하게 출력하도록 개선했습니다.

```text
Ethernet 또는 Wireless 구간
protocol_inventory_state
길이를 500자로 제한한 제품의 비식별 오류 메시지
```

캡처 내용, 경로, 원본 주소와 TShark stderr 원문은 출력하지 않습니다.

단말 여정 실제 검증 범위도 교정했습니다.

- Ethernet 합성 캡처의 직접 EAPOL 프레임은 거래 모델에서 EAP Request·Response·Success로 해석되지 않음
- EAP 본문 해석은 PPP 전용 실제 TShark 게이트에서 별도 검증
- Ethernet 단말 여정은 DHCP → DNS → TCP만 요구
- RADIUS NAD와 단말 MAC을 분리한 전용 합성 캡처 사용
- EAP·RADIUS를 시간 또는 재사용 주소만으로 DEVICE-N에 연결하지 않음

## Phase 4I 구현 기능

- EAPOL-Key `eapol_key_message_1`~`eapol_key_message_4`만 허용
- 이벤트 범주, 메시지 상세 번호, 프레임 근거 필터와 시간·프레임 순서 검증
- 동일 프레임 Key 이벤트 중복 차단
- Key 프레임이 정확히 하나의 `DEVICE-N` 공개 근거에 있을 때만 연결
- 해당 단말의 `AP-N`이 정확히 하나일 때만 관찰 생성
- 단말 없음은 미할당, 단말·AP 후보가 둘 이상이면 모호 처리
- M4 이후 새 메시지와 진행 중 새 M1에 따른 관찰 창 분리
- `sequence-observed`, `message-repetition-observed`, `out-of-order`, `incomplete`
- 전체 메시지 번호, 첫 관찰 순서, 미관찰 번호, 반복 번호
- 같은 프레임의 802.11 Retry 비트
- `EAPOL-HS-N`, 근거 프레임과 Wireshark `frame.number` 필터
- GUI `[10. EAPOL 4-Way Handshake 메시지 순서]`
- 기존 최상위 JSON `schema_version = 2`의 `eapol_handshakes` 추가 결과

## Phase 4I 절대 판정 경계

다음 값은 전체 보고서와 각 관찰에서 항상 `false`입니다.

```text
replay_counter_correlation_available
raw_key_material_serialized
raw_identifiers_serialized
same_handshake_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

M1→M2→M3→M4가 모두 보여도 동일한 한 번의 Handshake, 키 설치, 암호학적 성공과 전체 무선 접속 성공을 확정하지 않습니다. 같은 메시지 번호와 Retry 비트가 함께 보여도 Replay Counter 관계가 없으므로 실제 동일 교환 재전송으로 확정하지 않습니다.

## Phase 4I 개인정보·키 정보 경계

제품 모델·GUI·JSON·로그에 다음 값을 기록하지 않습니다.

```text
원본 Ethernet·802.11 MAC 주소
BSSID·SSID
Replay Counter 원문
Nonce·MIC·Key Data
암호화 키
사용자명·EAP Identity
IPv4·IPv6 주소와 포트
절대 epoch
Raw Payload·자격 증명
캡처 파일명·절대경로
TShark stderr 원문
```

AI·LLM·Ollama·MCP·외부 API·런타임 네트워크·텔레메트리·자동 업데이트·실시간 캡처·장비 접속은 없습니다.

## Phase 4I Windows 일반 검증

현재 검증 완료 결과:

```text
Windows CI 실행 232
Microsoft Windows Server 2025
CPython 3.13.15 x64
소스 감사 56개 파일 통과
저장소 감사 146개 추적 파일 통과
전체 테스트 316개 실행
315개 통과
Windows 열린 파일 교체 제약 1개 명시적 건너뜀
Phase 4I 자체 점검 통과
런타임 의존성 0개
제품 네트워크 기능 없음
```

일반 CI 통과는 Portable EAPOL 실제 해석 성공을 의미하지 않습니다.

## Phase 4I Portable 목표

런타임 생성 Radiotap/IEEE 802.11 캡처:

```text
Authentication Request/Response
Association Request/Response
M1
M2
M3
Retry 비트가 있는 반복 M3
M4
```

최종 EXE 필수 결과:

```text
DEVICE-1 ↔ AP-1
source_key_events_total = 5
linked_key_events = 5
observed_message_numbers = [1,2,3,3,4]
first_observed_order = [1,2,3,4]
repeated_message_numbers = [3]
retry_flag_frames = [8]
state = message-repetition-observed
```

Python 환경변수와 일반 Python PATH를 제거한 상태에서 내장 TShark 4.6.8로 실행하고 다음도 확인합니다.

- 원본 MAC·BSSID·Nonce·MIC·Key Data·Replay Counter 원문·절대 시간 비노출
- 모든 Handshake·키 설치·암호학적 성공·근본 원인 확정 플래그 `false`
- 분석 전후 Portable 배포 폴더 무변경
- 기존 Finding·타임라인·거래·단말 가명·여정·관찰 가능성 게이트 유지

## 고정 공급망

```text
Python 계열 3.13 x64
PyInstaller 6.22.2
Wireshark/TShark 4.6.8 x64
Wireshark MSI SHA-256 779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3
Wireshark 소스 SHA-256 c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0
```

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다.

## 아직 지원하지 않는 기능

- Replay Counter 원문을 노출하지 않는 관계 기반 상관분석
- 로밍 단말의 프레임별 비식별 `DEVICE-N ↔ AP-N` 연결
- PCAPNG Interface Statistics Block·실제 드롭 카운터 활용
- 캡처 시작·종료가 장애 구간을 완전히 포함했는지 증명
- 응답 미관찰을 실제 미응답으로 확정
- Radiotap RSSI·채널·데이터율 기반 RF 분석
- Aruba Controller·ClearPass Role·VLAN 맞춤 점검 안내
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 로컬 검증
- 네트워크 어댑터 비활성·Outbound 차단·EDR·GPO·읽기 전용 경로 검증
- 상용 코드 서명 인증서를 이용한 EXE 서명

현재 Phase 4I 브랜치는 **EAPOL-Key 메시지 번호 순서 관찰 프리뷰**입니다. 4-Way Handshake 성공 또는 키 설치 성공 분석기로 표현하지 않습니다.
