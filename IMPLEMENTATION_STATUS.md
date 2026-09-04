# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`부터 `docs/PHASE_4J_PLAN.md`, `docs/adr/0004-analysis-scoped-device-pseudonyms.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0~3 기반·Portable | 구현 완료·검증 통과 | 오프라인 보안 경계, PCAP/PCAPNG, 내장 TShark |
| Phase 4A 프로토콜 인벤토리 | 구현 완료·릴리스 게시 | 실제 프로토콜 존재 집계 |
| Phase 4B 접속 단계·Finding | 구현 완료·릴리스 게시 | 명시적 실패 Finding |
| Phase 4C 이벤트 타임라인 | 구현 완료·릴리스 게시 | 상대 시간·비식별 거래 별칭 |
| Phase 4D 프로토콜 거래 시도 | 구현 완료·릴리스 게시 | EAP·RADIUS·DHCP·DNS·TCP 완결성 |
| Phase 4E 단말·AP 가명 | 구현 완료·릴리스 게시 | `DEVICE-N`, `AP-N`, HMAC 키 미저장 |
| Phase 4F 단말 관찰 여정 | 구현 완료·릴리스 게시 | 실제 프레임 순서와 단계 상태 |
| Phase 4G 캡처 관찰 가능성 | 구현 완료·릴리스 게시 | 미응답·경계·잘림·불완전 입력 구분 |
| Phase 4I EAPOL M1~M4 순서 | 구현 완료·`v0.11.0-alpha.1` 게시 | 메시지 순서·반복·Retry 근거 |
| Phase 4J Replay Counter 관계 | 구현 완료·후보 Windows/Portable 검증 통과 | Counter 원문 미직렬화 관계 분석 |
| `v0.12.0-alpha.1` | 깨끗한 main 대상 PR 재검증 후 게시 예정 | 관계 전용 Portable 실분석 게이트 |
| PCAPNG Interface Statistics | 초기 개발 진행 | Phase 4K 초안 PR |
| 캡처 시간 범위·로밍·RF·HTML | 미착수 | 후속 Phase |

## Phase 4J 구현

- Wireshark 4.6.8의 `eapol.keydes.replay_counter` 전용 최소 프로파일
- 원문 Counter를 공개 이벤트·단말 가명·레거시 경로에서 차단
- 기존 분석과 같은 캡처 SHA-256·TShark 매니페스트 재검증
- M1/M2·M3/M4 동일·불일치 관계
- M1→M3 증가·동일·감소 관계
- 반복 메시지의 같은 Counter·다른 Counter 관계
- 필드 부재·Counter 누락·근거 생략의 `unavailable`·`partial`
- GUI `[11. EAPOL Replay Counter 관계]`
- 기존 최상위 JSON 스키마 2를 유지하는 `eapol_replay_relations`

## 절대 판정 경계

```text
raw_replay_counters_serialized = false
replay_counter_values_persisted = false
same_handshake_confirmed = false
retransmission_confirmed = false
key_installation_confirmed = false
cryptographic_success_confirmed = false
root_cause_confirmed = false
```

Counter 관계가 일반적 형태와 일치해도 동일 Handshake, 실제 재전송, 키 설치와 암호학적 성공을 확정하지 않습니다. 관계 불일치는 캡처 누락·여러 교환 혼재 가능성을 포함하므로 AP·단말·RF 장애의 근본 원인으로 확정하지 않습니다.

## 후보 Windows 검증

Phase 4J 기능 기준 Windows CI:

```text
Windows Server 2025
CPython 3.13.15 x64
전체 테스트 340개 실행
339개 통과
플랫폼 제약 테스트 1개 명시적 건너뜀
오프라인 소스 감사 59개 파일 통과
저장소 감사 156개 추적 파일 통과
런타임 의존성 0개
제품 네트워크 기능 없음
```

## 후보 Portable 실제 분석

외부 Python·Wireshark를 사용할 수 없는 PATH에서 최종 EXE로 다음 게이트를 모두 통과했습니다.

- DNS 오류·TCP RST Finding과 거래 시도
- Ethernet·Radiotap IEEE 802.11·PPP EAP 이벤트 타임라인
- EAP·RADIUS·DHCP·DNS·TCP 거래
- `DEVICE-N`·`AP-N` 개인정보 경계
- 단말 가명별 DHCP→DNS→TCP 여정
- 미응답 DNS와 캡처 종료 경계
- EAPOL M1→M2→M3→반복 M3→M4
- Replay Counter 관계 전용 실제 TShark 해석

합성 Counter:

```text
M1/M2 = 18446744073709551000
M3/반복 M3/M4 = 18446744073709551001
```

공개 결과:

```text
M1/M2 = equal-observed
M3/M4 = equal-observed
M1→M3 = increased-observed
반복 M3 = same-counter-observed
state = expected-relations-observed
```

후보 Portable 자산:

```text
WlanTroubleshooterKO-v0.12.0-alpha.1-win64-portable.zip
크기 = 98,539,557 bytes
SHA-256 = 0273bbc000d3fc0b19ca4d4109c756fcf4c43d61945e09ba3f1ede09501ba3eb
```

병합 후 `main` 릴리스 워크플로가 다시 빌드하므로 최종 게시 자산의 크기와 SHA-256은 새로 확정합니다.

## 데이터 보호

다음 값은 공개 결과에 기록하지 않습니다.

```text
Replay Counter 원문
Nonce·MIC·Key Data
원본 MAC·BSSID·SSID
IP·포트·사용자명·호스트명
암호화 키·자격 증명
HMAC 키·내부 토큰
절대 epoch
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

제품 런타임에는 AI·외부 API·네트워크 통신·텔레메트리·자동 업데이트가 없습니다.

## 고정 공급망

- Python: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

## 남은 개발

- Phase 4J를 `main` 단일 부모의 깨끗한 PR로 재검증·병합
- `v0.12.0-alpha.1` 게시 자산의 최종 SHA-256·크기 확인
- Phase 4K PCAPNG Interface Statistics Block 완성
- 캡처 첫→마지막 상대 시간과 ISB 시간 해상도 결합
- 프레임별 비식별 `DEVICE-N ↔ AP-N` 링크와 로밍 관찰
- Radiotap RSSI·채널·데이터율·Retry RF 관찰
- Aruba Controller·ClearPass 맞춤 점검 안내
- 오프라인 단일 HTML 보고서
- 실제 사내 캡처·EDR·Outbound 차단 환경 검증
- 상용 코드 서명
