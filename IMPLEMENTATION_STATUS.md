# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`부터 `docs/PHASE_4K_PLAN.md`, `docs/adr/0004-analysis-scoped-device-pseudonyms.md`.

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
| Phase 4I EAPOL M1~M4 순서 | 구현 완료·릴리스 게시 | `v0.11.0-alpha.1` |
| Phase 4J Replay Counter 관계 | 구현 완료·`main` 병합 | `v0.12.0-alpha.1` 릴리스 확인 필요 |
| Phase 4K PCAPNG 인터페이스 통계 | 구현 완료·Windows/Portable 검증 중 | PR #18 |
| `v0.13.0-alpha.1` | Phase 4K 검증·병합 후 게시 예정 | Portable 실제 PCAPNG 게이트 |
| 캡처 상대 시간·장애 구간 포함성 | 미착수 | 다음 Phase 후보 |
| 로밍·Radiotap RF 분석 | 미착수 | 후속 범위 |
| 오프라인 HTML 보고서 | 미착수 | 상관 정확도 안정화 이후 |

## Phase 4K 구현

- TShark와 독립된 PCAPNG Interface Statistics Block 로컬 파서
- 기존 `validate_capture`를 이용한 분석 전후 캡처 재검증
- SHB Byte-Order Magic 기반 섹션별 little/big-endian 처리
- 블록 앞·뒤 Total Length와 4바이트 정렬 검증
- IDB 선언과 ISB Interface ID 참조 검증
- Counter 옵션 길이·중복·패딩·옵션 경계 검증
- 파일·블록·섹션·인터페이스·ISB·옵션 수 bounded 처리
- `isb_ifrecv`, `isb_ifdrop`, `isb_filteraccept`, `isb_osdrop`, `isb_usrdeliv`
- 선언 순서 기반 `IFACE-N`
- 여러 누적 스냅샷 비합산
- Counter별 관찰 횟수·첫·마지막 보고값과 변화 방향
- 일반 PCAP `unsupported-capture-format`
- TShark 없는 소스 실행 모드에서도 PCAPNG 통계 제공
- 다운스트림 TShark 실패 시 이미 검증된 PCAPNG 통계 유지
- GUI `[12. PCAPNG 인터페이스 통계]`
- 기존 최상위 JSON `schema_version = 2` 유지

## 상태

```text
reported-drop-observed
zero-reported-drop-counters
statistics-without-drop-counters
no-interface-statistics
unsupported-capture-format
```

Counter 변화:

```text
not-reported
single-value-observed
counter-increase-observed
counter-decrease-observed
counter-unchanged-observed
```

## 판정 경계

다음 값은 항상 `false`입니다.

```text
raw_interface_identifiers_serialized
absolute_timestamps_serialized
capture_loss_excluded
specific_packet_loss_confirmed
root_cause_confirmed
```

- 드롭 Counter 0은 캡처 무손실 증명이 아닙니다.
- ISB 부재는 캡처 무손실 증명이 아닙니다.
- 양수 드롭은 특정 응답 패킷 누락 증명이 아닙니다.
- 양수 드롭은 RF·AP·단말·SPAN 장애 확정이 아닙니다.
- Counter 감소는 재시작·초기화·wrap 확정이 아닙니다.

## 개인정보·메타데이터 보호

다음 값은 GUI·JSON·로그·릴리스 자산에 기록하지 않습니다.

```text
인터페이스 이름·설명·GUID·장치 경로
하드웨어·운영체제·캡처 애플리케이션 문자열
캡처 필터와 PCAPNG 주석
ISB Timestamp·starttime·endtime
원본 MAC·BSSID·SSID
IP 주소·포트·사용자명·호스트명
Replay Counter 원문
Nonce·MIC·Key Data
암호화 키·자격 증명
절대 epoch
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

제품 런타임에는 AI·LLM·외부 API·네트워크 통신·텔레메트리·자동 업데이트가 없습니다.

## 단위 검증 범위

- little-endian 두 ISB와 양수 드롭
- big-endian 0 드롭 Counter
- ISB 있으나 드롭 옵션 없음
- 인터페이스 있으나 ISB 없음
- 다중 섹션의 Interface ID 재시작과 전역 `IFACE-N`
- Counter 증가·감소·변화 없음·단일 관찰
- 일반 PCAP 비적용 상태
- 선언되지 않은 Interface ID 거부
- 같은 ISB의 중복 Counter 거부
- 8바이트가 아닌 Counter 거부
- 앞·뒤 Total Length 불일치 거부
- 옵션 패딩 오류 거부
- 취소 처리
- 분석 전후 캡처 지문 변경 거부
- 민감한 문자열 옵션 비직렬화
- GUI의 항목 미보고와 0 보고값 구분
- 서비스의 TShark 독립 통계 보존

## Portable 실제 분석

런타임 생성 PCAPNG:

```text
SHB 1개
IDB 1개
EPB 2개
ISB 2개
```

첫 ISB:

```text
ifrecv=2
ifdrop=0
filteraccept=2
osdrop=0
usrdeliv=2
```

둘째 ISB:

```text
ifrecv=4
ifdrop=3
filteraccept=4
osdrop=1
usrdeliv=4
```

기대 공개 결과:

```text
IFACE-1
statistics_blocks=2
state=reported-drop-observed
ifrecv 2→4
ifdrop 0→3
osdrop 0→1
capture_loss_excluded=false
specific_packet_loss_confirmed=false
root_cause_confirmed=false
```

fixture에는 인터페이스 이름·설명, 하드웨어, 운영체제, 캡처 애플리케이션, 패킷·통계 주석, 절대 시작·종료 시각과 원본 MAC·IP를 넣습니다. 최종 JSON에서 이 값이 발견되면 검증을 실패시킵니다.

외부 Python·Wireshark를 사용할 수 없도록 환경변수와 PATH를 제한하며 분석 전후 Portable 폴더 무변경도 검사합니다.

## 고정 공급망

- Python: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

## 남은 개발

- PR #18 최신 HEAD의 Windows CI·Portable 최종 통과
- Phase 4K PR Draft 해제·`main` 병합
- `v0.13.0-alpha.1` 게시와 최종 ZIP SHA-256 확인
- PCAP·PCAPNG 첫→마지막 상대 시간 범위
- 캡처 시작·종료가 장애 구간을 포함했는지 보수적 판단 보강
- 프레임별 비식별 DEVICE/AP 로밍 관찰
- Radiotap RSSI·채널·데이터율 RF 분석
- Aruba Controller·ClearPass 맞춤 점검 안내
- 오프라인 단일 HTML 보고서
- 실제 사내 캡처·EDR·Outbound 차단 환경 검증
- 상용 코드 서명
