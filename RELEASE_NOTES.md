# v0.13.0-alpha.1 — PCAPNG 인터페이스 드롭 통계 프리뷰

이번 릴리스는 기존 캡처 품질·Finding·단말 관찰·EAPOL 분석에 PCAPNG Interface Statistics Block(ISB) 분석을 추가합니다.

PCAPNG에 기록된 수신·드롭 Counter를 로컬에서 직접 읽되, 실제 인터페이스 이름·설명·운영체제·캡처 애플리케이션·주석·절대 시각은 결과에 기록하지 않습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.13.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행하고 PCAP 또는 PCAPNG를 선택합니다.

Python, Wireshark, 관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 새 기능

- PCAPNG Section Header Block의 섹션별 little/big-endian 처리
- Interface Description Block 선언 순서에 따른 `IFACE-N`
- `isb_ifrecv`, `isb_ifdrop`, `isb_filteraccept`, `isb_osdrop`, `isb_usrdeliv`
- 여러 ISB의 Counter 관찰 횟수·첫·마지막 보고값
- Counter 증가·감소·변화 없음 구분
- GUI `[12. PCAPNG 인터페이스 통계]`
- 최상위 분석 JSON 스키마 2를 유지하는 `pcapng_interface_statistics`
- 내장 TShark가 없는 소스 실행 모드에서도 PCAPNG 통계 제공

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

여러 ISB는 누적 스냅샷일 수 있으므로 값을 합산하지 않습니다.

## 해석 제한

다음 값은 항상 `false`입니다.

```text
raw_interface_identifiers_serialized
absolute_timestamps_serialized
capture_loss_excluded
specific_packet_loss_confirmed
root_cause_confirmed
```

다음 결론을 자동으로 내리지 않습니다.

```text
드롭 Counter 0 → 캡처 손실 없음
ISB 없음 → 캡처 손실 없음
양수 드롭 → 특정 DHCP·DNS·RADIUS·EAPOL 패킷 누락
양수 드롭 → RF·AP·단말·SPAN 장애
Counter 감소 → 캡처 도구 재시작·초기화·wrap
```

## 개인정보·메타데이터 보호

PCAPNG에 다음 값이 들어 있어도 GUI·JSON·로그에 기록하지 않습니다.

```text
인터페이스 이름·설명·GUID·장치 경로
하드웨어·운영체제·캡처 애플리케이션 문자열
캡처 필터
Section·Interface·Packet·Statistics 주석
ISB 절대 Timestamp와 starttime·endtime
원본 MAC·BSSID·SSID
IP 주소·포트·사용자명·호스트명
캡처 파일명·절대경로
```

기존 보호 경계도 유지합니다.

```text
Replay Counter 원문
Nonce·MIC·Key Data
HMAC 키·내부 토큰
Raw Payload·자격 증명
TShark stderr 원문
```

제품 런타임에는 AI·LLM·Ollama·외부 API·네트워크 통신·텔레메트리·자동 업데이트가 없습니다.

## Portable 실제 검증

런타임 생성 PCAPNG 구성:

```text
Section Header Block 1개
Interface Description Block 1개
Ethernet Enhanced Packet Block 2개
Interface Statistics Block 2개
```

첫 통계 스냅샷:

```text
ifrecv=2
ifdrop=0
filteraccept=2
osdrop=0
usrdeliv=2
```

둘째 통계 스냅샷:

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
ifrecv: first=2, last=4, counter-increase-observed
ifdrop: first=0, last=3, counter-increase-observed
osdrop: first=0, last=1, counter-increase-observed
capture_loss_excluded=false
specific_packet_loss_confirmed=false
root_cause_confirmed=false
```

합성 PCAPNG에는 인터페이스 이름·설명, 하드웨어·운영체제·캡처 앱, 패킷·통계 주석, 절대 시각, 원본 MAC·IP를 의도적으로 넣습니다. 최종 JSON에서 해당 값이 발견되면 검증을 실패시킵니다.

최종 EXE는 `PYTHONPATH`·`PYTHONHOME`을 제거하고 PATH를 Windows 시스템 폴더로 제한한 상태에서 실행합니다. 외부 Python·Wireshark를 사용하지 않으며 분석 전후 Portable 폴더 무변경도 확인합니다.

## 호환성

- 최상위 분석 JSON `schema_version = 2` 유지
- 기존 프로토콜 인벤토리·Finding·이벤트·거래·DEVICE-N·단말 여정·미응답 경계·EAPOL 순서·Replay Counter 관계 유지
- 일반 PCAP은 `unsupported-capture-format` 통계 보고서 제공
- PCAPNG 파서 오류는 TShark 실행 전에 실패-폐쇄 처리

## 아직 지원하지 않는 기능

- 드롭 Counter로 특정 누락 패킷 식별
- 캡처 시작·종료가 장애 전체 구간을 포함했는지 자동 증명
- 응답 미관찰을 실제 미응답으로 확정
- 프레임별 비식별 DEVICE/AP 로밍 연결
- RSSI·채널·데이터율 기반 RF 분석
- Aruba Controller·ClearPass 맞춤 점검 안내
- 단일 오프라인 한국어 HTML 보고서
- 실제 사내 캡처 검증
- 상용 코드 서명

## 릴리스 자산

- `WlanTroubleshooterKO-v0.13.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.13.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`
