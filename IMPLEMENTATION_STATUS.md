# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| Phase 3 Win64 Portable 배포 | 구현 완료·Windows 빌드 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스·Portable ZIP 검증 |
| `v0.3.0-alpha.1` Win64 Portable | 게시 완료 | Python·Wireshark 미설치 PC용 ZIP 및 SHA-256 자산 |
| 내장 TShark 준비 확인 | 자동 검증 통과 | `tshark -n -v`, `tshark -n -G fields`, 전체 파일 매니페스트 |
| 실제 PCAP TShark 프로토콜 인벤토리 | 미연결 | `-T fields` 파서·프로파일은 있으나 GUI 실행 경로는 아직 없음 |
| EAP·RADIUS·DHCP·DNS·TCP 장애 판정 | 미착수 | 이벤트 상관분석과 규칙 단계 필요 |

## Phase 3 병합과 자동 검증

Phase 3 PR #4를 병합한 뒤 릴리즈 요약 구문을 수정하여 다음 커밋을 기준으로 최종 검증했습니다.

- 기능 병합 커밋: `1114083274dd59fe1e288dcb6cb3cefb33d00d06`
- 최종 릴리즈 워크플로 커밋: `4021ba3703fa5dfe765fda82c6013e78ab4e8c23`
- Windows CI 실행 30번: 성공
- Win64 Portable Preview Release 실행 4번: 성공
- CPython 3.13.15 x64
- Python 바이트코드 컴파일 통과
- 오프라인 소스 감사 41개 파일 통과
- 저장소 감사 80개 Git 추적 파일 통과
- 전체 단위 테스트 186개 실행, 185개 통과
- Windows에서 열린 파일 교체 자체가 불가능한 테스트 1개만 명시적 건너뜀
- 비대화형 자체 점검 통과
- 제품 런타임 의존성 선언 0개와 네트워크 기능 없음 확인

## Python·Wireshark 미설치 실행 검증

Portable 빌드에서 Python 관련 환경변수를 제거하고 `PATH`를 Windows 시스템 디렉터리로 제한한 상태에서 `WlanTroubleshooterKO.exe`를 직접 실행해 자체 점검했습니다.

- `python_external_required=false`
- `tshark_external_required=false`
- 내장 Tkinter 리소스 로딩 성공
- 내장 TShark 전체 파일 크기·SHA-256 매니페스트 검증 성공
- 내장 TShark 버전 확인 성공
- 내장 TShark 필드 카탈로그 생성 성공
- Portable 패키지 실행 파일은 `WlanTroubleshooterKO.exe`, `vendor/wireshark/tshark.exe` 두 개만 허용
- Python·Tcl·Tk·PyInstaller·Wireshark 라이선스 파일 포함 확인

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `Wireshark Foundation`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리즈 빌드 서버에서만 수행합니다.

## `v0.3.0-alpha.1` 릴리즈

프리릴리즈는 최종 워크플로 커밋 `4021ba3703fa5dfe765fda82c6013e78ab4e8c23`을 대상으로 게시됐습니다.

- Portable 자산: `WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip`
- ZIP 크기: 98,342,206바이트
- ZIP SHA-256: `c4845c7cd191bc1a8cdb95d64029f9b0790eeb803c42728130a7d892ab866d71`
- ZIP 검증 자산: `WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip.sha256`
- 대응 소스: `wireshark-4.6.8.tar.xz`
- 공급망 기록: `supply-chain-observed.json`
- 릴리즈 성격: 설치가 필요 없는 Win64 Portable 프리뷰
- 애플리케이션 EXE 상용 코드 서명 인증서: 없음

## 현재 사용 가능한 기능

- Python·Wireshark·Node.js 설치 없이 GUI 실행
- PCAP·PCAPNG 파일 형식과 컨테이너 구조 검사
- 다중 Section·다중 인터페이스 PCAPNG 처리
- Link Type, Snap Length, 패킷 레코드 수 확인
- 잘린 패킷과 일부 스캔 경고
- Radiotap·IEEE 802.11·Ethernet·PPI의 보수적 구분
- 캡처 형식상 확인 가능한 항목과 확인할 수 없는 항목 안내
- 내장 TShark 공급망·무결성·필드 카탈로그 검증

## 아직 지원하지 않는 기능

- GUI에서 실제 PCAP을 TShark `-T fields`로 처리하는 프로토콜 인벤토리
- EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 추출과 상관분석
- 인증 실패·DHCP 실패·DNS 실패·TCP 연결 실패의 장애 Finding
- 4-Way Handshake와 로밍 장애 판정
- 최종 한국어 HTML 장애 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태의 별도 사내 PC 검증
- 상용 코드 서명 인증서를 이용한 애플리케이션 EXE 서명

현재 릴리즈는 실행 가능한 **캡처 사전 점검 프리뷰**이며 완성형 무선 장애 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
