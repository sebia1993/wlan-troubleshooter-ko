# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 정책, HTML 검사 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지, 초급자 UI |
| Phase 2A 합성 입력 단위 테스트 | 구현 완료·161개 전체 테스트 통과 | 실제 캡처 없이 런타임 생성 PCAP·PCAPNG 테스트 포함 |
| 프리뷰 릴리즈 자동화 | 구현 완료·게시 성공 | `v0.2.0-alpha.1` 소스 프리뷰와 SHA-256 자산 생성 |
| 승인된 Portable TShark | 미제공 | 실행 파일·해시·내부 승인 자료 없음 |
| TShark 프로토콜 필드 추출 | 미착수 | Phase 2B 범위 |
| EAP·RADIUS·DHCP·DNS·TCP 장애 판정 | 미착수 | Phase 2C 이후 범위 |

## 자동 검증 결과

2026년 9월 3일 다음 Windows 검증이 통과했습니다.

- PR 검증: Windows CI 실행 7번 성공
- `main` 병합 후 재검증: Windows CI 실행 8번 성공
- CPython 3.13.15 x64
- Python 바이트코드 컴파일 통과
- 오프라인 소스 감사 34개 파일 통과
- 저장소 감사 61개 Git 추적 파일 통과
- 전체 단위 테스트 161개 통과
- Windows에서 open-file replacement 자체가 허용되지 않은 테스트 1개는 명시적으로 건너뜀
- 비대화형 자체 점검 통과
- 런타임 의존성 0개와 제품 네트워크 기능 없음 확인

## Phase 2A에서 제공하는 기능

- PCAP과 PCAPNG 구조의 로컬 읽기 전용 사전 점검
- 인터페이스별 Link Type, Snap Length, 검사한 패킷 수 표시
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부에 따른 분석 가능 범위 표시
- 잘린 패킷 관찰과 불완전 스캔 경고
- 파일명, 절대경로, 패킷 원문을 노출하지 않는 한국어 GUI 결과
- Windows의 동일 크기 제자리 파일 변경을 재개방 SHA-256 비교로 검출

Phase 2A의 Link Type 판정은 프로토콜의 실제 존재나 장애 원인을 확정하지 않습니다.

## 릴리즈 상태

`v0.2.0-alpha.1` 프리릴리즈가 병합 커밋 `ab7705e76655e24b5075c46f6fc98890efa854c7`을 기준으로 게시됐습니다.

- 자산: `wlan-troubleshooter-ko-v0.2.0-alpha.1-source-preview.zip`
- ZIP 크기: 53,568바이트
- ZIP SHA-256: `05626e5e7744e82b73909e3eb05ebb32daf6c123c93ac1941a37638d5c7efb29`
- 검증 파일: `wlan-troubleshooter-ko-v0.2.0-alpha.1-source-preview.zip.sha256`
- 릴리즈 성격: 설치형 실행 파일이 아닌 Python 3.13 소스 프리뷰
- 승인된 Portable TShark, Python 런타임, DLL, 설치 프로그램은 포함하지 않음

## 미검증 범위

- 승인된 TShark 실행 파일과 DLL의 Windows 실행
- 네트워크 어댑터 비활성 상태 및 Windows 방화벽 아웃바운드 차단 상태
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 사용한 분석
- 대화형 Windows GUI와 EDR/GPO 환경
- 로컬 드라이브처럼 매핑된 네트워크 드라이브의 완전한 식별
- PPI 내부 캡슐화와 벤더별 비표준 Link Type

실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다. GitHub-hosted Windows 작업은 코드·테스트·환경 호환성 근거이며 실제 사내 배포 환경 검증을 대신하지 않습니다.
