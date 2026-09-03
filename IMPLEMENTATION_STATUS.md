# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| `v0.2.0-alpha.2` 소스 프리뷰 | 게시 완료 | 병합 커밋 기준 ZIP 및 SHA-256 자산 생성 |
| 승인된 Portable TShark | 미제공 | 실행 파일·DLL·해시·내부 승인 자료 없음 |
| 실제 TShark 필드 추출 | 차단됨 | 승인 번들 제공과 별도 통합 검증 필요 |
| EAP·RADIUS·DHCP·DNS·TCP 장애 판정 | 미착수 | Phase 2C 이후 범위 |

## Phase 2B 자동 검증 결과

2026년 9월 3일 PR과 `main` 병합 커밋을 Windows에서 검증했습니다.

- PR Windows CI 실행 14번: 성공
- `main` 병합 후 Windows CI 실행 15번: 성공
- Preview Release 실행 2번: 성공
- CPython 3.13.15 x64
- Python 바이트코드 컴파일 통과
- 오프라인 소스 감사 40개 파일 통과
- 저장소 감사 71개 Git 추적 파일 통과
- 전체 단위 테스트 176개 실행, 175개 통과
- Windows에서 open-file replacement 자체가 불가능한 테스트 1개만 명시적 건너뜀
- 비대화형 자체 점검 통과
- 런타임 의존성 0개와 제품 네트워크 기능 없음 확인

## Phase 2B에서 구현한 기능

- 합성 `-G fields` P·F 레코드 파싱
- 프로파일 JSON 중복·미지 키·잘못된 필드명 차단
- 필수·선택 필드 호환성 해석
- 고정 이중 따옴표·탭 구분 fields 헤더·행·열 수 검증
- `frame.protocols` 기반 프로토콜 그룹별 관찰 프레임 수·첫 프레임·마지막 프레임 집계
- `frame.cap_len`·`frame.len` 기반 잘린 프레임 관찰
- 무순서 입력의 승인 필드 순서 정규화
- 이미 구성된 argv의 비정규 순서·중복·미승인 필드·실시간 캡처 인자 차단
- 승인 TShark가 있을 때 사용할 필드 카탈로그·인벤토리 argv와 빈 격리 환경의 실행 전 준비
- 실행 전 준비 테스트에서 자식 프로세스가 시작되지 않음을 확인

프로토콜 존재 또는 미관찰은 접속 성공·실패와 장애 원인의 증거로 사용하지 않습니다.

## 프리릴리즈 상태

`v0.2.0-alpha.2` 프리릴리즈가 병합 커밋 `34058ce98e5abf6ad3ef559a424d9c04a02252ba`를 기준으로 게시됐습니다.

- 자산: `wlan-troubleshooter-ko-v0.2.0-alpha.2-source-preview.zip`
- ZIP 크기: 64,836바이트
- ZIP SHA-256: `450f6c48b39f2d3bd0c4dd8188b9a225203ea056612c9379ea20442be7fcb54e`
- 검증 자산: `wlan-troubleshooter-ko-v0.2.0-alpha.2-source-preview.zip.sha256`
- 릴리즈 성격: Python 3.13 소스 프리뷰
- 승인 TShark·Python 런타임·DLL·설치 프로그램은 포함하지 않음

## 차단·미검증 범위

- 승인된 TShark 실행 파일과 DLL의 실제 Windows 실행
- 실제 `tshark -G fields` 필드 호환성
- 실제 PCAP에 대한 `-T fields` 프로토콜 인벤토리
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 사용한 분석
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태
- 대화형 Windows GUI와 EDR/GPO 환경
- PPI 내부 캡슐화와 벤더별 비표준 Link Type

실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다. 합성 테스트 통과를 실제 사내 환경 검증으로 표현하지 않습니다.
