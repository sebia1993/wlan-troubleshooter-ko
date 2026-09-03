# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·PR Windows CI 검증 대기 | 카탈로그, 프로파일, TSV 파서, 프로토콜 정규화, argv 준비 |
| 승인된 Portable TShark | 미제공 | 실행 파일·DLL·해시·내부 승인 자료 없음 |
| 실제 TShark 필드 추출 | 차단됨 | 승인 번들 제공과 별도 통합 검증 필요 |
| EAP·RADIUS·DHCP·DNS·TCP 장애 판정 | 미착수 | Phase 2C 이후 범위 |

## Phase 2B 자동 검증 범위

- 합성 `-G fields` P·F 레코드 파싱
- 프로파일 JSON 중복·미지 키·잘못된 필드명 차단
- 필수·선택 필드 해석
- fields 헤더·행·따옴표·열 수 검증
- 프로토콜 그룹별 프레임 집계와 결정론적 직렬화
- 무순서 입력의 승인 필드 순서 정규화
- 미승인 필드·필터·실시간 캡처 인자 차단
- 실행 전 격리 환경 준비 시 자식 프로세스 미생성 확인

## 검증 대기 및 미검증 범위

- 현재 문서·버전 갱신 커밋의 Windows CI
- 승인된 TShark의 실제 `-G fields`와 `-T fields`
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 사용한 분석
- 네트워크 어댑터 비활성·Windows 방화벽 차단 상태
- 대화형 Windows GUI와 EDR/GPO 환경
- PPI 내부 캡슐화와 벤더별 비표준 Link Type

## 릴리즈 계획

`v0.2.0-alpha.2`는 Python 3.13 소스 프리뷰입니다. 승인 TShark·Python 런타임·DLL·설치 프로그램은 포함하지 않습니다. Windows 전체 검증이 통과하고 PR이 병합된 뒤 Preview Release 워크플로가 새 소스 ZIP과 SHA-256을 게시합니다.

실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다. 합성 테스트 통과를 실제 사내 환경 검증으로 표현하지 않습니다.
