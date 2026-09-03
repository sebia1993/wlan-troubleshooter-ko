# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 정책, HTML 검사 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·PR Windows CI 검증 대기 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지, 초급자 UI |
| Phase 2A 합성 입력 단위 테스트 | 구현 완료 | 실제 캡처 없이 런타임 생성 PCAP·PCAPNG 테스트 |
| 프리뷰 릴리즈 자동화 | 구성 완료·병합 후 실행 대기 | 검증 통과 후 `v0.2.0-alpha.1` 소스 프리뷰 생성 |
| 승인된 Portable TShark | 미제공 | 실행 파일·해시·내부 승인 자료 없음 |
| TShark 프로토콜 필드 추출 | 미착수 | Phase 2B 범위 |
| EAP·RADIUS·DHCP·DNS·TCP 장애 판정 | 미착수 | Phase 2C 이후 범위 |

## Phase 2A에서 제공하는 기능

- PCAP과 PCAPNG 구조의 로컬 읽기 전용 사전 점검
- 인터페이스별 Link Type, Snap Length, 검사한 패킷 수 표시
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부에 따른 분석 가능 범위 표시
- 잘린 패킷 관찰과 불완전 스캔 경고
- 파일명, 절대경로, 패킷 원문을 노출하지 않는 한국어 GUI 결과

Phase 2A의 Link Type 판정은 프로토콜의 실제 존재나 장애 원인을 확정하지 않습니다.

## 릴리즈 상태

`v0.2.0-alpha.1`은 설치형 실행 파일이 아닌 **소스 프리뷰**입니다. Python 3.13이 필요하며 승인된 Portable TShark는 포함하지 않습니다. 릴리즈 워크플로는 PR 병합 뒤 전체 Windows 검증을 다시 통과한 경우에만 릴리즈를 생성합니다.

## 미검증 범위

- 승인된 TShark 실행 파일과 DLL의 Windows 실행
- 네트워크 어댑터 비활성 상태 및 Windows 방화벽 아웃바운드 차단 상태
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 사용한 분석
- 대화형 Windows GUI와 EDR/GPO 환경
- 로컬 드라이브처럼 매핑된 네트워크 드라이브의 완전한 식별
- PPI 내부 캡슐화와 벤더별 비표준 Link Type

실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다. GitHub-hosted Windows 작업은 코드·테스트·환경 호환성 근거이며 실제 사내 배포 환경 검증을 대신하지 않습니다.
