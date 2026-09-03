# 구현 상태

기준: `CODEX_IMPLEMENTATION_PLAN.md`의 Phase 0·1. Phase 2는 시작하지 않았습니다.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·Windows 검증 대기 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·Windows 검증 대기 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 정책, HTML 검사 |
| 로컬 macOS 보조 검증 | 통과 | macOS Python 3.9.6에서 컴파일, 단위 테스트 134개, 소스 감사 27개 파일, 자체 점검 통과 |
| staged 저장소 감사 | 통과 | 의도한 50개 파일의 Git index blob을 감사해 실제 캡처·민감 산출물·바이너리 없음 확인 |
| Windows GitHub Actions | 대기 | 최초 푸시 후 `windows-latest` 결과 기록 예정 |
| 승인된 Portable TShark | 미제공 | 실행 파일·해시·내부 승인 자료 없음 |
| 실제 PCAP 분석 | 미착수 | Phase 2 범위 |

## 미검증 범위

- 승인된 TShark 실행 파일과 DLL의 Windows 실행
- 네트워크 어댑터 비활성 상태 및 Windows 방화벽 아웃바운드 차단 상태
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 사용한 분석
- 대화형 Windows GUI와 EDR/GPO 환경
- 로컬 드라이브처럼 매핑된 네트워크 드라이브의 완전한 식별

실제 사내 데이터와 캡처는 이 공개 저장소에 추가하지 않습니다.

macOS 결과는 Python 3.13 또는 Windows 검증을 대신하지 않습니다. 목표 런타임 검증의 기준은 최신 `main` 커밋에 대한 `Windows CI` 성공 결과입니다.
