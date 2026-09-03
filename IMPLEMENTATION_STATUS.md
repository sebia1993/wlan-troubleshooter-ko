# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| Phase 3 Win64 Portable 배포 | 구현 완료·Windows 빌드 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스·Portable ZIP 검증 |
| Phase 4A 실제 프로토콜 존재 인벤토리 | 구현 완료·Windows 실분석 통과 | 내장 TShark `-G fields`·`-T fields`, GUI, 취소, 식별자 없는 결과 |
| `v0.4.0-alpha.1` Win64 Portable | 게시 완료 | Python·Wireshark 미설치 PC용 ZIP, SHA-256, 대응 Wireshark 소스 |
| EAP·RADIUS·DHCP·DNS·TCP 장애 판정 | 미착수 | 이벤트 상관분석과 규칙 단계 필요 |

## Phase 4A 병합

- PR: `#5 Phase 4A: 내장 TShark 실제 프로토콜 인벤토리 및 v0.4.0-alpha.1`
- 병합 커밋: `b1342149eb4aacd1c811e29557cd2dff0a78d171`
- 변경 파일: 30개
- 병합 후 Windows CI 실행 43번: 성공
- 병합 후 Win64 Portable Preview Release 실행 5번: 성공

## Windows 일반 검증

병합 커밋을 Windows Server 2025, CPython 3.13.15 x64에서 검증했습니다.

- Python 바이트코드 컴파일 통과
- 오프라인 소스 감사 46개 파일 통과
- 저장소 감사 89개 Git 추적 파일 통과
- 전체 단위 테스트 197개 실행, 196개 통과
- Windows에서 열린 파일 교체 자체가 불가능한 기존 테스트 1개만 명시적 건너뜀
- 비대화형 자체 점검 Phase 4A 통과
- 런타임 의존성 선언 0개
- 제품 네트워크 기능 없음 확인

## 실제 내장 TShark 실행 검증

최종 Portable ZIP을 압축 해제한 뒤 다음 조건에서 `WlanTroubleshooterKO.exe`를 직접 실행했습니다.

- `PYTHONPATH`와 `PYTHONHOME` 제거
- `PATH`를 Windows 시스템 디렉터리로 제한
- 외부 Python과 외부 Wireshark 사용 불가 상태
- 실행 중 합성한 ARP·DNS PCAP 사용
- 내장 TShark 4.6.8로 실제 `-G fields`와 `-T fields` 수행

검증 결과:

- 프로토콜 인벤토리 상태 `completed`
- 사전 점검 프레임 2개와 TShark 관찰 프레임 2개 일치
- ARP 그룹 관찰 성공
- DNS 그룹 관찰 성공
- 결과 JSON에 캡처 절대경로·파일명·`192.0.2.1` 없음
- 분석 전후 Portable 배포 폴더 파일 목록 동일
- 내장 TShark 전체 파일 매니페스트 검증 통과
- Python·Wireshark 별도 설치 불필요

## Phase 4A 구현 기능

- PCAP·PCAPNG 형식과 컨테이너 구조 사전 점검
- TShark 필드 카탈로그의 실제 호환성 검사
- 고정 최소 필드만 사용하는 저장 캡처 분석
- Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP, QUIC 그룹 집계
- 그룹별 관찰 프레임 수, 첫 프레임, 마지막 프레임 표시
- 전체·일부·판단 불가 상태와 잘린 프레임 경고
- 스크롤 가능한 한국어 결과 화면
- 진행 표시와 사용자 분석 취소
- 식별정보가 없는 비대화형 로컬 JSON 결과

프로토콜이 관찰됐다는 사실은 단계 성공을 뜻하지 않고, 관찰되지 않았다는 사실도 해당 단계 장애를 뜻하지 않습니다.

## TShark 실행 안전장치

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용
- 시스템 TShark, 레지스트리와 `PATH` 실행 파일로 대체하지 않음
- 모든 TShark 프로세스 생성을 검토된 단일 함수로 제한
- `shell=False`, stdin 비활성화, Windows 콘솔 숨김
- `-n`, `-2`, `-r`, `-c`, 고정 fields 출력과 승인 필드만 허용
- 실시간 `-i`, rpcap, TCP@호스트, 임의 extcap·Lua·필터·필드·옵션 차단
- stdout 64MiB, stderr 1MiB, 처리 패킷 수와 실행시간 상한
- stdout·stderr 동시 처리로 파이프 교착 방지
- stderr 원문 저장·표시 금지
- 실행 전후 TShark 번들과 캡처의 크기·SHA-256 재검증
- 호출별 빈 config·plugin·extcap·data·temp 환경
- 종료 후 격리 경로에 파일이 남으면 실패

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리즈 빌드 서버에서만 수행합니다.

## `v0.4.0-alpha.1` 릴리즈

프리릴리즈는 병합 커밋 `b1342149eb4aacd1c811e29557cd2dff0a78d171`을 대상으로 게시됐습니다.

- Portable 자산: `WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip`
- ZIP 크기: 98,383,341바이트
- ZIP SHA-256: `9581c53930c93080079eac80979940e1fe6561459ba888688c43a2e4423d5716`
- ZIP 검증 자산: `WlanTroubleshooterKO-v0.4.0-alpha.1-win64-portable.zip.sha256`
- 대응 소스: `wireshark-4.6.8.tar.xz`
- 공급망 기록: `supply-chain-observed.json`
- 릴리즈 성격: 설치가 필요 없는 Win64 Portable 프로토콜 인벤토리 프리뷰
- 애플리케이션 EXE 상용 코드 서명 인증서: 없음

## 아직 지원하지 않는 기능

- EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 단위 추출과 요청·응답 상관분석
- 인증 실패·DHCP 실패·DNS 실패·TCP 연결 실패의 장애 Finding
- EAPOL 4-Way Handshake와 로밍 중단 시간 판정
- 초급 엔지니어용 원인·근거·확인 명령·조치 안내
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태의 별도 사내 PC 검증
- 상용 코드 서명 인증서를 이용한 애플리케이션 EXE 서명

현재 릴리즈는 실행 가능한 **프로토콜 존재 인벤토리 프리뷰**이며 완성형 무선 장애 원인 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
