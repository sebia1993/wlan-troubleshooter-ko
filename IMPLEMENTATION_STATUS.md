# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`, `docs/PHASE_4C_PLAN.md`, `docs/PHASE_4D_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| Phase 3 Win64 Portable 배포 | 구현 완료·Windows 빌드 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스·Portable ZIP 검증 |
| Phase 4A 실제 프로토콜 존재 인벤토리 | 구현 완료·Windows 실분석 통과 | 내장 TShark `-G fields`·`-T fields`, GUI, 취소, 식별자 없는 결과 |
| Phase 4B 접속 단계·근거 Finding | 구현 완료·릴리즈 게시 | 명시적 실패 Finding, 미응답 안전 제한, `v0.5.0-alpha.1` |
| Phase 4C 비식별 이벤트 타임라인 | 구현 완료·릴리즈 게시 | 시간순 이벤트·로컬 별칭·Portable 실제 분석, `v0.6.0-alpha.1` |
| Phase 4D 비식별 프로토콜 거래 시도 | 구현 완료·Windows 및 Portable 검증 통과 | EAP·RADIUS·DHCP·DNS·TCP 시도 분리와 보수적 완결성 |
| `v0.7.0-alpha.1` Win64 Portable | 게시 완료 | Python·Wireshark 미설치 PC용 ZIP, SHA-256, 대응 Wireshark 소스 |
| 단말별 익명 세션 분리 | 미착수 | 다음 Phase 범위 |
| 최종 오프라인 HTML 보고서 | 미착수 | 단말 세션·상관 정확도 확보 이후 범위 |

## Phase 4D 병합

- PR: `#8 Phase 4D: 비식별 프로토콜 거래 시도 요약 및 v0.7.0-alpha.1`
- 병합 커밋: `15d0ba1a26d4d1407db35f98527539562f850dab`
- 병합 후 Windows CI: 실행 146번 성공
- 병합 후 Win64 Portable Preview Release: 실행 8번 성공

## Phase 4D 구현 기능

- Phase 4C의 `EAP-N`, `RADIUS-N`, `DHCP-N`, `DNS-N`, `TCP-N` 비식별 별칭만 사용
- 같은 별칭이 명시적 종료 이벤트 뒤 재사용되면 `A1`, `A2` 거래 시도로 분리
- EAP Request → Response → Success 완결성
- RADIUS Access-Request → Access-Accept 완결성 및 Access-Reject
- DHCP Discover → Offer → Request → ACK 완결성 및 NAK
- DNS Query → 정상 Response 완결성 및 오류 Response
- TCP SYN → SYN/ACK 성공 방향 관찰 및 TCP RST 실패 결과
- `complete`, `success-observed`, `failure-observed`, `mixed`, `incomplete` 상태
- 첫·마지막 프레임, 상대 지속시간, 관찰 이벤트와 미관찰 순서 요소
- 시도별 `frame.number` Wireshark 근거 필터와 다음 점검 항목
- GUI `[6. 비식별 거래 시도 요약]`
- 기존 분석 JSON 스키마 버전 2를 유지하면서 `transaction_sessions` 추가 결과 제공

## 판정 안전 기준

- 모든 거래 시도는 `root_cause_confirmed=false`를 유지합니다.
- 모든 거래 시도는 `device_session_confirmed=false`를 유지합니다.
- 프로토콜 거래 완료는 해당 순서 요소의 관찰일 뿐 무선 접속 전체 성공을 뜻하지 않습니다.
- Failure·Reject·NAK·DNS 오류·RST는 해당 패킷 이벤트가 관찰됐다는 뜻이며 책임 시스템이나 근본 원인을 확정하지 않습니다.
- TCP는 최종 ACK를 구분하지 않으므로 SYN·SYN/ACK가 있어도 3-Way Handshake 완료로 표시하지 않습니다.
- 거래 미완료를 서버·방화벽·ClearPass 장애로 확정하지 않습니다.
- 서로 다른 프로토콜 거래를 동일 단말의 한 접속으로 연결하지 않습니다.
- 성공과 실패가 같은 별칭 시도에 있으면 혼재로 표시합니다.
- 일부 캡처나 이벤트 상세 생략이 있으면 거래 보고서 전체를 일부 결과로 표시합니다.

## 개인정보·데이터 반출 방지

Phase 4D는 타임라인의 로컬 별칭, 이벤트 종류, 프레임 번호와 상대 시간만 사용합니다. 다음 값은 결과에 기록하지 않습니다.

- IPv4·IPv6 주소
- Ethernet·802.11 MAC 주소
- SSID·BSSID
- 사용자명·EAP Identity·RADIUS User-Name
- DNS 질의명·호스트명
- TCP·UDP 포트
- 원본 EAP·RADIUS·DHCP·DNS 거래 ID
- 원본 TCP·UDP Stream 번호
- 절대 epoch
- Raw Payload·파일·쿠키·Authorization·자격 증명
- 캡처 파일명·절대경로
- TShark 표준 오류 원문

AI·외부 API·런타임 네트워크·텔레메트리·자동 업데이트·실시간 캡처·장비 접속은 없습니다.

## Windows 일반 검증

병합 커밋을 Microsoft Windows Server 2025, CPython 3.13.15 x64에서 검증했습니다.

- Python 바이트코드 컴파일 통과
- 오프라인 소스 감사 49개 파일 통과
- 저장소 감사 106개 Git 추적 파일 통과
- 전체 단위 테스트 228개 실행, 227개 통과
- Windows에서 열린 파일 교체가 불가능한 기존 플랫폼 테스트 1개만 명시적 건너뜀
- Phase 4D 비대화형 자체 점검 통과
- 런타임 의존성 선언 0개
- 제품 네트워크 기능 없음 확인

## Portable 실제 패킷 검증

최종 Portable ZIP을 압축 해제하고 다음 조건에서 `WlanTroubleshooterKO.exe`를 직접 실행했습니다.

- `PYTHONPATH`와 `PYTHONHOME` 제거
- `PATH`를 Windows 시스템 디렉터리로 제한
- 외부 Python과 외부 Wireshark 사용 불가 상태
- 내장 TShark 4.6.8 사용

실제 합성 캡처 검증 결과:

- DNS NXDOMAIN: `DNS-1-A1 / failure-observed`
- TCP SYN → RST: `TCP-1-A1 / failure-observed`
- PPP EAP Request → Response → Success: `complete`
- RADIUS Access-Request → Access-Accept: `complete`
- DHCP Discover → Offer → Request → ACK: `complete`
- DNS Query → 정상 Response: `complete`
- TCP SYN → SYN/ACK: `success-observed`, `complete`로 과장하지 않음
- 별도 TCP RST: `failure-observed`
- 모든 거래의 `root_cause_confirmed=false` 확인
- 모든 거래의 `device_session_confirmed=false` 확인
- 결과 JSON에 캡처 경로·파일명·IP·MAC·DNS 질의명·원본 거래 ID·Stream 번호·절대 epoch가 없음
- 분석 전후 Portable 배포 폴더 파일 목록 동일

## `v0.7.0-alpha.1` 릴리즈

프리릴리즈는 병합 커밋 `15d0ba1a26d4d1407db35f98527539562f850dab`을 대상으로 게시됐습니다.

- Portable 자산: `WlanTroubleshooterKO-v0.7.0-alpha.1-win64-portable.zip`
- ZIP 크기: 98,440,392바이트
- ZIP SHA-256: `eee53dd56dc660456c4a2763e9c709855b4c52c930f0e8f7b5e191bb9b72d846`
- ZIP 검증 자산: `WlanTroubleshooterKO-v0.7.0-alpha.1-win64-portable.zip.sha256`
- 대응 소스: `wireshark-4.6.8.tar.xz`
- 공급망 기록: `supply-chain-observed.json`
- 릴리즈 성격: 설치가 필요 없는 Win64 Portable 비식별 거래 시도 프리뷰
- 애플리케이션 EXE 상용 코드 서명 인증서: 없음

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리즈 빌드 서버에서만 수행합니다.

## 아직 지원하지 않는 기능

- 원본 MAC·SSID를 결과에 노출하지 않는 단말별 익명 세션 분리
- 서로 다른 EAP·RADIUS·DHCP·DNS·TCP 거래를 동일 단말 접속으로 연결
- 동일 단말의 EAPOL 4-Way Handshake 메시지 1~4 완결성 판정
- 응답 미관찰과 캡처 누락·단방향 수집의 자동 구분
- BSSID·채널·RSSI 기반 로밍·RF 장애 상관분석
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태의 별도 사내 PC 검증
- 상용 코드 서명 인증서를 이용한 애플리케이션 EXE 서명

현재 릴리즈는 **비식별 프로토콜 거래 시도 프리뷰**이며 완성형 단말별 WLAN 근본 원인 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
