# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 넓히지 않습니다.

## 현재 범위

사용자는 2026년 9월 4일 Phase 4A 이후 남은 개발과 릴리즈 갱신을 승인했습니다. 현재 범위는 `docs/PHASE_4B_PLAN.md`의 **접속 단계 상관분석과 근거 기반 Finding**입니다.

- 무선 연결·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP 단계를 재구성합니다.
- 명시적 성공·실패 응답과 근거 프레임을 분리합니다.
- Finding에 등급, 설명, 프레임 번호 Display Filter와 다음 점검 항목을 연결합니다.
- 응답 미관찰은 전체 캡처와 최소 후속 시간이 확보돼도 `판단 불가`로 제한합니다.
- EAPOL 4-Way Handshake, 로밍·RF 상관분석과 HTML 보고서는 다음 단계로 남깁니다.
- 가짜 패킷 결과, 임시 성공값과 근거 없는 원인을 만들지 않습니다.

## 기술과 런타임 금지사항

- Python 3.13 표준 라이브러리와 `tkinter/ttk`만 런타임에 사용합니다.
- AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, 온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 추가하지 않습니다.
- 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다.
- GitHub Actions의 공급망 다운로드는 제품 런타임과 분리하며 다운로드 코드를 앱에 넣지 않습니다.

## TShark 실행 경계

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용합니다.
- 시스템 설치본, 레지스트리와 PATH 실행 파일로 대체하지 않습니다.
- 실행 파일과 모든 종속 파일의 크기·SHA-256을 실행 전후 확인합니다.
- 자식 프로세스 생성은 `tshark/runner.py`의 검토된 단일 함수만 허용합니다.
- `shell=False`, stdin 비활성화, Windows 콘솔 숨김을 고정합니다.
- 이름 해석 비활성화 `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 고정 fields 출력만 허용합니다.
- 실시간 `-i`, rpcap, TCP@호스트, 임의 extcap·Lua·필터·필드·사용자 옵션을 금지합니다.
- stdout과 stderr를 동시에 읽고 크기·시간 상한을 적용합니다.
- stderr 원문은 저장·표시하지 않습니다.
- 호출마다 빈 config·plugin·extcap·data·temp 경로를 만들고 종료 후 무잔류를 확인합니다.

## Phase 4B 필드와 개인정보 경계

프로파일은 프레임 번호·시각·길이·프로토콜 계층, 802.11 상태·사유, EAP·RADIUS·DHCP·DNS·ARP·TCP의 최소 코드만 사용할 수 있습니다.

다음 값은 GUI·기본 JSON·로그에 기록하지 않습니다.

- IP·MAC·SSID·BSSID
- 사용자명·RADIUS User-Name
- DNS 질의명·호스트명
- Raw Payload·쿠키·Authorization·자격 증명
- 원본 파일명·절대경로
- DHCP·DNS 거래 ID와 TCP·UDP 스트림 번호
- TShark 표준 오류 원문

내부 거래 ID와 스트림 번호는 요청·응답 상관을 위해 메모리에서만 사용합니다.

## 판정 안전성

- Association/Reassociation 거부, EAP Failure, Access-Reject, DHCP NAK, DNS 오류 응답과 TCP RST는 해당 이벤트가 명시적으로 관찰된 경우에만 `확정`으로 표시합니다.
- `확정`은 패킷 이벤트의 존재를 뜻하며 근본 원인 전체의 확정을 뜻하지 않습니다.
- Deauthentication·Disassociation과 TCP 재전송은 `참고`로 표시합니다.
- TCP 재전송만으로 RF 장애를 확정하지 않습니다.
- 패킷 부재와 프로토콜 미관찰을 장애로 해석하지 않습니다.
- 일부 캡처에서는 미응답 Finding을 생성하지 않습니다.
- 전체 캡처의 미응답도 `판단 불가`로 유지합니다.
- Radiotap이 없으면 RSSI·SNR·채널·무선 Retry를 판단하지 않습니다.
- RADIUS가 없으면 ClearPass 장애를 확정하지 않습니다.
- 근거가 부족하면 `판단 불가`가 우선입니다.

## 검증과 릴리즈

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 통합 검증을 수행합니다.

Portable 통합 검증은 Python PATH 없이 EXE를 실행하고 임시 DNS NXDOMAIN·TCP RST 캡처에서 두 `확정` Finding이 생성되는지 확인해야 합니다. 결과에 캡처 경로·파일명·IP·DNS 질의명이 없고 배포 폴더가 변경되지 않아야 합니다.

`v0.5.0-alpha.1`은 접속 단계·근거 Finding 프리릴리즈입니다. EAPOL 4-Way Handshake·로밍·RF 근본 원인과 최종 HTML 보고서를 지원하는 완성판으로 표현하지 않습니다. 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
