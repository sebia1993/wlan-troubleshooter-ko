# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 넓히지 않습니다.

## 현재 범위

사용자는 2026년 9월 4일 남은 개발을 계속하도록 승인했습니다. 현재 범위는 `docs/PHASE_4C_PLAN.md`의 **비식별 무선 접속 이벤트 타임라인**입니다.

- 저장된 로컬 PCAP·PCAPNG에서 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트를 정리합니다.
- 기존 접속 단계 Finding과 타임라인을 동일한 TShark fields 출력에서 생성합니다.
- 상대 시간, 근거 프레임, 고정 Display Filter와 로컬 상관 별칭을 표시합니다.
- 여러 단말과 접속이 섞인 캡처를 하나의 세션으로 자동 결합하지 않습니다.
- 단말별 익명 세션 분리, 로밍·RF 근본 원인과 HTML 보고서는 다음 단계로 남깁니다.
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

## Phase 4C 허용 필드

접속 이벤트 프로파일에는 다음 종류만 허용합니다.

- 프레임 번호·시간·인터페이스·캡처 길이·프로토콜 계층
- 802.11 유형·Retry·상태·사유·인증 알고리즘·인증 순번
- EAPOL 유형·Key 메시지 번호
- EAP·RADIUS·DHCP·DNS 결과 코드와 내부 거래 번호
- UDP·TCP 내부 스트림 번호
- ARP Opcode
- TCP SYN·ACK·RST·Retransmission
- TLS Handshake 유형

IP·IPv6·MAC·SSID·BSSID·사용자명·EAP Identity·RADIUS User-Name·DNS 질의명·호스트명·포트·Payload 필드는 금지합니다.

## 데이터와 판정 안전성

- 입력 캡처는 확장자·매직·구조·정규 파일·링크 여부·SHA-256을 검사합니다.
- TShark 실행 전후 캡처의 형식·크기·SHA-256이 달라지면 실패합니다.
- 원본 캡처를 수정하거나 자동 삭제하지 않습니다.
- GUI·기본 JSON·로그에 금지된 식별정보와 원본 파일 경로를 남기지 않습니다.
- 절대 epoch와 원본 EAP·RADIUS·DHCP·DNS 거래 ID, UDP·TCP 스트림 번호를 결과에 남기지 않습니다.
- 거래 ID와 스트림은 캡처 내부 순번 별칭으로만 표시합니다.
- 실제 사내 캡처·프로파일·사용자 정보·장비 설정·로그·보고서를 커밋하지 않습니다.
- 테스트는 런타임 생성 합성 PCAP·PCAPNG·JSON·TSV만 사용합니다.

## 오탐 방지

- 명시적 Success·Accept·ACK·오류 코드는 관찰 사실이며 최종 원인이나 책임 시스템을 뜻하지 않습니다.
- 프로토콜 미관찰과 패킷 부재를 장애로 해석하지 않습니다.
- 성공과 실패가 모두 있으면 혼재로 표시합니다.
- EAPOL Key 메시지 번호 1~4가 모두 있어도 동일 단말의 한 번의 교환이라고 확정하지 않습니다.
- TCP 재전송만으로 RF 장애나 서버 장애를 확정하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널을 판단하지 않습니다.
- RADIUS가 없으면 ClearPass 장애를 확정하지 않습니다.
- 근거가 부족하면 `판단 불가`가 우선입니다.

## 결과와 자원 제한

- 각 이벤트에 상대 시간, 프레임 번호와 `frame.number == N` 근거 필터를 연결합니다.
- 상세 이벤트는 기본 2,000개까지만 보관하고 유형별 전체 집계는 유지합니다.
- GUI는 주요 이벤트 120개까지 표시하고 생략 수를 명시합니다.
- 패킷 수, stdout·stderr 크기와 실행시간에 상한을 둡니다.

## 검증과 릴리즈

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 통합 검증을 수행합니다.

Portable 통합 검증은 Python PATH 없이 EXE를 실행하고 런타임 생성 Ethernet 및 IEEE 802.11 PCAP에서 EAP·RADIUS·DHCP·DNS·ARP·TCP·무선 인증·Association 이벤트를 확인해야 합니다. 결과에 캡처 경로·파일명·IP·MAC·원본 거래 ID·절대 시간이 없고 배포 폴더가 변경되지 않아야 합니다.

`v0.6.0-alpha.1`은 비식별 이벤트 타임라인 프리릴리즈입니다. 단일 단말의 완전한 장애 원인 분석기로 표현하지 않으며 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
