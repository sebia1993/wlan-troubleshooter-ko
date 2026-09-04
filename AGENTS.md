# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 넓히지 않습니다.

## 현재 범위

사용자는 2026년 9월 4일 남은 개발을 계속하도록 승인했습니다. 현재 범위는 `docs/PHASE_4D_PLAN.md`의 **비식별 프로토콜 거래 시도 요약**입니다.

- Phase 4C 타임라인의 `EAP-N`, `RADIUS-N`, `DHCP-N`, `DNS-N`, `TCP-N` 별칭을 프로토콜 거래 시도별로 묶습니다.
- 요청·중간 이벤트·명시적 성공·실패 응답의 순서와 미관찰 요소를 표시합니다.
- 같은 별칭이 종료 응답 뒤 재사용되면 `A1`, `A2` 시도 번호로 분리합니다.
- 거래 완료·실패는 해당 프로토콜 이벤트 관찰 결과로만 표현합니다.
- 서로 다른 프로토콜 거래를 동일 단말 접속으로 자동 연결하지 않습니다.
- 단말별 익명 세션, 로밍·RF 근본 원인과 HTML 보고서는 다음 단계로 남깁니다.
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

## Phase 4D 입력과 개인정보 경계

거래 시도 분석기는 Phase 4C가 만든 다음 값만 사용합니다.

```text
correlation_alias
frame_number
relative_time_ms
event_type
```

다음 값은 GUI·기본 JSON·로그와 거래 시도 모델에 기록하지 않습니다.

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
- 원본 캡처 파일명·절대경로
- TShark 표준 오류 원문

거래 별칭은 캡처 내부에서만 사용하는 순번이며 단말이나 사용자의 신원을 의미하지 않습니다.

## 판정 안전성

- EAP 완료는 Request → Response → Success가 순서대로 관찰된 경우만 표시합니다.
- RADIUS 완료는 Access-Request → Access-Accept가 관찰된 경우만 표시합니다.
- DHCP 완료는 Discover → Offer → Request → ACK가 관찰된 경우만 표시합니다.
- DNS 완료는 Query → 정상 Response가 관찰된 경우만 표시합니다.
- TCP는 최종 ACK를 구분하지 않으므로 SYN → SYN/ACK가 있어도 3-Way Handshake 완료로 표시하지 않습니다.
- Failure·Reject·NAK·DNS 오류·RST는 해당 실패 이벤트 관찰로 표시하되 근본 원인을 확정하지 않습니다.
- 모든 거래 시도는 `root_cause_confirmed=false`, `device_session_confirmed=false`를 유지합니다.
- 거래 미완료를 서버·방화벽·ClearPass 장애로 확정하지 않습니다.
- 프로토콜별 거래를 서로 연결해 동일 단말 접속으로 단정하지 않습니다.
- 성공과 실패가 함께 있으면 혼재로 표시합니다.
- TCP 재전송만으로 RF 장애나 서버 장애를 확정하지 않습니다.
- 패킷 부재와 프로토콜 미관찰을 장애로 해석하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널을 판단하지 않습니다.
- 근거가 부족하면 `판단 불가`가 우선입니다.

## 결과와 자원 제한

- 시도별 첫·마지막 프레임, 상대 지속시간, 관찰·미관찰 이벤트와 `frame.number` 근거 필터를 제공합니다.
- 거래 별칭은 최대 50,000개까지 허용합니다.
- 한 거래 시도의 이벤트는 최대 200,000개까지 허용합니다.
- 거래 시도별 근거 프레임은 최대 64개를 표시하고 초과 수를 기록합니다.
- 타임라인 이벤트가 생략되거나 캡처가 일부이면 거래 보고서를 일부 결과로 표시합니다.
- 별칭·프로토콜·프레임·시간·개수가 규칙과 다르면 실패-폐쇄 처리합니다.

## 검증과 릴리즈

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 자체 점검, 소스 감사, 저장소 감사, Portable 빌드와 실제 내장 TShark 통합 검증을 수행합니다.

Portable 검증은 Python PATH 없이 최종 EXE를 실행하고 다음 거래를 실제 패킷에서 확인해야 합니다.

- PPP EAP Request → Response → Success 완료
- RADIUS Access-Request → Access-Accept 완료
- DHCP Discover → Offer → Request → ACK 완료
- DNS Query → 정상 Response 완료
- DNS 오류 Response 실패 결과
- TCP SYN → SYN/ACK 성공 방향 응답이지만 완료로 과장하지 않음
- TCP RST 실패 결과

모든 거래의 근본 원인·단말 세션 확정 값이 `false`이고, 결과에 경로·파일명·IP·MAC·원본 ID·절대 시간이 없으며 배포 폴더가 변경되지 않아야 합니다.

`v0.7.0-alpha.1`은 비식별 프로토콜 거래 시도 프리릴리즈입니다. 단일 단말의 완전한 WLAN 근본 원인 분석기로 표현하지 않으며 애플리케이션 상용 코드 서명이 없음을 명시합니다.

외부 프로젝트의 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소가 바뀌면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
