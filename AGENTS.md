# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 넓히지 않습니다.

## 현재 범위

사용자는 2026년 9월 4일 별도 회사 승인 절차가 없음을 확인하고 Python·Wireshark 미설치 PC용 Windows Portable 배포 개발과 릴리즈를 승인했습니다. 현재 범위는 `docs/PHASE_3_PORTABLE_PLAN.md`입니다.

- Python 3.13과 Tcl/Tk를 PyInstaller `onedir`로 포함합니다.
- 공식 Wireshark 4.6.8 x64 MSI에서 TShark 런타임을 구성합니다.
- 빌드 서버에서만 정확한 공식 URL·SHA-256·Authenticode 서명을 확인합니다.
- 사용자 PC에서는 다운로드·설치·외부 통신 없이 실행해야 합니다.
- 실제 장애 Finding과 상태 머신은 이후 단계로 남깁니다.

## 런타임 금지사항

AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 제품 런타임에 추가하지 않습니다.

Python 런타임 소스에서 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다. GitHub Actions의 빌드 다운로드는 제품 런타임과 분리하며 다운로드 코드를 애플리케이션 패키지에 넣지 않습니다.

## Portable 공급망

- Python 3.13, PyInstaller 6.22.2, Wireshark 4.6.8을 고정합니다.
- 공식 Wireshark MSI와 소스 아카이브의 정확한 URL과 SHA-256만 사용합니다.
- MSI와 추출된 `tshark.exe`의 Authenticode 서명자를 확인합니다.
- 시스템 TShark, 레지스트리, `PATH` 실행 파일로 대체하지 않습니다.
- `tshark.exe` 이외 Wireshark 실행 파일, Npcap, extcap, GUI, 실시간 캡처 도구를 최종 패키지에서 제거합니다.
- TShark 전체 파일의 크기·SHA-256을 `manifest.json`에 기록합니다.
- Python·Tcl·Tk·PyInstaller·Wireshark 라이선스 파일을 Portable ZIP에 포함합니다.
- 정확한 Wireshark 소스 아카이브와 SHA-256을 릴리즈 자산으로 제공합니다.

## 데이터와 판정 안전성

- 입력은 확장자·매직·구조·정규 파일·링크 여부를 함께 검사합니다.
- 원본 캡처는 수정하거나 자동 삭제하지 않습니다.
- 로그와 GUI에 Raw Payload, 자격 증명, 파일명 원문, 전체 IP·MAC, 절대경로, TShark 표준 오류 원문을 남기지 않습니다.
- 실제 사내 캡처·프로파일·사용자 정보·장비 설정·로그·보고서를 커밋하지 않습니다.
- 프로토콜 존재·미관찰을 성공·실패 증거로 사용하지 않습니다.
- 패킷 부재를 장애로 해석하지 않습니다.
- TCP 재전송만으로 RF 장애를 확정하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널·무선 Retry를 판단하지 않습니다.
- RADIUS 패킷이 없으면 ClearPass 장애를 확정하지 않습니다.
- 근거가 부족하면 `판단 불가`가 우선입니다.

## 검증과 릴리즈

변경 후 Windows에서 바이트코드 컴파일, 전체 테스트, 비대화형 자체 점검, 소스 감사, 저장소 감사, Portable 빌드, Python PATH 없는 EXE 자체 점검, TShark 매니페스트·버전·필드 카탈로그 검증을 수행합니다.

`v0.3.0-alpha.1`은 실행 가능한 Win64 Portable 프리릴리즈이지만 실제 WLAN 장애 원인 판정 완성판으로 표현하지 않습니다. 애플리케이션 코드 서명 인증서가 없음을 명시합니다.

외부 소스·테스트·문장·이미지·자산을 복사하지 않습니다. 제3자 구성요소를 변경하면 `THIRD_PARTY_NOTICES.md`, 공급망 고정값, 대응 소스와 라이선스를 먼저 갱신합니다.
