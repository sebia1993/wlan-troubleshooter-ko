# Phase 3 실행 계획 — Python 미설치 PC용 Windows Portable 배포

## 승인 배경

2026년 9월 4일 사용자는 회사에 별도 소프트웨어 승인 절차가 없음을 확인하고, Python과 Wireshark가 설치되지 않은 Windows 11 PC에서 실행할 수 있는 Portable 배포 개발을 승인했습니다.

## 사용자 경험 목표

```text
ZIP 압축 해제
→ WlanTroubleshooterKO.exe 더블클릭
→ PCAP 또는 PCAPNG 선택
→ 로컬 분석 결과 확인
```

사용자 PC에는 Python, Wireshark, Node.js, 관리자 권한, 인터넷 연결이 필요하지 않아야 합니다.

## 구성

- 애플리케이션과 Python 3.13 런타임: PyInstaller `onedir`
- 패킷 해석 엔진: 프로젝트에서 버전을 고정한 공식 Wireshark x64 배포본의 TShark
- 배포 형식: 설치가 필요 없는 Win64 Portable ZIP
- 무결성: 전체 TShark 파일 목록·크기·SHA-256 매니페스트와 ZIP SHA-256
- 소스 제공: 사용한 Wireshark 버전의 공식 소스 아카이브를 릴리즈 자산에 함께 게시

## 빌드 시 네트워크와 실행 시 네트워크의 분리

GitHub Actions 빌드 서버는 버전과 주소가 저장소에 고정된 공식 파일만 내려받을 수 있습니다. 다운로드한 Wireshark MSI는 SHA-256과 Authenticode 서명을 확인합니다. 릴리즈에 포함될 TShark 파일은 다시 개별 SHA-256 매니페스트로 봉인합니다.

최종 Portable 프로그램은 다운로드, 업데이트, 텔레메트리, 외부 API, 소켓, DNS 조회 기능을 포함하지 않습니다. 빌드 서버의 다운로드 기능은 프로그램 런타임에 포함되지 않습니다.

## 고정 버전

- Python: 3.13 계열 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64

버전 변경은 `tests/portable_build/supply-chain.json`, 릴리즈 문서, 테스트를 함께 갱신해야 합니다.

## TShark 최소화

공식 Wireshark MSI를 관리 설치 방식으로 임시 폴더에 풀고 TShark가 있는 설치 디렉터리를 복사합니다. 최종 번들에서는 다음 항목을 제거합니다.

- `tshark.exe` 이외의 실행 파일
- 실시간 캡처용 `dumpcap.exe`
- Wireshark GUI 실행 파일
- extcap 실행 도구와 실시간 캡처 보조 프로그램
- 디버그 심볼과 설치·제거 프로그램

DLL과 프로토콜 데이터는 TShark 저장 캡처 분석 호환성을 위해 유지하되, 애플리케이션은 별도의 빈 설정·플러그인·extcap 디렉터리로 TShark를 실행합니다.

## 공급망 검증 순서

1. 버전이 포함된 공식 Wireshark MSI와 동일 버전 소스 아카이브 다운로드
2. MSI Authenticode 서명 상태와 서명자 확인
3. MSI와 소스 아카이브 SHA-256을 고정값과 비교
4. 관리 설치 방식으로 MSI 추출
5. 추출된 `tshark.exe` Authenticode 서명 재확인
6. 불필요한 실행 파일 제거
7. 남은 모든 TShark 파일의 크기와 SHA-256을 `manifest.json`에 기록
8. 애플리케이션 EXE 자체 점검에서 매니페스트 전체 검증
9. Python 관련 환경변수와 일반 Python 경로를 제거한 상태에서 EXE 실행 확인
10. Portable ZIP과 ZIP SHA-256 생성

## 단계별 구현

### 3A — 공급망 고정

- 공식 파일 다운로드 주소와 버전을 JSON으로 고정
- 첫 CI에서 실제 SHA-256과 서명자를 관찰
- 관찰 결과를 검토한 뒤 SHA-256 고정
- 빌드 입력에 임의 URL·버전·해시를 받지 않음

### 3B — Python 포함 EXE

- PyInstaller `onedir`, `windowed` 빌드
- Python·Tcl·Tk·프로젝트 리소스 포함
- `--self-check-output` 비대화형 자체 점검 추가
- 외부 Python이 없는 PATH에서 EXE 자체 점검

### 3C — TShark 포함

- 공식 MSI 추출
- `tshark.exe` 이외 실행 파일 제거
- GPL 라이선스 원문 포함
- 전체 파일 매니페스트 생성과 런타임 검증
- `tshark -n -v` 및 `tshark -n -G fields` 빌드 검증

### 3D — 릴리즈

- `win64-portable.zip`
- ZIP SHA-256 파일
- 정확한 Wireshark 소스 아카이브와 SHA-256 파일
- 빌드 출처·버전·해시가 포함된 `BUILD_INFO.json`
- Python 미설치 PC용 실행 안내

## 완료 기준

- Windows GitHub Actions에서 Portable 빌드 성공
- 생성된 `WlanTroubleshooterKO.exe`가 Python PATH 없이 자체 점검 성공
- EXE 자체 점검에서 `python_external_required=false` 확인
- TShark 전체 매니페스트 검증 성공
- TShark 버전과 필드 카탈로그 확인 성공
- Portable 폴더에 `dumpcap.exe`, `wireshark.exe`, extcap 실행 파일이 없음
- ZIP 내부에 실제 PCAP, 사내 정보, 빌드 로그, API 키, 토큰이 없음
- `v0.3.0-alpha.1` 프리릴리즈에 Portable ZIP과 대응 소스가 게시됨

## 현재 제품 범위

Phase 3는 실행·배포 기반을 완성하는 단계입니다. EAP·RADIUS·DHCP·DNS·TCP의 장애 원인 판정과 최종 HTML 보고서는 이후 단계에서 구현합니다.
