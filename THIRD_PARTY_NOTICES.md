# 제3자 구성요소 고지

이 문서는 `WlanTroubleshooterKO` Win64 Portable 배포물에 포함되거나 빌드에 사용되는 주요 제3자 구성요소를 설명합니다. 각 라이선스 원문이 우선하며 이 문서는 법률 자문이 아닙니다.

## CPython 3.13 x64

- 용도: 애플리케이션 실행 런타임
- 배포 방식: PyInstaller `onedir` 패키지 내부
- 외부 설치: 필요 없음
- 라이선스: Python Software Foundation License Version 2 및 공식 Python 배포본에 포함된 관련 제3자 고지
- 라이선스 파일: `licenses/PYTHON-LICENSE.txt`
- 정확한 패치 버전: 각 패키지의 `BUILD_INFO.json`
- 수정 여부: 프로젝트에서 CPython 소스를 수정하지 않음

## Tcl/Tk 8.6 계열

- 용도: `tkinter/ttk` Windows GUI
- 배포 방식: 공식 CPython 런타임과 PyInstaller가 포함한 Tcl/Tk 데이터
- 라이선스 파일: `licenses/TCL-LICENSE.txt`, `licenses/TK-LICENSE.txt`
- 수정 여부: 프로젝트에서 Tcl/Tk 소스를 수정하지 않음

## PyInstaller 6.22.2

- 용도: Python 애플리케이션과 런타임을 Windows `onedir` 프로그램으로 묶는 빌드 도구와 부트로더
- 라이선스: PyInstaller가 제공하는 GPL 2.0 예외 및 일부 파일의 Apache License 2.0 조건
- 라이선스 파일: `licenses/PYINSTALLER-COPYING.txt`
- 수정 여부: 프로젝트에서 PyInstaller 소스와 부트로더를 수정하지 않음
- 참고: PyInstaller의 빌드 예외는 생성된 실행 파일을 프로젝트 라이선스로 배포하는 것을 허용하며 정확한 조건은 동봉 라이선스 원문을 따름

## Wireshark/TShark 4.6.8 x64

- 용도: 저장된 PCAP·PCAPNG 프로토콜 해석
- 공급 출처: Wireshark Foundation 공식 `Wireshark-4.6.8-x64.msi`
- MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `Wireshark Foundation`
- 라이선스: Wireshark 배포본의 `COPYING`과 개별 파일 고지에 따름. 대부분의 Wireshark 코드는 GNU GPL version 2 or later 조건임
- 라이선스 파일: `vendor/wireshark/COPYING`
- 대응 소스: 릴리즈 자산 `wireshark-4.6.8.tar.xz`
- 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`
- 수정 여부: Wireshark/TShark 소스를 수정하거나 다시 컴파일하지 않음. 공식 MSI를 관리 설치 방식으로 풀고 저장 캡처 해석에 불필요한 GUI·실시간 캡처 실행 파일과 extcap 도구를 배포 대상에서 제외함

Portable 패키지의 TShark 전체 파일 목록·크기·SHA-256은 `vendor/wireshark/manifest.json`에 기록됩니다. 매니페스트와 다른 파일이 있으면 프로그램은 TShark를 신뢰하지 않습니다.

## Microsoft Visual C++ Runtime 및 Python 배포본의 종속 구성요소

공식 CPython Windows 배포본과 PyInstaller 결과에는 Microsoft Visual C++ Runtime과 Python이 사용하는 제3자 라이브러리가 포함될 수 있습니다. 정확한 파일은 패키지별 `_internal/` 디렉터리와 `BUILD_INFO.json`을 기준으로 하며, 관련 재배포 조건은 공식 Python 배포본의 `LICENSE.txt` 및 각 파일의 권리자 조건을 따릅니다.

## 참고한 공개 프로젝트

다음 프로젝트는 일반적인 기능 범위와 UX를 비교하는 데만 참고했습니다. 소스·테스트·문장·이미지·아이콘·샘플 PCAP을 복사하지 않았습니다.

- `bx33661/Wireshark-MCP`
- `NotYuSheng/TracePcap`
- `kspviswa/pktai`
- `srixivas/PcapXray`
- `privatefound/AI-PCAP-Analyzer`

## 변경 규칙

제3자 코드, 바이너리, 폰트, 이미지, 아이콘, 테스트 데이터 또는 공개 PCAP을 추가하거나 버전을 변경하기 전에 이름, 버전, 공급 출처, 라이선스, 포함 파일, 수정 여부와 재배포 의무를 이 문서와 빌드 검증에 먼저 반영합니다.
