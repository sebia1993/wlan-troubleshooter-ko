# v0.3.0-alpha.1 — Python 미설치 PC용 Win64 Portable 프리뷰

이 릴리즈부터 Windows 사용자는 Python과 Wireshark를 별도로 설치하지 않고 프로그램을 실행할 수 있습니다.

## 사용 방법

1. `WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip`을 받습니다.
2. 같은 이름의 `.sha256` 파일과 ZIP의 SHA-256을 비교합니다.
3. ZIP을 로컬 폴더에 완전히 압축 해제합니다.
4. `WlanTroubleshooterKO.exe`를 실행합니다.
5. PCAP 또는 PCAPNG 파일을 선택합니다.

관리자 권한과 인터넷 연결은 필요하지 않습니다. ZIP 내부에서 EXE를 직접 실행하지 마십시오.

## 포함된 런타임

- CPython 3.13 x64
- Tcl/Tk GUI 런타임
- PyInstaller 6.22.2 부트로더
- Wireshark/TShark 4.6.8 x64

TShark는 공식 MSI에서 추출했으며 MSI SHA-256과 Wireshark Foundation Authenticode 서명을 빌드 시 확인합니다. 최종 TShark 파일은 전체 SHA-256 매니페스트로 다시 검증합니다.

## 데이터 보호

- AI·LLM·Ollama·MCP·외부 API 없음
- 입력 PCAP 업로드·외부 전송 없음
- 런타임 HTTP·소켓·DNS 조회 없음
- 텔레메트리·오류 자동 전송·자동 업데이트 없음
- 실시간·원격 캡처 없음
- 온라인 OUI·WHOIS·GeoIP 조회 없음
- Raw Payload·쿠키·Authorization·자격 증명 추출 없음

## 검증한 사항

- Python 관련 환경변수와 일반 Python PATH를 제거한 상태에서 EXE 자체 점검
- 내장 Python·Tkinter 리소스 로딩
- 내장 TShark 전체 매니페스트 검증
- 내장 TShark 버전 확인과 필드 카탈로그 생성
- Portable 패키지에 허용된 실행 파일 두 개만 존재하는지 확인
- Windows 전체 단위 테스트와 오프라인 소스·저장소 감사

## 현재 기능 제한

이 릴리즈는 캡처 사전 점검 프리뷰입니다.

- PCAP·PCAPNG 구조, Link Type, Snap Length, 잘린 패킷은 확인할 수 있습니다.
- 실제 EAP·RADIUS·DHCP·DNS·TCP 성공·실패 판정은 아직 제공하지 않습니다.
- 프로토콜 존재는 접속 성공 또는 장애를 뜻하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널·무선 Retry를 판단하지 않습니다.
- 애플리케이션 EXE 자체의 상용 코드 서명 인증서가 없어 Windows에서 `알 수 없는 게시자`로 표시될 수 있습니다.

## 릴리즈 자산

- `WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip`
- `WlanTroubleshooterKO-v0.3.0-alpha.1-win64-portable.zip.sha256`
- `wireshark-4.6.8.tar.xz`
- `wireshark-4.6.8.tar.xz.sha256`
- `supply-chain-observed.json`

Wireshark 소스 아카이브는 동봉 TShark 4.6.8 바이너리의 대응 소스입니다.
