# v0.2.0-alpha.1 — Phase 2A 캡처 사전 점검 프리뷰

이 릴리즈는 초급 네트워크 엔지니어가 PCAP·PCAPNG 파일을 본격 분석하기 전에 **어떤 종류의 캡처인지, 무엇을 확인할 수 있고 무엇을 확인할 수 없는지** 판단하도록 돕는 첫 소스 프리뷰입니다.

## 새 기능

- PCAP·PCAPNG 컨테이너 구조의 로컬 읽기 전용 점검
- PCAP 바이트 순서, 타임스탬프 정밀도, Link Type, Snap Length 확인
- PCAPNG 다중 Section·다중 인터페이스와 인터페이스별 Link Type 확인
- 캡처 길이가 원본 길이보다 짧은 패킷 관찰
- Radiotap, IEEE 802.11, Ethernet, PPI, 알 수 없는 Link Type의 보수적 분류
- `형식상 확인 가능`, `현재 확인 불가`, `주의`를 분리한 한국어 GUI
- 파일명·절대경로·패킷 원문을 화면에 노출하지 않는 결과 표시

## 데이터 보호

- AI, LLM, Ollama, MCP, 외부 API를 사용하지 않습니다.
- 프로그램 런타임은 외부 통신, 텔레메트리, 자동 업데이트를 포함하지 않습니다.
- PCAP을 업로드하거나 외부로 전송하지 않습니다.
- 테스트에는 실제 캡처가 아닌 실행 중 생성한 최소 합성 바이트만 사용합니다.

## 중요한 제한사항

이 릴리즈는 실제 무선 장애 원인을 판정하는 완성판이 아닙니다.

- 승인된 Portable TShark가 포함되지 않습니다.
- EAP·RADIUS·DHCP·DNS·TCP·TLS 필드 추출과 장애 판정은 아직 지원하지 않습니다.
- Radiotap이 없으면 RSSI·SNR·채널·무선 Retry를 판단하지 않습니다.
- Link Type만으로 특정 프로토콜이 실제로 포함됐다고 단정하지 않습니다.
- Windows 설치 프로그램이나 독립 실행 EXE가 아닌 Python 3.13 소스 프리뷰입니다.

## 실행 조건

- Windows 11
- Python 3.13

릴리즈 자산의 `START_PREVIEW.ps1`을 실행하거나 다음 명령을 사용할 수 있습니다.

```powershell
$env:PYTHONPATH = "src"
py -3.13 -m wlan_troubleshooter_ko
```

## 다음 단계

회사에서 승인한 Portable TShark 실행 파일, 필수 DLL, 버전·SHA-256 매니페스트가 준비되면 Phase 2B에서 실제 프로토콜 인벤토리와 필드 추출을 구현합니다.
