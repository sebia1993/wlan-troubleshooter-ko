# v0.2.0-alpha.2 — Phase 2B 프로토콜 인벤토리 기반 프리뷰

이 프리릴리즈는 실제 패킷 장애 판정 전에 필요한 **TShark 필드 호환성·출력 파싱·프로토콜 존재 집계 기반**을 추가합니다.

## 새 기능

- `tshark -G fields` 형식의 프로토콜·필드 등록 정보 파서
- 필수 필드가 없는 TShark 버전을 차단하는 호환성 검사
- 선택 필드 누락 시 나머지 인벤토리를 유지하는 보수적 처리
- 식별자 없이 프레임 번호·길이·프로토콜 계층만 사용하는 추출 프로파일
- Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP, QUIC 관찰 프레임 집계
- 잘린 프레임과 일부 검사 상태 경고
- 초급자가 `프로토콜 미관찰 = 장애`로 오해하지 않도록 하는 한국어 설명

## 데이터 보호

- AI·LLM·Ollama·MCP·외부 API를 사용하지 않습니다.
- IP·MAC·SSID·사용자명·서버 주소·Payload를 Phase 2B 프로파일에 포함하지 않습니다.
- 외부 통신·텔레메트리·자동 업데이트를 추가하지 않습니다.
- 테스트는 실제 PCAP이 아니라 실행 중 생성한 합성 데이터만 사용합니다.

## 중요한 제한사항

- 승인된 Portable TShark가 포함되지 않습니다.
- 실제 `-G fields`와 PCAP `-T fields` 자식 프로세스 실행은 아직 활성화하지 않았습니다.
- EAP·RADIUS·DHCP·DNS·TCP 장애 단계 판정은 지원하지 않습니다.
- 프로토콜이 관찰됐다는 사실은 성공이나 실패를 의미하지 않습니다.
- Windows 설치 프로그램이나 독립 실행 EXE가 아닌 Python 3.13 소스 프리뷰입니다.

## 실행 조건

- Windows 11
- Python 3.13

```powershell
$env:PYTHONPATH = "src"
py -3.13 -m wlan_troubleshooter_ko
```

## 다음 단계

회사에서 승인한 `tshark.exe`, 필수 DLL, 버전·SHA-256 매니페스트가 제공되면 실제 필드 호환성 및 프로토콜 인벤토리 통합 검증을 진행합니다. 그 전에도 합성 fields 출력으로 EAP·RADIUS·DHCP·DNS·TCP 이벤트 스키마를 계속 개발할 수 있습니다.
