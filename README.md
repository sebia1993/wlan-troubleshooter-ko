# wlan-troubleshooter-ko

Windows 11에서 로컬 PCAP·PCAPNG를 외부로 전송하지 않고 분석하여, 초급 네트워크 엔지니어에게 확인 가능한 범위와 근거를 쉬운 한국어로 안내하는 완전 오프라인 도구입니다.

이 프로젝트는 AI로 원인을 생성하지 않습니다. 실제 패킷에서 관찰된 사실, 확인할 수 없는 영역, 다음 점검 대상을 결정론적으로 분리하는 것을 목표로 합니다.

## 현재 구현 상태

- Phase 0: 저장소·보안 정책·정적 감사
- Phase 1: 최소 GUI·입력 검증·격리 작업공간·Portable TShark 공급망 경계
- Phase 2A: PCAP·PCAPNG 구조·Link Type·Snap Length·잘린 패킷 사전 점검
- Phase 2B: TShark 필드 카탈로그 파서·고정 추출 프로파일·fields 출력 파서·프로토콜 존재 인벤토리 정규화·실행 전 argv 준비

Phase 2B는 승인된 TShark가 없어도 프로파일과 파서 자체를 검증할 수 있습니다. 다만 실제 `-G fields`와 PCAP `-T fields` 실행은 아직 활성화하지 않았습니다.

## v0.2.0-alpha.2 프리뷰

이번 프리뷰에는 다음 기반이 추가됩니다.

- `frame.number`, 선택적인 `frame.interface_id`, `frame.cap_len`, `frame.len`, `frame.protocols`만 사용하는 최소 추출 프로파일
- TShark 버전별 필수·선택 필드 호환성 해석
- Radiotap·802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS·ICMP·QUIC 그룹별 프레임 존재 집계
- 프로토콜 미관찰을 장애로 오해하지 않도록 하는 고정 주의 문구
- 무순서 필드 요청의 승인 순서 정규화와 기존 argv의 엄격한 재검증

이 릴리즈는 Python 3.13이 필요한 소스 프리뷰이며 승인 Portable TShark, Python 런타임, DLL, Windows 설치 프로그램을 포함하지 않습니다.

## 고정 원칙

- AI·LLM·Ollama·MCP·외부 API·런타임 네트워크 기능 없음
- 텔레메트리·자동 업데이트·온라인 조회 없음
- 입력 PCAP 업로드·외부 전송 없음
- 시스템 TShark와 `PATH` 자동 대체 없음
- Raw Payload·쿠키·Authorization·자격 증명 추출 없음
- 실제 사내 PCAP·프로파일·로그·보고서의 공개 저장소 커밋 금지
- 패킷 부재와 프로토콜 미관찰을 장애 증거로 사용하지 않음
- Radiotap 없이 RF 품질을 판정하지 않음

## Phase 2B 결과의 의미

프로토콜 인벤토리는 패킷에 특정 프로토콜 토큰이 관찰됐는지만 집계합니다. 예를 들어 RADIUS가 관찰됐다는 것은 인증 성공을 뜻하지 않고, RADIUS가 관찰되지 않았다는 것도 ClearPass 장애를 뜻하지 않습니다.

실제 접속 성공·실패와 장애 단계 판정은 후속 이벤트 상관분석 단계에서 근거 프레임과 Display Filter를 함께 제공할 때만 수행합니다.

## 개발 검증

```powershell
$env:PYTHONPATH = "src"
py -3.13 -m compileall -q src tests scripts
py -3.13 -m unittest discover -s tests -v
py -3.13 -m wlan_troubleshooter_ko --self-test
py -3.13 scripts/audit_source.py
py -3.13 scripts/audit_repository.py
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/verify_offline.ps1
```

테스트는 임시 디렉터리에 최소 합성 PCAP·PCAPNG·필드 카탈로그·TSV를 생성합니다. 실제 캡처는 저장소에 넣지 않습니다.

## 아직 지원하지 않는 기능

- 승인 TShark를 사용한 실제 프로토콜 추출
- EAP·RADIUS·DHCP·DNS·TCP 이벤트 상관분석과 장애 Finding
- 실시간·원격 캡처
- 장비 로그인·조회·설정 변경
- Payload·파일·자격 증명 추출
- 온라인 OUI·WHOIS·GeoIP 조회
- 독립 실행 Windows EXE

세부 범위는 `docs/PHASE_2B_PLAN.md`, 실제 검증 상태는 `IMPLEMENTATION_STATUS.md`를 확인합니다.
