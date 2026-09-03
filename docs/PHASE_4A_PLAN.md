# Phase 4A 실행 계획 — 내장 TShark 프로토콜 존재 인벤토리

## 승인 배경

2026년 9월 4일 사용자는 Python·Wireshark 미설치 PC용 Portable 배포 이후 실제 패킷 분석 개발을 계속하도록 지시했습니다. Phase 4A는 내장 TShark를 저장된 PCAP·PCAPNG에 연결하되, 아직 장애 원인을 추정하지 않고 **어떤 프로토콜이 어느 프레임에서 관찰됐는지**만 안전하게 보여 줍니다.

## 사용자 흐름

```text
Portable ZIP 압축 해제
→ WlanTroubleshooterKO.exe 실행
→ PCAP 또는 PCAPNG 선택
→ 구조 사전 점검
→ 내장 TShark 필드 호환성 검사
→ 프로토콜 존재 인벤토리
→ 한국어 결과 확인
```

Python, Wireshark, 관리자 권한과 인터넷 연결은 필요하지 않습니다.

## 구현 범위

- 고정 명령 `tshark.exe -n -G fields` 실제 실행
- 현재 TShark의 필수·선택 필드 호환성 검사
- 검증된 로컬 캡처에 대한 고정 `-T fields` 실제 실행
- 프레임 번호, 선택적 인터페이스 ID, 캡처 길이, 원본 길이, 프로토콜 계층만 추출
- Radiotap, IEEE 802.11, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS, ICMP, QUIC 그룹 집계
- 그룹별 관찰 프레임 수, 첫 프레임, 마지막 프레임 표시
- 잘린 프레임과 일부 분석 상태 표시
- GUI 스크롤 결과, 진행 상태와 분석 취소
- 비대화형 Portable 통합 검증용 로컬 JSON 출력

## 구현하지 않는 범위

- IP·MAC·SSID·BSSID·호스트명·DNS 질의명·사용자명·RADIUS User-Name 출력
- Raw Payload, 쿠키, Authorization, 인증정보와 파일 추출
- EAP·RADIUS·DHCP·DNS·TCP 성공·실패 상관분석
- 장애 원인 Finding과 자동 조치
- 자유 입력 Display Filter, 필드와 TShark 옵션
- 실시간·원격 캡처
- 시스템 설치 TShark나 PATH 실행 파일 사용
- 외부 API, AI, LLM, 텔레메트리와 자동 업데이트

## TShark 실행 경계

모든 자식 프로세스 생성은 검토된 단일 함수에서만 수행합니다.

- `shell=False`
- 저장 캡처 경로는 사전 검증된 로컬 절대경로만 허용
- `-n` 이름 해석 비활성화
- `-2`, `-r`, `-c`, 고정 `-T fields`, 고정 `-E`, 고정 `-Y`, 승인 `-e`만 허용
- `-i`, rpcap, TCP@호스트, extcap, Lua와 사용자 옵션 금지
- Windows 콘솔 창을 생성하지 않음
- stdin 비활성화
- stdout·stderr를 동시에 읽어 파이프 교착 방지
- stdout 64MiB, stderr 1MiB 기본 상한
- stderr 내용은 저장·표시하지 않고 크기만 계산
- 180초 기본 제한시간과 사용자 취소
- 비정상 종료, UTF-8 오류, NUL, 과대 출력 시 안전한 실패

## 파일과 격리 검증

- TShark 번들의 매니페스트·파일 크기·SHA-256을 실행 전후 확인
- 캡처 파일의 형식·크기·SHA-256을 TShark 실행 전후 확인
- 호출마다 새 임시 작업공간 생성
- config, plugin, extcap, data, temp 디렉터리를 빈 상태로 제공
- 사용자 Wireshark 설정, 플러그인, SSLKEYLOGFILE과 일반 PATH를 전달하지 않음
- 종료 후 격리 디렉터리에 파일이 남으면 실패
- 정상·실패·취소 후 임시 작업공간 삭제

## 결과 의미

- `관찰됨`은 해당 프로토콜 토큰이 프레임에 있었다는 뜻입니다.
- `관찰되지 않음`은 해당 캡처에서 보이지 않았다는 뜻입니다.
- 어느 쪽도 접속 성공·실패 또는 장애 원인의 증거가 아닙니다.
- 캡처 위치, 시작 시점, 방향, Snap Length와 패킷 상한 때문에 누락될 수 있습니다.
- Phase 2A 프레임 수와 TShark 처리 프레임 수가 같을 때만 전체 인벤토리로 표시합니다.

## 검증 기준

- 합성 TShark 프로세스로 시간·취소·출력 상한·비정상 종료를 검증
- stderr의 사내 경로·비밀 문자열이 사용자 오류에 나타나지 않음을 검증
- 결과 JSON에 캡처 경로·파일명·패킷 IP가 포함되지 않음을 검증
- 최종 Portable ZIP을 Python PATH 없이 실행
- 실행 중 생성한 실제 ARP·DNS PCAP을 내장 TShark로 분석
- ARP와 DNS 그룹이 각각 관찰되는지 확인
- 분석 전후 Portable 폴더 파일 목록이 바뀌지 않는지 확인
- Windows 전체 테스트·소스 감사·저장소 감사 통과

## 다음 단계

Phase 4B에서는 식별정보를 기본 출력에 노출하지 않는 범위에서 EAPOL/EAP/RADIUS/DHCP/DNS/ARP/TCP 이벤트 스키마와 근거 프레임을 구현합니다. 장애 Finding은 캡처 한계와 상관분석 테스트가 확보된 후 별도 단계에서 추가합니다.
