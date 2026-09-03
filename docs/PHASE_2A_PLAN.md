# Phase 2A 실행 계획 — 캡처 구조 사전 점검

## 승인 배경

2026년 9월 3일 사용자가 Phase 0·1 이후 개발을 계속하고 릴리즈도 갱신하도록 명시적으로 요청했습니다. 이 문서는 `CODEX_IMPLEMENTATION_PLAN.md`의 Phase 2를 한 번에 구현하지 않고 첫 번째 안전 단위인 Phase 2A 범위를 고정합니다.

## 목표

승인된 Portable TShark가 아직 제공되지 않은 상태에서도 PCAP·PCAPNG 컨테이너 구조를 로컬에서 읽어 다음 정보를 초급 네트워크 엔지니어에게 제공합니다.

- 캡처 형식과 바이트 순서
- 인터페이스 수와 Link Type
- PCAP 전역 Snap Length와 PCAPNG 인터페이스별 Snap Length
- 검사한 패킷 레코드 수
- 캡처 길이가 원본 길이보다 짧은 패킷의 관찰 수
- Radiotap 또는 IEEE 802.11 Link Type 존재 여부
- 현재 형식에서 확인 가능한 항목과 확인할 수 없는 항목

## 허용 범위

- Python 표준 라이브러리만 사용하는 PCAP·PCAPNG bounded scan
- PCAP Global Header와 Packet Record Header 해석
- PCAPNG Section Header, Interface Description, Enhanced Packet, Simple Packet, 구형 Packet Block 해석
- PCAPNG 블록 시작·종료 길이 검증
- Link Type 기반의 보수적인 캡처 유형 추정
- GUI에 파일명·절대경로·패킷 원문 없이 사전 점검 결과 표시
- 합성 바이트만 사용하는 단위 테스트
- 검증 통과 후 소스 프리뷰 GitHub Release를 생성하는 개발 인프라 워크플로

## 금지 범위

- TShark를 통한 실제 프로토콜 필드 추출
- EAP, RADIUS, DHCP, DNS, ARP, TCP, TLS 이벤트 생성
- 장애 원인 판정과 Finding 생성
- Raw Payload, 자격 증명, 파일 추출
- AI, 외부 API, 온라인 조회, 실시간·원격 캡처
- Radiotap이 없는데 RSSI·SNR·채널·무선 Retry를 판단하는 동작
- Link Type만으로 특정 프로토콜이 실제 존재한다고 단정하는 동작
- 릴리즈 자산에 Python, TShark 또는 외부 실행 파일을 자동 다운로드해 포함하는 동작

## 판정 안전성

Phase 2A 결과는 **캡처 형식상 분석 가능성**만 의미합니다. 예를 들어 Ethernet Link Type은 DHCP·DNS·TCP를 담을 수 있음을 뜻할 뿐 해당 프로토콜의 실제 존재를 보증하지 않습니다. 실제 프로토콜 존재 여부는 승인된 Portable TShark가 제공된 뒤 별도 단계에서 확인합니다.

PPI Link Type은 내부 캡슐화를 추가로 확인하기 전까지 IEEE 802.11·RF·IP 캡처로 분류하지 않습니다.

## 안전 제한

- 블록 또는 레코드 개수에 상한을 둡니다.
- 비정상적으로 큰 레코드와 블록을 거부합니다.
- 선언 길이가 파일 경계를 넘으면 실패합니다.
- PCAPNG 블록의 앞·뒤 길이가 다르면 실패합니다.
- 사용자 취소를 매 레코드·블록 경계에서 확인합니다.
- 점검 전후 캡처의 크기·형식·SHA-256이 달라지면 실패합니다.
- 오류 메시지에는 캡처 경로와 패킷 원문을 포함하지 않습니다.

## 완료 기준

- Ethernet, IEEE 802.11, Radiotap, PPI, 알 수 없는 Link Type을 보수적으로 구분합니다.
- Radiotap이 없으면 RF 분석을 `현재 확인 불가`로 표시합니다.
- 802.11 Link Type이 없으면 Association·Deauthentication·로밍을 `현재 확인 불가`로 표시합니다.
- 잘린 패킷이 관찰되면 상위 프로토콜 해석 한계를 표시합니다.
- 제한에 도달한 스캔을 완료된 전체 검사로 표현하지 않습니다.
- 동일한 합성 입력은 동일한 정규화 결과를 생성합니다.
- 기존 Phase 0·1 테스트와 새 Phase 2A 테스트가 Windows CI에서 모두 통과해야 합니다.
- `v0.2.0-alpha.1`은 Python 3.13이 필요한 소스 프리뷰로만 게시하며 실제 장애 분석 완성판으로 표시하지 않습니다.

## 다음 단계

Phase 2A가 병합돼도 실제 장애 분석이 완료된 것으로 표시하지 않습니다. 다음 단계는 승인된 Portable TShark 번들이 준비되었을 때 수행할 **Phase 2B 프로토콜 인벤토리와 필드 추출**입니다.
