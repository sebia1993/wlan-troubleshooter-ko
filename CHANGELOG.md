# 변경 기록

## 0.2.0-alpha.1 — 2026-09-03

### 추가

- PCAP 전역 헤더와 패킷 레코드 경계 사전 점검
- PCAPNG Section Header, Interface Description, Enhanced Packet, Simple Packet, 구형 Packet Block 구조 점검
- 인터페이스별 Link Type, Snap Length, 타임스탬프 해상도, 패킷 수 정규화
- Radiotap·IEEE 802.11·Ethernet·PPI·알 수 없는 Link Type의 보수적 분류
- 잘린 패킷과 부분 스캔 경고
- 초급 네트워크 엔지니어용 `확인 가능 / 현재 확인 불가 / 주의` GUI 설명
- 합성 PCAP·PCAPNG 단위 테스트
- 검증 통과 후 첫 소스 프리뷰를 생성하는 GitHub Release 워크플로

### 변경

- 애플리케이션 단계 표시를 `Phase 2A`로 갱신
- 패키지 버전을 `0.2.0a1`로 갱신
- Windows CI 작업명을 Phase 0~2A 범위에 맞게 갱신

### 제한

- 승인된 Portable TShark와 Windows 설치 파일은 포함하지 않음
- EAP·RADIUS·DHCP·DNS·TCP 장애 판정은 아직 지원하지 않음
- Link Type은 프로토콜의 실제 존재나 장애 원인에 대한 증거가 아님
