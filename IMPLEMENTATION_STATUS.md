# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| Phase 3 Win64 Portable 배포 | 구현 완료·Windows 빌드 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스·Portable ZIP 검증 |
| Phase 4A 실제 프로토콜 존재 인벤토리 | 구현 완료·Windows 실분석 통과 | 내장 TShark `-G fields`·`-T fields`, GUI, 취소, 식별자 없는 결과 |
| Phase 4B 접속 단계·근거 Finding | 구현 완료·최종 Windows 검증 진행 | 고정 이벤트 프로파일, 단계 상관분석, 명시적 실패 Finding, 미응답 안전 제한 |
| `v0.5.0-alpha.1` Win64 Portable | 병합 후 게시 예정 | DNS NXDOMAIN·TCP RST 실제 Finding 통합 게이트 포함 |
| EAPOL 4-Way Handshake·로밍·RF 상관분석 | 미착수 | Phase 4C 이후 범위 |
| 최종 오프라인 HTML 보고서 | 미착수 | Finding 안정화 이후 범위 |

## Phase 4B 구현 기능

- 무선 연결, EAPOL, EAP, RADIUS, DHCP, DNS, ARP, TCP 단계별 상태
- Association/Reassociation 거부 상태 코드
- Deauthentication/Disassociation 사유 코드 관찰
- EAP Success·Failure
- RADIUS Access-Accept·Access-Reject
- DHCP ACK·NAK와 거래 ID 기반 묶음
- DNS 정상·오류 응답과 스트림·거래 ID 기반 묶음
- ARP Reply
- TCP 3-way Handshake·RST·재전송
- Finding별 등급, 근거 프레임, 프레임 번호 Display Filter, 다음 점검 항목
- GUI 스크롤 결과와 분석 취소
- 식별정보 없는 비대화형 JSON 스키마 2

## 판정 안전 기준

### 확정

패킷에 다음 명시적 응답이 실제로 기록된 경우에만 해당 이벤트를 `확정`으로 표시합니다.

- Association/Reassociation 비정상 상태 코드
- EAP Failure
- RADIUS Access-Reject
- DHCP NAK
- DNS 비정상 RCODE
- TCP RST

`확정`은 해당 패킷 이벤트의 관찰을 뜻하며 근본 원인 전체의 확정을 뜻하지 않습니다.

### 참고

- Deauthentication/Disassociation
- TCP 재전송 3개 프레임 이상

TCP 재전송만으로 RF 장애를 확정하지 않습니다.

### 판단 불가

DHCP·DNS·TCP 요청 뒤 응답이 보이지 않은 경우에는 다음 조건을 모두 만족할 때만 `판단 불가` Finding을 생성합니다.

- 사전 점검과 TShark 처리 프레임 수 일치
- 같은 거래·스트림의 요청 관찰
- 응답 미관찰
- DHCP 5초·DNS 2초·TCP 3초 이상의 캡처 후속 시간

일부 캡처에서는 미응답 Finding을 생성하지 않습니다.

## 데이터 보호

상관분석에는 코드·거래 ID·내부 스트림을 메모리에서 사용하지만 다음 값은 결과에 기록하지 않습니다.

- IP·MAC·SSID·BSSID
- 사용자명·RADIUS User-Name
- DNS 질의명·호스트명
- DHCP·DNS 거래 ID
- TCP·UDP 스트림 번호
- Raw Payload·쿠키·Authorization·자격 증명
- 캡처 파일명·절대경로
- TShark 표준 오류 원문

## 자동 검증 범위

- 성공·실패·혼합·불완전·미관찰·판단 불가 단계 상태
- 명시적 실패 Finding의 규칙 ID·등급·근거 프레임·Display Filter
- 부분 캡처에서 미응답 Finding 차단
- 내부 거래 ID·스트림·IP·경로 비노출
- 필드 프로파일 0.3.0과 규칙셋 0.2.0 스키마
- 기존 Phase 0~4A 호환성
- 최종 Portable EXE의 실제 DNS NXDOMAIN·TCP RST 분석

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리즈 빌드 서버에서만 수행합니다.

## 아직 지원하지 않는 기능

- EAPOL 4-Way Handshake 메시지 1~4 완성도 판정
- BSSID·채널·RSSI 기반 로밍·RF 상관분석
- 단말·AP·서버별 분석 세션 선택
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태의 별도 사내 PC 검증
- 상용 코드 서명 인증서를 이용한 애플리케이션 EXE 서명

현재 브랜치는 **접속 단계·근거 Finding 프리뷰**이며 완성형 WLAN 근본 원인 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
