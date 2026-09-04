# 구현 상태

기준 문서: `CODEX_IMPLEMENTATION_PLAN.md`, `docs/PHASE_2A_PLAN.md`, `docs/PHASE_2B_PLAN.md`, `docs/PHASE_3_PORTABLE_PLAN.md`, `docs/PHASE_4A_PLAN.md`, `docs/PHASE_4B_PLAN.md`, `docs/PHASE_4C_PLAN.md`.

## 현재 상태

| 구분 | 상태 | 근거 |
|---|---|---|
| Phase 0 저장소·보안 기반 | 구현 완료·자동 검증 통과 | 문서, ADR, 커밋 차단, 감사 도구 |
| Phase 1 최소 앱·안전 경계 | 구현 완료·자동 검증 통과 | Tkinter, 입력 검증, 임시공간, 마스킹, TShark 공급망 정책 |
| Phase 2A 캡처 구조 사전 점검 | 구현 완료·Windows CI 통과 | PCAP·PCAPNG bounded scan, Link Type 분류, 잘림 탐지 |
| Phase 2B 필드·인벤토리 기반 | 구현 완료·Windows CI 통과 | 카탈로그, 프로파일, fields 파서, 프로토콜 정규화, argv 준비 |
| Phase 3 Win64 Portable 배포 | 구현 완료·Windows 빌드 통과 | 내장 Python·Tcl/Tk·TShark, 무결성·라이선스·Portable ZIP 검증 |
| Phase 4A 실제 프로토콜 존재 인벤토리 | 구현 완료·Windows 실분석 통과 | 내장 TShark `-G fields`·`-T fields`, GUI, 취소, 식별자 없는 결과 |
| Phase 4B 접속 단계·근거 Finding | 구현 완료·릴리즈 게시 | 명시적 실패 Finding, 미응답 안전 제한, `v0.5.0-alpha.1` |
| Phase 4C 비식별 이벤트 타임라인 | 구현 완료·최종 Portable 검증 진행 | 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 이벤트 |
| `v0.6.0-alpha.1` Win64 Portable | 게시 대기 | 병합 후 Preview Release 워크플로 실행 |
| 단말별 익명 세션 분리 | 미착수 | 다음 Phase 범위 |
| 최종 오프라인 HTML 보고서 | 미착수 | 세션 분리·상관 정확도 확보 이후 범위 |

## Phase 4C 구현 기능

- 필드 프로파일 버전 `0.4.0`
- 기존 `connection-events` 프로파일을 32개 고정 필드로 확장
- 캡처를 한 번만 해석하고 동일 fields 출력에서 인벤토리·Finding·타임라인 생성
- 802.11 인증·Association·Reassociation·Disassociation·Deauthentication·Retry
- EAPOL Start·Logoff·Key와 확인 가능한 메시지 번호 1~4
- EAP Request·Response·Success·Failure
- RADIUS Access-Request·Challenge·Accept·Reject·Accounting
- DHCP Discover·Offer·Request·ACK·NAK·Decline·Release·Inform
- DNS Query·정상 Response·오류 Response
- ARP Request·Reply
- TCP SYN·SYN/ACK·RST·Retransmission
- TLS ClientHello·ServerHello·Certificate·Finished
- 단계별 성공 결과·실패 결과·혼재·순서 요소·관련 트래픽·미관찰·판단 불가
- 상대 시간, 프레임 번호와 `frame.number == N` 근거 필터
- 원본 거래 ID 대신 EAP·RADIUS·DHCP·DNS·TCP 순번 별칭
- 상세 이벤트 2,000건 보관 상한과 유형별 전체 집계
- GUI 주요 이벤트 120건 표시와 생략 수 안내

## 개인정보·오탐 방지

이벤트 프로파일에는 IP·IPv6·MAC·SSID·BSSID·사용자명·DNS 질의명·호스트명·포트·Payload 필드가 없습니다. 절대 epoch와 원본 거래 ID·스트림 번호도 결과에 기록하지 않습니다.

기본 결과는 여러 단말과 여러 접속을 하나의 세션으로 자동 결합하지 않습니다. 성공과 실패가 모두 관찰되면 혼재로 표시합니다. EAPOL Key 메시지 번호 1~4가 모두 보이더라도 동일 단말의 한 번의 4-Way Handshake라고 확정하지 않습니다. TCP 재전송만으로 RF 또는 서버 장애를 확정하지 않습니다.

## 자동 검증 범위

- 이벤트 프로파일의 개인정보·Payload 필드 부재
- 모든 프로파일 후보 필드의 명시적 화이트리스트 포함 여부
- 802.11·EAPOL·EAP·RADIUS·DHCP·DNS·ARP·TCP·TLS 합성 fields 출력
- 성공·실패 혼재와 선택 필드 누락 처리
- 역순 시간·중복 프레임·잘못된 값 거부
- 상세 이벤트 상한과 전체 집계 유지
- 결과 JSON에서 캡처 경로·파일명·IP·원본 거래 ID·절대 epoch 비노출
- 최종 Portable EXE에서 실제 합성 Ethernet 16프레임 분석
- 최종 Portable EXE에서 실제 합성 IEEE 802.11 8프레임 분석
- 분석 전후 Portable 배포 폴더 무변경

## 고정 공급망

- Python 계열: 3.13 x64
- PyInstaller: 6.22.2
- Wireshark/TShark: 4.6.8 x64
- Wireshark MSI SHA-256: `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`
- 확인된 MSI 서명자: `CN=Wireshark Foundation, O=Wireshark Foundation, L=Davis, S=California, C=US`
- 대응 Wireshark 소스 SHA-256: `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`

사용자 PC에서는 구성요소를 다운로드하거나 설치하지 않습니다. 공식 파일 다운로드와 공급망 검증은 릴리즈 빌드 서버에서만 수행합니다.

## 아직 지원하지 않는 기능

- MAC·SSID를 결과에 노출하지 않는 단말별 익명 세션 분리
- 동일 단말의 완전한 EAP·RADIUS·4-Way Handshake 세션 결합
- 응답 미관찰과 캡처 누락의 자동 확정 구분
- BSSID·채널·RSSI 기반 로밍·RF 상관분석
- ClearPass 정책·Role·VLAN의 구체적 원인 판정
- 최종 오프라인 한국어 HTML 보고서
- 실제 사내 PCAP과 Aruba/ClearPass 장비를 이용한 검증
- 네트워크 어댑터 비활성·Windows 방화벽 아웃바운드 차단 상태의 별도 사내 PC 검증
- 상용 코드 서명 인증서를 이용한 애플리케이션 EXE 서명

현재 브랜치는 **비식별 무선 접속 이벤트 타임라인 프리뷰**이며 완성형 단말별 WLAN 근본 원인 분석기로 표현하지 않습니다. 실제 사내 데이터와 캡처는 공개 저장소에 추가하지 않습니다.
