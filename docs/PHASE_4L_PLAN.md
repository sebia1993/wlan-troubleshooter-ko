# Phase 4L — 캡처 상대 시간과 거래 경계

## 현재 구현과 목적

저장 PCAP·PCAPNG에서 내장 TShark의 고정 최소 프로파일 `capture-time-boundaries`를 실행합니다. 필드는 `frame.number`, `frame.time_epoch` 두 개뿐입니다. 원본 epoch는 분석 중 일시적으로 처리하고 공개 결과에는 첫 분석 프레임 기준 상대 밀리초와 근거 프레임만 남깁니다.

이 단계는 새 PCAPNG 이진 시간 파서를 구현한 것이 아닙니다. PCAP·PCAPNG 디코딩은 내장 TShark가 담당합니다. 타임스탬프 없는 프레임과 서로 다른 인터페이스 시계의 신뢰성은 후속 검증 범위입니다.

## 분석 결과

- 처리 프레임 수, 예상 프레임 수, 전체·일부 처리 구분
- 첫→마지막 상대 시간, 최소·최대 상대 시간, 관찰 span
- 표시 반올림 전의 시간 역행 탐지와 처음 64개 근거 프레임
- EAP·RADIUS·DHCP·DNS·TCP 거래별 시작 거리, 종료 뒤 관찰 창, 양 끝 프레임 상대 시간차
- `spans-analysis-window`, `at-analysis-start`, `at-analysis-end`, `near-both-boundaries`, `near-analysis-start`, `near-analysis-end`, `analysis-window-interior`, `timestamp-order-risk`
- 기본 경계 표시 기준 1,000ms. 장애 판정 또는 응답 타임아웃 기준이 아닙니다.
- GUI `[13. 캡처 상대 시간과 거래 경계]`, 최상위 JSON 스키마 2 유지

## 판정·개인정보 경계

다음 값은 항상 false입니다.

```
absolute_timestamps_serialized
capture_start_proven
capture_end_proven
incident_window_fully_covered
response_wait_sufficiency_assessed
response_absence_confirmed
capture_loss_excluded
root_cause_confirmed
```

긴 관찰 창으로 응답 대기 충분성이나 실제 서버 미응답을 확정하지 않습니다. 거래가 분석 창 중간에 있어도 장애 전체를 캡처했다고 확정하지 않습니다. 패킷 상한으로 일부 처리한 창의 끝을 전체 캡처 끝으로 표현하지 않습니다.

원본 MAC·IP·BSSID·SSID·사용자명·DNS 질의명·키 정보·절대 epoch·파일명·경로를 공개 결과에 추가하지 않습니다. 제품에 AI·외부 통신·실시간 캡처·자동 업데이트를 추가하지 않습니다.

## 시간 역행 안정성 수정

허용 소수부 전체를 비교해 나노초 이하의 순서 역행도 표시 반올림 전에 탐지합니다. 공개 밀리초는 기존 이벤트·거래 계약과 호환됩니다.

거래의 이벤트 최대−최소 시간과 양 끝 프레임 시간차를 구분합니다. 역행 거래의 검증에는 그 거래의 근거 프레임만 사용하며, 근거가 생략되면 정확한 검증 완료로 표현하지 않습니다. 다른 거래의 중간 프레임으로 빈 근거를 채우지 않습니다.

## 검증 기준

- 단위·서비스·GUI·프로파일 회귀 테스트와 정적 감사
- 같은 입력·버전의 결정론적 직렬화
- 같은 캡처 경로·형식·크기·SHA-256과 TShark 매니페스트 재검증
- Portable 합성 PCAPNG 4프레임: ARP(+0ms), DNS(+250ms), ARP(+1500ms), DNS(+3000ms)
- DNS 거래의 종료 뒤 관찰 창 2750ms와 0ms 확인
- 외부 Python·Wireshark를 사용할 수 없는 PATH에서 실제 EXE 분석
- 합성 원본 주소·절대 epoch·PCAPNG 주석·경로의 최종 JSON 비노출

## 완료와 미완료의 구분

`57ef989`의 Windows CI 및 Portable 검증은 성공했습니다. Windows CI는 411개 실행, 410개 통과, 플랫폼 제약 1개 건너뜀입니다. 문서 갱신 뒤 최신 HEAD를 다시 검증하고 병합합니다. 릴리스 게시 성공은 별도 Actions 결과와 실제 자산으로 확인합니다.

실제 사내 캡처, Windows 11 사용자 데스크톱·EDR·아웃바운드 차단, 모든 시간 역행 입력의 전체 파이프라인 통과는 아직 검증하지 않았습니다.
