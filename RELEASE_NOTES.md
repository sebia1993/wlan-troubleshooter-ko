# v0.14.0-alpha.1 — 캡처 상대 시간·거래 경계 프리뷰

PCAP·PCAPNG의 첫 분석 프레임 기준 상대 시간과 거래별 관찰 창을 추가했습니다. 내장 TShark를 사용하며 Python과 Wireshark를 대상 PC에 따로 설치하지 않습니다.

## 사용

`WlanTroubleshooterKO-v0.14.0-alpha.1-win64-portable.zip`과 같은 이름의 `.sha256` 파일을 비교한 뒤 로컬 폴더에 완전히 압축 해제하고 `WlanTroubleshooterKO.exe`를 실행합니다. ZIP 안에서 바로 실행하지 않습니다. 제품 분석에는 AI·인터넷·외부 API·업로드·텔레메트리·자동 업데이트를 사용하지 않습니다.

## 새 기능

- GUI `[13. 캡처 상대 시간과 거래 경계]`
- 첫→마지막 상대 시간, 최소·최대·관찰 span
- 패킷 상한을 반영한 전체·일부 분석 구분
- 표시 반올림 전 시간 역행 탐지, 제한된 근거 프레임과 생략 수
- EAP·RADIUS·DHCP·DNS·TCP 거래별 시작 거리·종료 뒤 관찰 시간
- 시간 역행 거래의 이벤트 시간 범위와 양 끝 프레임 시간차를 구분
- 승인된 두 필드·필터·행 상한과 캡처·내장 TShark 지문 재검증
- 기존 Finding·타임라인·거래·DEVICE-N·여정·EAPOL·PCAPNG 통계 유지
- 최상위 JSON 스키마 2 유지

## 쉽게 읽는 예

분석 창이 3000ms이고 DNS 요청이 +250ms에 있으면 요청 뒤 2750ms를 더 관찰했다는 뜻입니다. 마지막 +3000ms에 있는 DNS 요청은 그 뒤 관찰 시간이 0ms입니다. 어느 경우도 DNS 서버 장애나 실제 미응답을 자동 확정하지 않습니다.

기본 1000ms 경계 표시는 요청이 분석 창의 시작·끝에 가까운지 보여줄 뿐 프로토콜 응답 타임아웃이 아닙니다. 일부 프레임만 처리했으면 분석 창 끝을 파일 전체 끝으로 해석하지 않습니다.

## 보호 경계

원본 주소·사용자명·DNS 질의명·절대 epoch·캡처 파일명·경로·키 원문을 결과에 추가하지 않습니다. `capture_start_proven`, `capture_end_proven`, `incident_window_fully_covered`, `response_wait_sufficiency_assessed`, `response_absence_confirmed`, `capture_loss_excluded`, `root_cause_confirmed`는 항상 false입니다.

## 검증

Windows CI와 Python·Wireshark 외부 설치본을 사용할 수 없도록 PATH를 제한한 Portable EXE 검증을 사용합니다. 합성 PCAPNG의 두 DNS 요청(+250ms, +3000ms)에서 관찰 창과 비식별 결과를 확인합니다. 실제 사내 캡처는 저장소나 Actions에 업로드하지 않습니다.

## 알려진 제한

- 시간 역행 모듈의 회귀 테스트 통과가 모든 역행 캡처의 전체 분석 성공을 보장하지 않습니다.
- 타임스탬프 없는 프레임·다중 인터페이스 시계는 추가 검증이 필요합니다.
- 프레임별 DEVICE/AP 연결·로밍, RSSI·채널·데이터율 RF 관찰은 아직 구현되지 않았습니다.
- Aruba·ClearPass 맞춤 안내, 최종 HTML 보고서, 대용량 성능·실제 Windows 11/EDR/차단망 검증은 후속 작업입니다.
- 상용 코드 서명이 없어 게시자 경고가 나타날 수 있습니다.

## 자산

사용자 실행 파일은 `WlanTroubleshooterKO-v0.14.0-alpha.1-win64-portable.zip`입니다. `.sha256`은 무결성 확인용이고, Wireshark 소스 및 공급망 기록은 라이선스·재현성 증거입니다. 소스 압축파일은 사용자 실행용이 아닙니다.
