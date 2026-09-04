# Portable 실분석 안전 진단 원칙

Portable 통합 검증이 실패할 때 GitHub Actions 로그에는 합성 캡처의 종류와 프로그램이 이미 정규화한 안전 오류 상태만 표시합니다.

허용되는 진단:

- `Ethernet`, `PPP-EAP`, `IEEE-802.11` 같은 고정 합성 캡처 라벨
- `protocol_inventory_state`
- 최대 500자로 제한된 `protocol_inventory_message`
- 단계 성공·실패와 종료 코드

표시하지 않는 정보:

- 캡처 절대경로와 원본 파일명
- 패킷 원문과 TShark stderr 원문
- IP·MAC·SSID·BSSID·사용자명·DNS 질의명
- 원본 거래 ID·Stream 번호·가명화 비밀값

실제 사내 캡처를 CI에 추가하지 않습니다. 검증 캡처는 워크플로 실행 중 결정론적으로 생성하고 종료 시 삭제합니다.
