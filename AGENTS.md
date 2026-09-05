# 저장소 작업 규칙

변경 전에 `AGENTS.md`, `CODEX_IMPLEMENTATION_PLAN.md`, 현재 Phase 계획, `IMPLEMENTATION_STATUS.md`, 관련 ADR을 순서대로 읽습니다. 최신 명시적 사용자 지시가 우선하며 범위를 임의로 넓히지 않습니다.

사용자는 개발을 계속 진행하고, 각 작업 종료 시 남은 개발 항목을 반드시 보고하도록 지시했습니다.

## 현재 범위

현재 범위는 `docs/PHASE_4J_PLAN.md`의 **EAPOL Replay Counter 비식별 관계 분석**입니다.

- Phase 4I의 `EAPOL-HS-N`, `DEVICE-N`, `AP-N` 관찰만 사용합니다.
- Replay Counter 원문은 전용 최소 TShark 프로파일에서만 일시적으로 읽습니다.
- 공개 결과에는 같음·증가·감소·불일치 관계와 근거 프레임만 기록합니다.
- 동일 Handshake·실제 재전송·키 설치·암호학적 성공·근본 원인을 확정하지 않습니다.
- 가짜 Counter, 임시 성공값과 근거 없는 책임 시스템 판정을 만들지 않습니다.

## 런타임 금지사항

- Python 3.13 표준 라이브러리와 `tkinter/ttk`만 제품 런타임에 사용합니다.
- AI, LLM, Ollama, MCP, 외부 API, HTTP 요청, 소켓, 온라인 DNS 조회, 텔레메트리, 오류 자동 전송, 자동 업데이트, 온라인 버전 확인, 수신 포트, HTTP 서버, 원격 제어, API 키·토큰·URL 설정을 추가하지 않습니다.
- 네트워크·AI Import, 외부 URL, `eval`, `exec`, `shell=True`를 정적 감사로 차단합니다.
- GitHub Actions의 공급망 다운로드는 제품 런타임과 분리합니다.

## TShark 실행 경계

- `vendor/wireshark/`의 고정 매니페스트 TShark만 사용합니다.
- 시스템 설치본, 레지스트리와 PATH 실행 파일로 대체하지 않습니다.
- 실행 파일과 종속 파일의 크기·SHA-256을 실행 전후 확인합니다.
- `shell=False`, stdin 비활성화, Windows 콘솔 숨김을 고정합니다.
- `-n`, 저장 파일 `-r`, 패킷 상한 `-c`, 고정 fields만 허용합니다.
- 실시간·원격 캡처, 임의 extcap·Lua·필터·필드·사용자 옵션을 금지합니다.
- stderr 원문은 저장·표시하지 않습니다.
- 빈 config·plugin·extcap·data·temp 경로와 종료 후 무잔류를 유지합니다.

## Replay Counter 최소 프로파일

허용 필드는 다음 세 개뿐입니다.

```text
frame.number
wlan_rsna_eapol.keydes.msgnr
eapol.keydes.replay_counter
```

`eapol.keydes.replay_counter`는 다음 경로에서 금지합니다.

```text
일반 프로토콜 인벤토리
공개 이벤트 타임라인
단말 가명화 프로파일
레거시 TShark 실행
GUI·JSON·로그
```

Nonce·MIC·Key Data·Payload 필드는 모든 프로파일에서 금지합니다.

## 동일 캡처·번들 검증

Replay Counter 실행은 기존 분석과 다음 값이 모두 같아야 합니다.

```text
캡처 절대경로
캡처 형식
파일 크기
SHA-256
TShark 버전
TShark 매니페스트 SHA-256
```

분석 단계 사이에 캡처 또는 내장 TShark가 변경되면 실패-폐쇄 처리합니다.

## 관계와 판정 경계

- M1/M2 및 M3/M4: 같음·불일치·여러 값·미관찰·사용 불가
- M1→M3: 증가·동일·감소·여러 값·미관찰·사용 불가
- 반복 M1~M4: 같은 Counter·다른 Counter·사용 불가

다음 값은 항상 `false`입니다.

```text
raw_replay_counters_serialized
replay_counter_values_persisted
same_handshake_confirmed
retransmission_confirmed
key_installation_confirmed
cryptographic_success_confirmed
root_cause_confirmed
```

- 일반적인 관계가 보여도 동일 Handshake로 확정하지 않습니다.
- 같은 메시지와 같은 Counter 관계가 반복돼도 실제 재전송으로 확정하지 않습니다.
- 불일치를 키 설치 실패·AP·단말·RF 장애로 확정하지 않습니다.
- 필드·프레임·근거 누락은 `unavailable` 또는 `partial`로 낮춥니다.

## 개인정보·키 정보 경계

다음 값은 GUI·JSON·로그·릴리스 자산에 기록하지 않습니다.

```text
Replay Counter 원문 숫자
EAPOL Nonce·MIC·Key Data
원본 MAC·BSSID·SSID
IPv4·IPv6 주소
사용자명·EAP Identity·RADIUS User-Name
DNS 질의명·호스트명
TCP·UDP 포트
원본 거래 ID·Stream 번호
HMAC 키와 내부 토큰
암호화 키·자격 증명
절대 epoch
Raw Payload
캡처 파일명·절대경로
TShark stderr 원문
```

메모리 포렌식까지 포함한 완전 비노출은 주장하지 않습니다. 보장 범위는 원문 값을 디스크·로그·GUI·JSON·릴리스 자산·외부 네트워크에 남기지 않는 것입니다.

## 검증과 릴리스

Windows 전체 테스트·자체 점검·소스 감사·저장소 감사와 Python·Wireshark 없는 Portable 실제 분석을 모두 통과해야 병합합니다.

Portable 합성 캡처 기대값:

```text
M1/M2 = equal-observed
M3/M4 = equal-observed
M1→M3 = increased-observed
반복 M3 = same-counter-observed
state = expected-relations-observed
```

고유 64비트 Counter 숫자, 필드명, 키 정보, 원본 주소, 절대 시간과 경로가 최종 JSON에 없어야 합니다.

`v0.12.0-alpha.1`은 Replay Counter 관계 프리릴리스입니다. 완전한 Handshake 성공 판정기나 WLAN 근본 원인 분석기로 표현하지 않습니다.
