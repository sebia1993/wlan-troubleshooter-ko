# 오프라인 PCAP 분석: 설계와 검증의 범위

검토 기준은 공개 기본 브랜치와 각 변경 PR의 실제 코드·Actions 결과입니다. 이 문서는 구현된 보안·관측 경계와 과거에 재현된 정확도 반례, 그에 대한 회귀 방어를 함께 설명합니다. 현장 진단 정확도, 조사 시간 절감, 운영 배포 규모는 측정된 근거가 없습니다.

## 사례: “DNS가 안 된다”는 신고를 받은 경우

먼저 캡처 형식·잘림·관찰 가능 계층을 확인합니다. DNS 오류 응답이 있으면 RCODE와 근거 프레임을 제시하지만, 응답을 못 본 것만으로 서버 실패를 확정하지 않습니다. 짧은 캡처, 한쪽 방향 수집, 패킷 상한 때문에 같은 결과가 나타날 수 있기 때문입니다.

사용자는 Finding의 `frame.number` 필터로 원본을 다시 확인합니다. 자동 상관 결과는 아래 회귀 테스트를 통과하더라도 실제 캡처의 모든 오탐·미탐을 배제하지 못하므로 원본 검토를 생략하는 자동 판정에 사용하지 않습니다.

## 설계 판단에서 구현까지

| 판단 | 구현 경로 | 합성 검증 근거 |
|---|---|---|
| 신뢰할 수 없는 파일을 먼저 검증 | [capture.py](../src/wlan_troubleshooter_ko/core/capture.py): 경로·형식·크기·해시, [preflight.py](../src/wlan_troubleshooter_ko/analysis/preflight.py) | [capture preflight tests](../tests/test_capture_preflight.py) |
| 설치 환경에 따라 달라지는 해석을 줄임 | [TShark 정책](../src/wlan_troubleshooter_ko/tshark/policy.py), [승인 번들 ADR](adr/0002-approved-portable-tshark.md) | [고정 Portable 검증 경로](../.github/workflows/windows-portable.yml) |
| 명시적 실패와 관측 부재를 구분 | [event_correlation.py](../src/wlan_troubleshooter_ko/analysis/event_correlation.py), [capture_observability.py](../src/wlan_troubleshooter_ko/analysis/capture_observability.py) | [event tests](../tests/test_event_correlation.py), [observability tests](../tests/test_capture_observability.py) |
| 원본 식별정보를 공개 결과에 남기지 않음 | [device_sessions.py](../src/wlan_troubleshooter_ko/analysis/device_sessions.py), [가명 ADR](adr/0004-analysis-scoped-device-pseudonyms.md) | [device session tests](../tests/test_device_sessions.py) |
| 누적 ISB Counter를 합산하지 않음 | [pcapng_interface_statistics.py](../src/wlan_troubleshooter_ko/analysis/pcapng_interface_statistics.py) | [ISB tests](../tests/test_pcapng_interface_statistics.py), [Portable ISB 검증](../tests/portable_build/verify_pcapng_interface_statistics.ps1) |

전체 진입 흐름은 [service.py](../src/wlan_troubleshooter_ko/analysis/service.py)에서 확인할 수 있습니다. Python 런타임 의존성 0개와 별도 배포되는 Portable TShark는 다른 범위입니다.

## 장비 없이 재현하기

Windows·CPython 3.13에서 저장소 루트 기준으로 실행합니다. 기본 테스트는 표준 라이브러리 `unittest`와 합성 입력을 사용합니다.

```powershell
py -3.13 -m venv .venv
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_event_correlation.py' -v
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_pcapng_interface_statistics.py' -v
.\scripts\verify_offline.ps1 -PythonPath .\.venv\Scripts\python.exe
```

마지막 명령은 compile·소스 감사·저장소 감사·전체 unittest·자체 점검을 실행합니다. TShark 바이너리는 Git에 포함되지 않으므로 이 테스트의 통과가 실제 Portable 분석 성공을 뜻하지 않습니다. 승인 바이너리가 없으면 미준비로 처리해야 합니다.

macOS에서 소스 테스트를 보조 실행할 때 `/var` 등 symlink가 포함된 임시 경로는 파일 경계 검사에 거부될 수 있습니다. 실제 경로인 `TMPDIR=/private/tmp`를 지정해 검증하되 Windows 검증으로 표현하지 않습니다.

## 상관 정확도 회귀 검증

2026-09-08 기준 소스 `60667abeb89b1ebf1fdb04a9861083081aa83f21`에서는 아래 두 합성 반례가 재현됐습니다. 실제 PCAP·장비 통신은 사용하지 않았습니다.

| 과거 합성 반례 | 과거 관찰 결과 | 현재 방어 |
|---|---|---|
| 같은 TCP stream에 `SYN=1, ACK=1`인 프레임 두 개만 입력 | TCP 단계 `success`, “TCP 3-way Handshake 순서” 표시 | 같은 stream의 `SYN(ACK 아님) → SYN+ACK → ACK(SYN 아님, RST 아님)`가 모두 있어야 성공 |
| DNS query와 response의 ID는 7로 같고 UDP stream은 각각 1·2 | 서로 다른 거래를 하나의 완결 거래로 묶을 수 있음 | transport stream과 DNS ID를 함께 상관 키로 사용 |

TCP 회귀 방어는 [event_correlation.py](../src/wlan_troubleshooter_ko/analysis/event_correlation.py)와 [test_event_correlation.py](../tests/test_event_correlation.py)에 고정했습니다. 다음 사례를 각각 검증합니다.

- `SYN+ACK, SYN+ACK`만 관찰: 성공 금지
- `SYN, SYN+ACK, ACK`: 성공 유지
- `SYN, SYN+ACK, SYN+ACK, ACK`: 반복 SYN+ACK를 최종 ACK로 보지 않고 마지막 순수 ACK에서만 성공
- `SYN+ACK, ACK`: 최초 순수 SYN이 없으므로 성공 금지
- `SYN, SYN+ACK`: 최종 순수 ACK가 없으므로 성공 금지

TCP 성공 근거는 같은 `tcp.stream` 안에서만 누적합니다. RST가 설정된 ACK는 최종 ACK로 사용하지 않습니다. 이 방어는 합성 상관 반례를 막는 검증이며, 실제 TCP 연결의 모든 변형·캡처 손실·중간 캡처 시작을 완전하게 해석한다는 보장은 아닙니다.

DNS 단계 집계와 거래 타임라인은 별개 계층입니다. transport stream과 DNS ID를 함께 사용하더라도 재전송, TCP 기반 DNS, 캡처 경계와 실제 클라이언트 귀속은 근거 프레임과 함께 검토해야 합니다.

과거 TCP 반례는 다음 형태였습니다.

```powershell
@'
import sys
sys.path.insert(0, 'tests')
from test_event_correlation import EventCorrelationTests
from wlan_troubleshooter_ko.analysis.event_correlation import build_event_correlation
EventCorrelationTests.setUpClass()
t = EventCorrelationTests()
rows = []
for n in (1, 2):
    row = t.base(n, n, 'eth:ip:tcp')
    row.update(tcp_stream=1, tcp_syn=1, tcp_ack=1)
    rows.append(row)
r = build_event_correlation(t.render(rows), t.profile, t.ruleset,
                            expected_frames=2, has_80211_link_type=False)
print([(s.state, s.evidence_frames) for s in r.stages if s.stage_id == 'tcp'])
'@ | .\.venv\Scripts\python.exe -
```

과거 기준 버전은 이 입력을 잘못된 성공으로 표시했습니다. 현재 회귀 테스트는 동일한 형태의 입력이 `success`가 되지 않는 것을 검증합니다.

## 검증 증거와 다음 우선순위

- TCP 상관 수정 PR의 Windows CI는 전체 오프라인 검증과 새 회귀 테스트를 포함해야 하며, Python 없는 Portable 빌드는 별도로 성공해야 병합합니다.
- [v0.13.0-alpha.1](https://github.com/sebia1993/wlan-troubleshooter-ko/releases/tag/v0.13.0-alpha.1)은 기존 공개 사전릴리스입니다. 소스 수정이 병합돼도 새 릴리스가 발행되기 전까지 기존 릴리스 바이너리가 자동으로 바뀌지는 않습니다.
- 다음 정확도 우선순위는 DHCP Relay의 단말 귀속 검토 → 대표 장애 5~10건의 Wireshark 대조 → 검색·구간 선택·단일 HTML 보고서 순서입니다. 이 항목은 완료 내역이 아닌 후속 제안입니다.
- Radiotap이 없으면 RF를, RADIUS가 없으면 ClearPass 결과를 판단할 수 없습니다. ISB 드롭 0·통계 부재는 무손실 증거가 아니며, 양수 드롭도 특정 시스템의 원인 증거가 아닙니다.