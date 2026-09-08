# 오프라인 PCAP 분석: 설계와 검증의 범위

검토 기준은 2026-09-08의 공개 기본 브랜치 소스 `60667abeb89b1ebf1fdb04a9861083081aa83f21`입니다. 이 문서는 구현된 보안·관측 경계와 아직 해결할 정확도 문제를 함께 설명합니다. 현장 진단 정확도, 조사 시간 절감, 운영 배포 규모는 측정된 근거가 없습니다.

## 사례: “DNS가 안 된다”는 신고를 받은 경우

먼저 캡처 형식·잘림·관찰 가능 계층을 확인합니다. DNS 오류 응답이 있으면 RCODE와 근거 프레임을 제시하지만, 응답을 못 본 것만으로 서버 실패를 확정하지 않습니다. 짧은 캡처, 한쪽 방향 수집, 패킷 상한 때문에 같은 결과가 나타날 수 있기 때문입니다.

사용자는 Finding의 `frame.number` 필터로 원본을 다시 확인합니다. 현재 버전의 거래 완결성·단말 연결 요약에는 아래 알려진 제한이 있으므로 원본 검토를 생략하는 자동 판정에 사용하지 않습니다.

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

## 알려진 상관 정확도 제한

아래 두 반례는 위 기준 소스의 기존 테스트 입력 생성기를 이용해 2026-09-08 macOS·CPython 3.13에서 재현했습니다. 실제 PCAP·장비 통신은 사용하지 않았습니다.

| 합성 입력 | 관찰 결과 | 필요한 판정과 영향 |
|---|---|---|
| 같은 TCP stream에 SYN=1, ACK=1인 프레임 두 개만 입력 | TCP 단계 `success`, “TCP 3-way Handshake 순서”와 프레임 1·2 표시 | 최초 SYN과 SYN=0인 최종 ACK가 없어 연결 성공을 확정할 수 없음 |
| DNS query와 response의 ID는 7로 같고 UDP stream은 각각 1·2 | `DNS-1-A1` 거래가 `complete` | 서로 다른 거래를 묶을 수 있으므로 stream·방향·시도 경계 검증 필요 |

첫 번째는 [event_correlation.py](../src/wlan_troubleshooter_ko/analysis/event_correlation.py)의 최종 ACK 분기, 두 번째는 [event_timeline.py](../src/wlan_troubleshooter_ko/analysis/event_timeline.py)의 DNS 별칭 생성과 [transaction_sessions.py](../src/wlan_troubleshooter_ko/analysis/transaction_sessions.py) 연결 경로에서 확인할 수 있습니다. DNS 단계 집계의 stream 구분과 거래 타임라인의 별칭 경계는 별개입니다.

TCP 반례는 기존 테스트 helper로 다음처럼 재현할 수 있습니다. 위 환경 설정 후 저장소 루트에서 PowerShell로 실행합니다.

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

기준 버전의 출력은 `[('success', (1, 2))]`로 잘못된 성공 판정을 보여 줍니다. 수정 버전에서는 이 결과가 달라져야 하며, 반례 회귀·전체 Windows·Portable 검증을 함께 갱신해야 합니다. 2026-09-08 확인 당시 [PR #19](https://github.com/sebia1993/wlan-troubleshooter-ko/pull/19)는 별도 진행 중이었으며 이 문서는 해당 브랜치의 수정 완료를 주장하지 않습니다.

## 검증 증거와 다음 우선순위

- 기준 소스의 [Windows CI 실행](https://github.com/sebia1993/wlan-troubleshooter-ko/actions/runs/33970543169)과 [Portable 릴리스 실행](https://github.com/sebia1993/wlan-troubleshooter-ko/actions/runs/33970543170)은 성공 이력입니다. 자동 검증이 위 반례까지 보장하지는 않습니다.
- [v0.13.0-alpha.1](https://github.com/sebia1993/wlan-troubleshooter-ko/releases/tag/v0.13.0-alpha.1)은 공개 사전릴리스입니다. 릴리스 자산의 SHA-256과 실제 내려받은 파일을 비교해야 합니다.
- 우선순위는 TCP·DNS 거래 경계 및 DHCP Relay의 단말 귀속 검토 → 대표 장애 5~10건의 Wireshark 대조 → 검색·구간 선택·단일 HTML 보고서 순서입니다. 이 항목은 완료 내역이 아닌 후속 제안입니다.
- Radiotap이 없으면 RF를, RADIUS가 없으면 ClearPass 결과를 판단할 수 없습니다. ISB 드롭 0·통계 부재는 무손실 증거가 아니며, 양수 드롭도 특정 시스템의 원인 증거가 아닙니다.
