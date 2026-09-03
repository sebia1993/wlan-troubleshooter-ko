"""TShark 프레임 메타데이터를 접속 단계와 보수적 Finding으로 상관분석한다."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from wlan_troubleshooter_ko.tshark.fields_output import FieldsOutputError, iter_fields_rows
from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


class EventCorrelationError(ValueError):
    """접속 이벤트 입력이나 규칙이 안전한 판정 조건을 충족하지 못한 경우."""


@dataclass(frozen=True)
class StageSummary:
    stage_id: str
    label_ko: str
    state: str
    summary_ko: str
    evidence_frames: Tuple[int, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "stage_id": self.stage_id,
            "label_ko": self.label_ko,
            "state": self.state,
            "summary_ko": self.summary_ko,
            "evidence_frames": list(self.evidence_frames),
        }


@dataclass(frozen=True)
class DiagnosticFinding:
    rule_id: str
    classification: str
    stage_id: str
    title_ko: str
    summary_ko: str
    evidence_frames: Tuple[int, ...]
    display_filter: str
    next_checks: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "classification": self.classification,
            "stage_id": self.stage_id,
            "title_ko": self.title_ko,
            "summary_ko": self.summary_ko,
            "evidence_frames": list(self.evidence_frames),
            "display_filter": self.display_filter,
            "next_checks": list(self.next_checks),
        }


@dataclass(frozen=True)
class EventCorrelation:
    profile_id: str
    profile_version: str
    ruleset_version: str
    frames_scanned: int
    event_frames: int
    complete: bool
    stages: Tuple[StageSummary, ...]
    findings: Tuple[DiagnosticFinding, ...]
    missing_optional_fields: Tuple[str, ...]
    cautions: Tuple[str, ...]

    def to_dict(self) -> Dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "ruleset_version": self.ruleset_version,
            "frames_scanned": self.frames_scanned,
            "event_frames": self.event_frames,
            "complete": self.complete,
            "stages": [item.to_dict() for item in self.stages],
            "findings": [item.to_dict() for item in self.findings],
            "missing_optional_fields": list(self.missing_optional_fields),
            "cautions": list(self.cautions),
        }


@dataclass
class _DhcpState:
    types: Set[int] = field(default_factory=set)
    frames: List[int] = field(default_factory=list)
    request_time_ns: Optional[int] = None


@dataclass
class _DnsState:
    query_frame: Optional[int] = None
    query_time_ns: Optional[int] = None
    response_frame: Optional[int] = None


@dataclass
class _TcpState:
    syn_frame: Optional[int] = None
    syn_time_ns: Optional[int] = None
    synack_frame: Optional[int] = None
    final_ack_frame: Optional[int] = None


_REQUIRED_RULES = {
    "WLAN-ASSOC-REJECT",
    "WLAN-DISCONNECT",
    "EAP-FAILURE",
    "RADIUS-ACCESS-REJECT",
    "DHCP-NAK",
    "DNS-ERROR-RESPONSE",
    "TCP-RST",
    "TCP-RETRANSMISSION-MANY",
    "DHCP-RESPONSE-NOT-OBSERVED",
    "DNS-RESPONSE-NOT-OBSERVED",
    "TCP-SYNACK-NOT-OBSERVED",
}
_STAGE_ORDER = ("wlan", "eapol", "eap", "radius", "dhcp", "dns", "arp", "tcp")
_STAGE_LABELS = {
    "wlan": "무선 연결",
    "eapol": "802.1X 시작·키 교환",
    "eap": "EAP 인증",
    "radius": "RADIUS 인증 서버",
    "dhcp": "DHCP 주소 할당",
    "dns": "DNS 이름 조회",
    "arp": "ARP 주소 확인",
    "tcp": "TCP 연결",
}
_DNS_RCODE = {
    1: "형식 오류(FORMERR)",
    2: "서버 실패(SERVFAIL)",
    3: "이름 없음(NXDOMAIN)",
    4: "미지원(NOTIMP)",
    5: "거부(REFUSED)",
}
_MAX_KEYS = 100_000
_MAX_EVIDENCE = 20


def _rules(ruleset: Mapping[str, object]) -> Tuple[str, Dict[str, str]]:
    version = ruleset.get("ruleset_version")
    rules = ruleset.get("rules")
    if not isinstance(version, str) or not version or not isinstance(rules, list):
        raise EventCorrelationError("판정 규칙 리소스가 올바르지 않습니다.")
    values: Dict[str, str] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            raise EventCorrelationError("판정 규칙 항목이 올바르지 않습니다.")
        identifier = rule.get("id")
        classification = rule.get("classification")
        if not isinstance(identifier, str) or not isinstance(classification, str):
            raise EventCorrelationError("판정 규칙 ID 또는 등급이 올바르지 않습니다.")
        values[identifier] = classification
    missing = sorted(_REQUIRED_RULES - set(values))
    if missing:
        raise EventCorrelationError("필수 판정 규칙이 누락됐습니다: " + ", ".join(missing))
    return version, values


def _cell(row: Tuple[str, ...], positions: Mapping[str, int], key: str) -> str:
    index = positions.get(key)
    return "" if index is None else row[index].strip()


def _uint(value: str, label: str, maximum: int = 2**64 - 1) -> Optional[int]:
    if value == "":
        return None
    try:
        result = int(value, 16 if value.casefold().startswith("0x") else 10)
    except ValueError as exc:
        raise EventCorrelationError(label + " 값이 정수가 아닙니다.") from exc
    if result < 0 or result > maximum:
        raise EventCorrelationError(label + " 값이 허용 범위를 벗어났습니다.")
    return result


def _required_uint(value: str, label: str, maximum: int = 2**64 - 1) -> int:
    result = _uint(value, label, maximum)
    if result is None:
        raise EventCorrelationError(label + " 값이 누락됐습니다.")
    return result


def _boolean(value: str, label: str) -> Optional[bool]:
    if value == "":
        return None
    lowered = value.casefold()
    if lowered in {"1", "true", "yes", "set"}:
        return True
    if lowered in {"0", "false", "no", "not set"}:
        return False
    raise EventCorrelationError(label + " 값이 불리언이 아닙니다.")


def _epoch_ns(value: str) -> int:
    if value.startswith("+"):
        value = value[1:]
    whole, separator, fraction = value.partition(".")
    if (
        not whole
        or not whole.isascii()
        or not whole.isdecimal()
        or value.startswith("-")
        or value.count(".") > 1
        or (separator and (not fraction or not fraction.isascii() or not fraction.isdecimal()))
        or len(fraction) > 9
    ):
        raise EventCorrelationError("프레임 시각 형식이 올바르지 않습니다.")
    result = int(whole) * 1_000_000_000
    result += int(fraction.ljust(9, "0")) if fraction else 0
    if result > 2**63 - 1:
        raise EventCorrelationError("프레임 시각이 허용 범위를 벗어났습니다.")
    return result


def _evidence(frames: Iterable[int]) -> Tuple[int, ...]:
    return tuple(sorted(set(frames))[:_MAX_EVIDENCE])


def _finding(
    classes: Mapping[str, str],
    rule_id: str,
    stage_id: str,
    title: str,
    summary: str,
    frames: Iterable[int],
    checks: Iterable[str],
) -> DiagnosticFinding:
    evidence = _evidence(frames)
    display_filter = " || ".join(
        "frame.number == {0}".format(frame) for frame in evidence
    )
    return DiagnosticFinding(
        rule_id,
        classes[rule_id],
        stage_id,
        title,
        summary,
        evidence,
        display_filter or "frame.number == 0",
        tuple(checks),
    )


def _stage(
    stage_id: str,
    available: bool,
    successes: Iterable[int],
    failures: Iterable[int],
    observed: Iterable[int],
    success_text: str,
    failure_text: str,
    observed_text: str,
    missing_text: str,
) -> StageSummary:
    success = list(successes)
    failure = list(failures)
    seen = list(observed)
    if not available:
        state, summary = "unavailable", "현재 TShark 또는 캡처 형식에서 이 단계를 판단할 수 없습니다."
    elif success and failure:
        state, summary = "mixed", "성공과 실패 응답이 모두 관찰됐습니다. 여러 시도가 섞였을 수 있습니다."
    elif failure:
        state, summary = "failure", failure_text
    elif success:
        state, summary = "success", success_text
    elif seen:
        state, summary = "incomplete", observed_text
    else:
        state, summary = "not_observed", missing_text
    return StageSummary(
        stage_id,
        _STAGE_LABELS[stage_id],
        state,
        summary,
        _evidence(success + failure + seen),
    )


def build_event_correlation(
    text: str,
    profile: ResolvedProfile,
    ruleset: Mapping[str, object],
    *,
    expected_frames: Optional[int],
    has_80211_link_type: bool,
) -> EventCorrelation:
    """명시적 응답은 판정하고, 미응답은 완전한 캡처에서도 판단 불가로 제한한다."""

    if profile.profile_id != "connection-events":
        raise EventCorrelationError("접속 이벤트 전용 추출 프로파일이 필요합니다.")
    if expected_frames is not None and (type(expected_frames) is not int or expected_frames < 0):
        raise EventCorrelationError("예상 프레임 수가 올바르지 않습니다.")
    ruleset_version, classes = _rules(ruleset)
    positions = {item.output_key: index for index, item in enumerate(profile.fields)}
    required = {"frame_number", "time_epoch", "captured_length", "frame_length", "protocols"}
    if not required.issubset(positions):
        raise EventCorrelationError("접속 이벤트 필수 열이 누락됐습니다.")

    available = {key: key in positions for key in (
        "wlan_type_subtype", "wlan_status_code", "wlan_reason_code",
        "eapol_type", "eap_code", "radius_code", "dhcp_id",
        "dhcp_message_type", "dns_id", "dns_is_response", "dns_rcode",
        "udp_stream", "arp_opcode", "tcp_stream", "tcp_syn", "tcp_ack",
        "tcp_reset", "tcp_retransmission",
    )}
    observed: Dict[str, List[int]] = {stage: [] for stage in _STAGE_ORDER}
    success: Dict[str, List[int]] = {stage: [] for stage in _STAGE_ORDER}
    failure: Dict[str, List[int]] = {stage: [] for stage in _STAGE_ORDER}
    findings: List[DiagnosticFinding] = []
    wlan_rejects: Dict[int, List[int]] = {}
    wlan_disconnects: Dict[int, List[int]] = {}
    dns_errors: Dict[int, List[int]] = {}
    dhcp_transactions: Dict[int, _DhcpState] = {}
    dns_transactions: Dict[Tuple[str, int, int], _DnsState] = {}
    tcp_states: Dict[int, _TcpState] = {}
    tcp_retransmissions: List[int] = []
    frames_scanned = event_frames = previous_frame = maximum_time_ns = 0

    try:
        for row in iter_fields_rows(text, profile):
            frame = _required_uint(_cell(row, positions, "frame_number"), "프레임 번호", 2**63 - 1)
            if frame == 0 or frame <= previous_frame:
                raise EventCorrelationError("프레임 번호가 엄격한 증가 순서가 아닙니다.")
            previous_frame = frame
            time_ns = _epoch_ns(_cell(row, positions, "time_epoch"))
            maximum_time_ns = max(maximum_time_ns, time_ns)
            cap_len = _required_uint(_cell(row, positions, "captured_length"), "캡처 길이")
            frame_len = _required_uint(_cell(row, positions, "frame_length"), "프레임 길이")
            if cap_len > frame_len:
                raise EventCorrelationError("캡처 길이가 프레임 길이보다 큽니다.")
            protocols = {
                token.strip().casefold()
                for token in _cell(row, positions, "protocols").split(":")
                if token.strip()
            }
            frames_scanned += 1
            if protocols & {"wlan", "eapol", "eap", "radius", "dhcp", "bootp", "dns", "arp", "tcp"}:
                event_frames += 1

            wlan_subtype = _uint(_cell(row, positions, "wlan_type_subtype"), "802.11 종류", 0xFFFF)
            if wlan_subtype is not None:
                observed["wlan"].append(frame)
                status = _uint(_cell(row, positions, "wlan_status_code"), "802.11 상태", 0xFFFF)
                reason = _uint(_cell(row, positions, "wlan_reason_code"), "802.11 사유", 0xFFFF)
                if wlan_subtype in {1, 3} and status is not None:
                    if status == 0:
                        success["wlan"].append(frame)
                    else:
                        failure["wlan"].append(frame)
                        wlan_rejects.setdefault(status, []).append(frame)
                if wlan_subtype in {10, 12}:
                    wlan_disconnects.setdefault(reason or 0, []).append(frame)

            if _uint(_cell(row, positions, "eapol_type"), "EAPOL 종류", 255) is not None:
                observed["eapol"].append(frame)

            eap_code = _uint(_cell(row, positions, "eap_code"), "EAP 코드", 255)
            if eap_code is not None:
                observed["eap"].append(frame)
                if eap_code == 3:
                    success["eap"].append(frame)
                elif eap_code == 4:
                    failure["eap"].append(frame)

            radius_code = _uint(_cell(row, positions, "radius_code"), "RADIUS 코드", 255)
            if radius_code is not None:
                observed["radius"].append(frame)
                if radius_code == 2:
                    success["radius"].append(frame)
                elif radius_code == 3:
                    failure["radius"].append(frame)

            dhcp_type = _uint(_cell(row, positions, "dhcp_message_type"), "DHCP 종류", 255)
            if dhcp_type is not None:
                observed["dhcp"].append(frame)
                if dhcp_type == 5:
                    success["dhcp"].append(frame)
                elif dhcp_type == 6:
                    failure["dhcp"].append(frame)
                dhcp_id = _uint(_cell(row, positions, "dhcp_id"), "DHCP ID", 0xFFFFFFFF)
                if dhcp_id is not None:
                    if dhcp_id not in dhcp_transactions and len(dhcp_transactions) >= _MAX_KEYS:
                        raise EventCorrelationError("DHCP 상관 키가 안전 제한을 초과했습니다.")
                    item = dhcp_transactions.setdefault(dhcp_id, _DhcpState())
                    item.types.add(dhcp_type)
                    item.frames.append(frame)
                    if dhcp_type in {1, 3}:
                        item.request_time_ns = time_ns

            dns_response = _boolean(_cell(row, positions, "dns_is_response"), "DNS 응답")
            dns_id = _uint(_cell(row, positions, "dns_id"), "DNS ID", 0xFFFF)
            if dns_response is not None:
                observed["dns"].append(frame)
                rcode = _uint(_cell(row, positions, "dns_rcode"), "DNS 응답 코드", 0xFFFF)
                if dns_response:
                    if rcode in {None, 0}:
                        success["dns"].append(frame)
                    else:
                        failure["dns"].append(frame)
                        dns_errors.setdefault(rcode, []).append(frame)
                if dns_id is not None:
                    udp_stream = _uint(_cell(row, positions, "udp_stream"), "UDP 스트림")
                    tcp_stream = _uint(_cell(row, positions, "tcp_stream"), "TCP 스트림")
                    key = ("udp", udp_stream, dns_id) if udp_stream is not None else (
                        ("tcp", tcp_stream, dns_id) if tcp_stream is not None else ("id", 0, dns_id)
                    )
                    if key not in dns_transactions and len(dns_transactions) >= _MAX_KEYS:
                        raise EventCorrelationError("DNS 상관 키가 안전 제한을 초과했습니다.")
                    item = dns_transactions.setdefault(key, _DnsState())
                    if dns_response:
                        item.response_frame = frame
                    elif item.query_frame is None:
                        item.query_frame, item.query_time_ns = frame, time_ns

            arp_opcode = _uint(_cell(row, positions, "arp_opcode"), "ARP 동작", 0xFFFF)
            if arp_opcode is not None:
                observed["arp"].append(frame)
                if arp_opcode == 2:
                    success["arp"].append(frame)

            tcp_stream = _uint(_cell(row, positions, "tcp_stream"), "TCP 스트림")
            tcp_syn = _boolean(_cell(row, positions, "tcp_syn"), "TCP SYN")
            tcp_ack = _boolean(_cell(row, positions, "tcp_ack"), "TCP ACK")
            tcp_reset = _boolean(_cell(row, positions, "tcp_reset"), "TCP RST")
            retransmission = bool(_cell(row, positions, "tcp_retransmission"))
            if tcp_stream is not None or any(value is not None for value in (tcp_syn, tcp_ack, tcp_reset)) or retransmission:
                observed["tcp"].append(frame)
            if tcp_reset is True:
                failure["tcp"].append(frame)
            if retransmission:
                tcp_retransmissions.append(frame)
            if tcp_stream is not None:
                if tcp_stream not in tcp_states and len(tcp_states) >= _MAX_KEYS:
                    raise EventCorrelationError("TCP 스트림 수가 안전 제한을 초과했습니다.")
                item = tcp_states.setdefault(tcp_stream, _TcpState())
                if tcp_syn is True and tcp_ack is not True and item.syn_frame is None:
                    item.syn_frame, item.syn_time_ns = frame, time_ns
                elif tcp_syn is True and tcp_ack is True and item.synack_frame is None:
                    item.synack_frame = frame
                elif tcp_ack is True and item.synack_frame is not None and item.final_ack_frame is None:
                    item.final_ack_frame = frame
                    success["tcp"].extend(
                        value for value in (item.syn_frame, item.synack_frame, frame) if value is not None
                    )
    except FieldsOutputError as exc:
        raise EventCorrelationError(str(exc)) from exc

    if expected_frames is not None and frames_scanned > expected_frames:
        raise EventCorrelationError("이벤트 분석 프레임 수가 사전 점검 프레임 수보다 큽니다.")
    complete = expected_frames is not None and frames_scanned == expected_frames

    for code, frames in sorted(wlan_rejects.items()):
        findings.append(_finding(
            classes, "WLAN-ASSOC-REJECT", "wlan", "무선 연결 응답이 거부됐습니다",
            "Association/Reassociation 상태 코드 {0}이 관찰됐습니다.".format(code),
            frames,
            ("해당 프레임의 상태 코드를 확인합니다.", "AP·컨트롤러 로그와 SSID 보안 정책을 확인합니다."),
        ))
    for code, frames in sorted(wlan_disconnects.items()):
        findings.append(_finding(
            classes, "WLAN-DISCONNECT", "wlan", "무선 연결 해제 프레임이 관찰됐습니다",
            "Deauthentication/Disassociation 사유 코드 {0}이 관찰됐습니다. 이 사실만으로 근본 원인을 확정하지 않습니다.".format(code),
            frames,
            ("해제 전후의 Association·EAPOL을 확인합니다.", "컨트롤러 사용자 종료 사유와 AP 로그를 확인합니다."),
        ))
    explicit = (
        ("EAP-FAILURE", "eap", "EAP 인증 실패 응답이 관찰됐습니다", "EAP Code 4(Failure)가 명시적으로 기록됐습니다.", failure["eap"],
         ("단말의 EAP 방식·인증서·계정 설정을 확인합니다.", "ClearPass Access Tracker에서 같은 시각의 결과를 확인합니다.")),
        ("RADIUS-ACCESS-REJECT", "radius", "RADIUS Access-Reject가 관찰됐습니다", "인증 서버가 Access-Reject(Code 3)를 반환했습니다.", failure["radius"],
         ("ClearPass에서 Reject 사유와 적용 Service·Role을 확인합니다.", "계정·인증서·단말 등록 상태를 확인합니다.")),
        ("DHCP-NAK", "dhcp", "DHCP NAK가 관찰됐습니다", "DHCP 서버가 요청한 주소 사용을 거부했습니다.", failure["dhcp"],
         ("단말 임대를 갱신하고 올바른 VLAN인지 확인합니다.", "DHCP Scope·Relay·서버 로그를 확인합니다.")),
        ("TCP-RST", "tcp", "TCP 연결 재설정(RST)이 관찰됐습니다", "한쪽 통신 주체가 TCP Reset을 보냈습니다. 이것만으로 RF 장애를 확정하지 않습니다.", failure["tcp"],
         ("RST 전후의 SYN·SYN/ACK를 확인합니다.", "서버 서비스·방화벽·세션 종료 로그를 확인합니다.")),
    )
    for rule_id, stage, title, summary, frames, checks in explicit:
        if frames:
            findings.append(_finding(classes, rule_id, stage, title, summary, frames, checks))
    for code, frames in sorted(dns_errors.items()):
        findings.append(_finding(
            classes, "DNS-ERROR-RESPONSE", "dns", "DNS 오류 응답이 관찰됐습니다",
            "DNS 서버 응답에 {0}가 기록됐습니다.".format(_DNS_RCODE.get(code, "오류 코드 {0}".format(code))),
            frames,
            ("응답 코드 기준으로 DNS 서버·상위 Resolver 상태를 확인합니다.", "질의 이름은 필요할 때 원본 캡처에서 직접 확인합니다."),
        ))
    if len(tcp_retransmissions) >= 3:
        findings.append(_finding(
            classes, "TCP-RETRANSMISSION-MANY", "tcp", "TCP 재전송이 여러 번 관찰됐습니다",
            "TCP 재전송 표시가 {0}개 프레임에 있습니다. 재전송만으로 RF 장애를 확정하지 않습니다.".format(len(tcp_retransmissions)),
            tcp_retransmissions,
            ("Radiotap 캡처가 있으면 같은 구간의 RSSI·Retry를 비교합니다.", "유선 측 캡처와 서버 로그로 손실 지점을 좁힙니다."),
        ))

    if complete:
        missing_dhcp: List[int] = []
        missing_dns: List[int] = []
        missing_tcp: List[int] = []
        for item in dhcp_transactions.values():
            if item.types & {1, 3} and not item.types & {2, 5, 6} and item.request_time_ns is not None:
                if maximum_time_ns - item.request_time_ns >= 5_000_000_000:
                    missing_dhcp.extend(item.frames)
        for item in dns_transactions.values():
            if item.query_frame is not None and item.response_frame is None and item.query_time_ns is not None:
                if maximum_time_ns - item.query_time_ns >= 2_000_000_000:
                    missing_dns.append(item.query_frame)
        for item in tcp_states.values():
            if item.syn_frame is not None and item.synack_frame is None and item.syn_time_ns is not None:
                if maximum_time_ns - item.syn_time_ns >= 3_000_000_000:
                    missing_tcp.append(item.syn_frame)
        missing_specs = (
            ("DHCP-RESPONSE-NOT-OBSERVED", "dhcp", "DHCP 요청 뒤 응답을 확인하지 못했습니다", missing_dhcp,
             "전체 캡처에서 충분한 후속 시간 동안 Offer·ACK·NAK가 보이지 않았습니다. 역방향 패킷 누락 가능성이 있어 장애로 확정하지 않습니다.",
             ("양방향 캡처인지 확인합니다.", "DHCP Relay·Scope·서버 로그에서 요청 도착 여부를 확인합니다.")),
            ("DNS-RESPONSE-NOT-OBSERVED", "dns", "DNS 질의 뒤 응답을 확인하지 못했습니다", missing_dns,
             "전체 캡처에서 충분한 후속 시간 동안 DNS 응답이 보이지 않았습니다. 단방향 캡처 가능성을 먼저 배제해야 합니다.",
             ("양방향 캡처와 DNS ACL·방화벽을 확인합니다.", "DNS 서버 로그에서 질의 도착·응답 생성을 확인합니다.")),
            ("TCP-SYNACK-NOT-OBSERVED", "tcp", "TCP SYN 뒤 SYN/ACK를 확인하지 못했습니다", missing_tcp,
             "전체 캡처에서 충분한 후속 시간 동안 SYN/ACK가 보이지 않았습니다. 서버 장애와 무선 손실 중 하나로 단정할 수 없습니다.",
             ("양방향 캡처인지 확인합니다.", "서버 Listen·방화벽·유선 구간 캡처를 비교합니다.")),
        )
        for rule_id, stage, title, frames, summary, checks in missing_specs:
            if frames:
                findings.append(_finding(classes, rule_id, stage, title, summary, frames, checks))

    stage_specs = {
        "wlan": (has_80211_link_type and available["wlan_type_subtype"], "연결 성공 응답이 관찰됐습니다.", "연결 거부 응답이 관찰됐습니다.", "802.11 관리 프레임은 보였지만 연결 결과는 확인하지 못했습니다.", "802.11 연결 관리 이벤트가 관찰되지 않았습니다."),
        "eapol": (available["eapol_type"], "EAPOL 프레임이 관찰됐습니다.", "", "EAPOL 프레임이 관찰됐습니다. 키 교환 완성 여부는 아직 판정하지 않습니다.", "EAPOL 프레임이 관찰되지 않았습니다."),
        "eap": (available["eap_code"], "EAP Success가 관찰됐습니다.", "EAP Failure가 관찰됐습니다.", "EAP 요청·응답은 보였지만 최종 결과는 확인하지 못했습니다.", "EAP 인증 프레임이 관찰되지 않았습니다."),
        "radius": (available["radius_code"], "Access-Accept가 관찰됐습니다.", "Access-Reject가 관찰됐습니다.", "RADIUS 요청·Challenge는 보였지만 최종 결과는 확인하지 못했습니다.", "RADIUS 패킷이 관찰되지 않았습니다. 이것만으로 ClearPass 장애를 뜻하지 않습니다."),
        "dhcp": (available["dhcp_message_type"], "DHCP ACK가 관찰됐습니다.", "DHCP NAK가 관찰됐습니다.", "DHCP 메시지는 보였지만 최종 ACK·NAK는 확인하지 못했습니다.", "DHCP 패킷이 관찰되지 않았습니다."),
        "dns": (available["dns_is_response"], "정상 DNS 응답이 관찰됐습니다.", "오류 DNS 응답이 관찰됐습니다.", "DNS 질의는 보였지만 정상·오류 응답은 확인하지 못했습니다.", "DNS 패킷이 관찰되지 않았습니다."),
        "arp": (available["arp_opcode"], "ARP Reply가 관찰됐습니다.", "", "ARP 패킷은 보였지만 Reply는 확인하지 못했습니다.", "ARP 패킷이 관찰되지 않았습니다."),
        "tcp": (available["tcp_stream"] and available["tcp_syn"], "TCP 3-way Handshake 순서가 관찰됐습니다.", "TCP Reset이 관찰됐습니다.", "TCP 패킷은 보였지만 완전한 Handshake는 확인하지 못했습니다.", "TCP 패킷이 관찰되지 않았습니다."),
    }
    stages = tuple(
        _stage(
            stage,
            stage_specs[stage][0],
            success[stage],
            failure[stage],
            observed[stage],
            stage_specs[stage][1],
            stage_specs[stage][2],
            stage_specs[stage][3],
            stage_specs[stage][4],
        )
        for stage in _STAGE_ORDER
    )
    rank = {"확정": 0, "유력": 1, "참고": 2, "판단 불가": 3}
    findings.sort(key=lambda item: (
        rank.get(item.classification, 99),
        item.evidence_frames[0] if item.evidence_frames else 2**63 - 1,
        item.rule_id,
    ))
    cautions = [
        "판정은 프레임 메타데이터만 사용하며 IP·MAC·SSID·사용자명·Payload를 결과에 기록하지 않습니다.",
        "명시적 실패 응답도 근본 원인 전체를 설명하지 않으므로 장비·서버 로그와 함께 확인해야 합니다.",
    ]
    if not complete:
        cautions.append("전체 프레임을 처리하지 못해 미응답 여부는 판정하지 않았습니다.")
    if profile.missing_optional_fields:
        cautions.append("선택 필드 일부가 없어 해당 단계는 판단 불가 또는 제한된 결과일 수 있습니다.")
    if not has_80211_link_type:
        cautions.append("802.11 Link Type이 없어 Association·Deauthentication 단계는 판단할 수 없습니다.")
    return EventCorrelation(
        profile.profile_id,
        profile.profile_version,
        ruleset_version,
        frames_scanned,
        event_frames,
        complete,
        stages,
        tuple(findings),
        profile.missing_optional_fields,
        tuple(cautions),
    )
