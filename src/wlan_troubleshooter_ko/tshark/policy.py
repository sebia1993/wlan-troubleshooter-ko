"""저장 캡처 전용 TShark 인자 화이트리스트."""

from pathlib import Path
from typing import Iterable, List

from wlan_troubleshooter_ko.core.capture import validate_capture
from wlan_troubleshooter_ko.tshark.manifest import VerifiedBundle


APPROVED_DISPLAY_FILTERS = {
    "capture-overview": "frame.number >= 1",
}
APPROVED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
)


class TSharkPolicyError(ValueError):
    """저장 파일 전용 실행 정책에 어긋난 요청."""


def assert_safe_argv(arguments: List[str]) -> None:
    if (
        not isinstance(arguments, list)
        or not all(isinstance(argument, str) for argument in arguments)
        or len(arguments) < 11
        or (len(arguments) - 9) % 2
    ):
        raise TSharkPolicyError("TShark 인자 개수와 고정 구조가 올바르지 않습니다.")
    executable = Path(arguments[0])
    if (
        "\x00" in arguments[0]
        or arguments[0].startswith(("\\\\", "//"))
        or not executable.is_absolute()
        or executable.name.casefold() != "tshark.exe"
    ):
        raise TSharkPolicyError("승인된 절대 tshark.exe 경로가 필요합니다.")
    if arguments[1:4] != ["-n", "-2", "-r"]:
        raise TSharkPolicyError("이름 해석 차단과 저장 파일 옵션 순서가 고정돼야 합니다.")
    capture_path = arguments[4]
    lowered_capture = capture_path.casefold()
    if (
        not Path(capture_path).is_absolute()
        or "\x00" in capture_path
        or capture_path.startswith(("\\\\", "//"))
        or lowered_capture.startswith("rpcap")
        or lowered_capture.startswith("tcp@")
        or "://" in lowered_capture
    ):
        raise TSharkPolicyError("검증된 로컬 절대 캡처 경로가 필요합니다.")
    if arguments[5:8] != ["-T", "fields", "-Y"]:
        raise TSharkPolicyError("승인된 fields 출력 순서만 사용할 수 있습니다.")
    if arguments[8] not in APPROVED_DISPLAY_FILTERS.values():
        raise TSharkPolicyError("승인되지 않은 Display Filter입니다.")

    field_values = []
    for index in range(9, len(arguments), 2):
        if arguments[index] != "-e" or arguments[index + 1] not in APPROVED_FIELDS:
            raise TSharkPolicyError("승인되지 않은 TShark 필드 인자입니다.")
        field_values.append(arguments[index + 1])
    canonical_fields = [field for field in APPROVED_FIELDS if field in field_values]
    if field_values != canonical_fields:
        raise TSharkPolicyError("TShark 필드는 중복 없이 고정 순서여야 합니다.")


def build_analysis_argv(
    bundle: VerifiedBundle,
    capture_path: Path,
    display_filter_name: str,
    fields: Iterable[str],
) -> List[str]:
    """사용자 임의 옵션 없이 내부 레지스트리만으로 argv를 만든다."""

    capture = validate_capture(capture_path)
    try:
        display_filter = APPROVED_DISPLAY_FILTERS[display_filter_name]
    except KeyError as exc:
        raise TSharkPolicyError("승인되지 않은 Display Filter입니다.") from exc
    requested_fields = list(fields)
    if not requested_fields or any(field not in APPROVED_FIELDS for field in requested_fields):
        raise TSharkPolicyError("승인되지 않은 TShark 필드입니다.")
    if len(requested_fields) != len(set(requested_fields)):
        raise TSharkPolicyError("중복 TShark 필드를 사용할 수 없습니다.")
    selected_fields = [field for field in APPROVED_FIELDS if field in requested_fields]

    arguments = [
        str(bundle.executable),
        "-n",
        "-2",
        "-r",
        str(capture.path),
        "-T",
        "fields",
        "-Y",
        display_filter,
    ]
    for field in selected_fields:
        arguments.extend(("-e", field))
    assert_safe_argv(arguments)
    return arguments
