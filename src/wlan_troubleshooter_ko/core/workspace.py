"""분석 중간 산출물을 격리하고 항상 정리하는 임시 작업공간."""

from __future__ import annotations

import stat
import tempfile
from pathlib import Path
from typing import Optional, Union


_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    "conin$",
    "conout$",
    *("com{0}".format(index) for index in range(1, 10)),
    *("lpt{0}".format(index) for index in range(1, 10)),
    *("com{0}".format(index) for index in ("¹", "²", "³")),
    *("lpt{0}".format(index) for index in ("¹", "²", "³")),
}


class WorkspaceError(ValueError):
    """임시 작업공간 밖으로 나가려는 경로가 요청된 경우."""


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = getattr(metadata, "st_file_attributes", 0) or 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


class AnalysisWorkspace:
    """정상 종료와 예외 종료 모두에서 자동 삭제되는 전용 공간."""

    def __init__(self, base_directory: Optional[Union[str, Path]] = None) -> None:
        self._base_directory = None if base_directory is None else str(base_directory)
        self._temporary: Optional[tempfile.TemporaryDirectory] = None
        self._root: Optional[Path] = None

    def __enter__(self) -> "AnalysisWorkspace":
        self._temporary = tempfile.TemporaryDirectory(
            prefix="wlan-troubleshooter-ko-",
            dir=self._base_directory,
        )
        self._root = Path(self._temporary.name).resolve(strict=True)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.cleanup()

    @property
    def root(self) -> Path:
        if self._root is None:
            raise WorkspaceError("작업공간이 아직 열리지 않았습니다.")
        return self._root

    def allocate(self, relative_name: str) -> Path:
        """작업공간 내부의 안전한 새 경로를 반환한다."""

        if not isinstance(relative_name, str) or not relative_name or "\x00" in relative_name:
            raise WorkspaceError("비어 있거나 잘못된 작업 경로입니다.")
        if "\\" in relative_name:
            raise WorkspaceError("작업 경로 구분자는 슬래시만 사용할 수 있습니다.")
        raw_parts = relative_name.split("/")
        for part in raw_parts:
            device_name = part.split(".", 1)[0].rstrip(" .").casefold()
            if (
                not part
                or part in {".", ".."}
                or part.endswith((" ", "."))
                or any(character in '<>:"|?*' for character in part)
                or any(ord(character) < 32 for character in part)
                or device_name in _WINDOWS_RESERVED_NAMES
            ):
                raise WorkspaceError("Windows에서도 안전한 상대 경로만 사용할 수 있습니다.")
        relative = Path(*raw_parts)
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise WorkspaceError("상대 하위 경로만 사용할 수 있습니다.")
        unresolved_target = self.root / relative
        current = self.root
        for part in relative.parts:
            current = current / part
            if _is_link_or_reparse(current):
                raise WorkspaceError("작업공간 내부의 심볼릭 링크는 사용할 수 없습니다.")
        target = unresolved_target.resolve(strict=False)
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise WorkspaceError("작업공간 밖의 경로는 사용할 수 없습니다.") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        current = self.root
        for part in relative.parts[:-1]:
            current = current / part
            if _is_link_or_reparse(current):
                raise WorkspaceError("작업공간 내부의 심볼릭 링크는 사용할 수 없습니다.")
        if _is_link_or_reparse(target):
            raise WorkspaceError("작업공간 내부의 재분석 지점은 사용할 수 없습니다.")
        if target.exists():
            raise WorkspaceError("기존 작업 산출물 경로는 다시 할당할 수 없습니다.")
        return target

    def cleanup(self) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()
            self._temporary = None
            self._root = None
