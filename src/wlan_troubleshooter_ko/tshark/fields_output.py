"""고정 `-T fields` TSV 출력의 엄격한 스트리밍 파서."""

from __future__ import annotations

import csv
import io
from typing import Iterator, Tuple

from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


_MAX_CELL_CHARACTERS = 1024 * 1024


class FieldsOutputError(ValueError):
    """TShark fields 출력이 프로파일 또는 안전 제한과 다른 경우."""


def iter_fields_rows(
    text: str,
    profile: ResolvedProfile,
    *,
    max_characters: int = 64 * 1024 * 1024,
) -> Iterator[Tuple[str, ...]]:
    """헤더가 해석된 프로파일과 정확히 일치하는 행만 반환한다."""

    if not isinstance(text, str) or "\x00" in text:
        raise FieldsOutputError("TShark fields 출력은 NUL 없는 UTF-8 텍스트여야 합니다.")
    if not 1024 <= max_characters <= 256 * 1024 * 1024 or len(text) > max_characters:
        raise FieldsOutputError("TShark fields 출력이 안전 제한을 초과했습니다.")
    try:
        reader = csv.reader(
            io.StringIO(text, newline=""),
            delimiter="\t",
            quotechar='"',
            doublequote=True,
            strict=True,
        )
        header = next(reader)
    except (StopIteration, csv.Error):
        raise FieldsOutputError("TShark fields 헤더를 읽을 수 없습니다.") from None
    if header:
        header[0] = header[0].lstrip("\ufeff")
    expected = list(profile.headers())
    if header != expected or len(header) != len(set(header)):
        raise FieldsOutputError("TShark fields 헤더가 승인 프로파일과 일치하지 않습니다.")

    rows = 0
    try:
        for row in reader:
            if not row or all(value == "" for value in row):
                continue
            rows += 1
            if rows > profile.max_packets:
                raise FieldsOutputError("TShark fields 행 수가 프로파일 상한을 초과했습니다.")
            if len(row) != len(expected):
                raise FieldsOutputError("TShark fields 행의 열 수가 헤더와 다릅니다.")
            if any("\x00" in value or len(value) > _MAX_CELL_CHARACTERS for value in row):
                raise FieldsOutputError("TShark fields 셀이 안전 제한을 벗어났습니다.")
            yield tuple(row)
    except csv.Error:
        raise FieldsOutputError("TShark fields 따옴표 또는 구분자 형식이 올바르지 않습니다.") from None
