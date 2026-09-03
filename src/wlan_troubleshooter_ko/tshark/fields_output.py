"""고정 `-T fields` TSV 출력의 엄격한 스트리밍 파서."""

from __future__ import annotations

from typing import Iterator, List, Tuple

from wlan_troubleshooter_ko.tshark.profiles import ResolvedProfile


_MAX_CELL_CHARACTERS = 1024 * 1024


class FieldsOutputError(ValueError):
    """TShark fields 출력이 프로파일 또는 안전 제한과 다른 경우."""


def _append_checked(characters: List[str], character: str) -> None:
    if character in "\r\n" or ord(character) == 0:
        raise FieldsOutputError("TShark fields 셀에 허용되지 않은 문자가 있습니다.")
    characters.append(character)
    if len(characters) > _MAX_CELL_CHARACTERS:
        raise FieldsOutputError("TShark fields 셀이 안전 제한을 벗어났습니다.")


def _parse_quoted_cell(line: str, position: int) -> Tuple[str, int]:
    characters: List[str] = []
    position += 1
    while position < len(line):
        character = line[position]
        if character == '"':
            if position + 1 < len(line) and line[position + 1] == '"':
                _append_checked(characters, '"')
                position += 2
                continue
            return "".join(characters), position + 1
        _append_checked(characters, character)
        position += 1
    raise FieldsOutputError("TShark fields 셀의 따옴표가 닫히지 않았습니다.")


def _parse_unquoted_cell(line: str, position: int) -> Tuple[str, int]:
    characters: List[str] = []
    while position < len(line) and line[position] != "\t":
        character = line[position]
        if character == '"':
            raise FieldsOutputError(
                "따옴표 없는 TShark fields 셀 안에 이중 따옴표를 사용할 수 없습니다."
            )
        _append_checked(characters, character)
        position += 1
    return "".join(characters), position


def _parse_tshark_tsv_line(line: str) -> Tuple[str, ...]:
    """공식 TShark의 따옴표형·비따옴표형 탭 구분 행을 엄격히 읽는다.

    Wireshark 버전과 필드 형식에 따라 ``-E quote=d``를 지정해도 헤더나
    단순 값이 따옴표 없이 출력될 수 있다. 각 셀은 완전히 따옴표로 감싼
    형식 또는 따옴표가 전혀 없는 형식만 허용하며 두 형식을 한 셀 안에서
    섞는 것은 거부한다.
    """

    if not line:
        return ()
    values: List[str] = []
    position = 0
    length = len(line)
    while True:
        if position < length and line[position] == '"':
            value, position = _parse_quoted_cell(line, position)
            if position < length and line[position] != "\t":
                raise FieldsOutputError(
                    "따옴표가 닫힌 TShark fields 셀 뒤에는 탭만 올 수 있습니다."
                )
        else:
            value, position = _parse_unquoted_cell(line, position)
        values.append(value)

        if position == length:
            break
        if line[position] != "\t":
            raise FieldsOutputError("TShark fields 셀 구분자가 탭이 아닙니다.")
        position += 1
        if position == length:
            values.append("")
            break
    return tuple(values)


def iter_fields_rows(
    text: str,
    profile: ResolvedProfile,
    *,
    max_characters: int = 64 * 1024 * 1024,
) -> Iterator[Tuple[str, ...]]:
    """헤더가 해석된 프로파일과 정확히 일치하는 행만 반환한다."""

    if not isinstance(text, str) or any(ord(character) == 0 for character in text):
        raise FieldsOutputError("TShark fields 출력은 NUL 없는 UTF-8 텍스트여야 합니다.")
    if not 1024 <= max_characters <= 256 * 1024 * 1024 or len(text) > max_characters:
        raise FieldsOutputError("TShark fields 출력이 안전 제한을 초과했습니다.")
    lines = text.splitlines()
    if not lines:
        raise FieldsOutputError("TShark fields 헤더를 읽을 수 없습니다.")
    first_line = lines[0].lstrip("\ufeff")
    header = _parse_tshark_tsv_line(first_line)
    expected = profile.headers()
    if header != expected or len(header) != len(set(header)):
        raise FieldsOutputError("TShark fields 헤더가 승인 프로파일과 일치하지 않습니다.")

    rows = 0
    for raw_line in lines[1:]:
        if not raw_line:
            continue
        row = _parse_tshark_tsv_line(raw_line)
        if not row or all(value == "" for value in row):
            continue
        rows += 1
        if rows > profile.max_packets:
            raise FieldsOutputError("TShark fields 행 수가 프로파일 상한을 초과했습니다.")
        if len(row) != len(expected):
            raise FieldsOutputError("TShark fields 행의 열 수가 헤더와 다릅니다.")
        yield row
