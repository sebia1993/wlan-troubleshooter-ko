"""TShark `-G fields` 출력의 제한된 파서."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple


_MAX_LINE_CHARACTERS = 1024 * 1024


class FieldCatalogError(ValueError):
    """TShark 필드 등록 정보가 손상됐거나 허용 범위를 넘은 경우."""


@dataclass(frozen=True)
class RegisteredProtocol:
    name: str
    abbreviation: str


@dataclass(frozen=True)
class RegisteredField:
    name: str
    abbreviation: str
    field_type: str
    parent_protocol: str
    display_base: str
    bitmask: str
    blurb: str


@dataclass(frozen=True)
class FieldCatalog:
    protocols: Tuple[RegisteredProtocol, ...]
    fields: Tuple[RegisteredField, ...]
    records_scanned: int
    characters_scanned: int

    def has_field(self, abbreviation: str) -> bool:
        return any(item.abbreviation == abbreviation for item in self.fields)

    def field_names(self) -> Tuple[str, ...]:
        return tuple(item.abbreviation for item in self.fields)


def _clean_line(raw: str, first: bool) -> str:
    if not isinstance(raw, str):
        raise FieldCatalogError("필드 카탈로그는 UTF-8 텍스트여야 합니다.")
    line = raw.rstrip("\r\n")
    if first:
        line = line.lstrip("\ufeff")
    if "\x00" in line or len(line) > _MAX_LINE_CHARACTERS:
        raise FieldCatalogError("필드 카탈로그 행이 안전 제한을 벗어났습니다.")
    return line


def _protocol_sort_key(item: RegisteredProtocol) -> Tuple[str, ...]:
    return (
        item.abbreviation.casefold(),
        item.abbreviation,
        item.name.casefold(),
        item.name,
    )


def _field_sort_key(item: RegisteredField) -> Tuple[str, ...]:
    return (
        item.abbreviation.casefold(),
        item.abbreviation,
        item.parent_protocol.casefold(),
        item.parent_protocol,
        item.field_type.casefold(),
        item.field_type,
        item.name.casefold(),
        item.name,
        item.display_base,
        item.bitmask,
        item.blurb,
    )


def _keep_canonical(mapping, key: str, item, sort_key) -> None:
    """같은 약어의 여러 공식 등록 중 입력 순서와 무관한 대표값을 유지한다."""

    previous = mapping.get(key)
    if previous is None or sort_key(item) < sort_key(previous):
        mapping[key] = item


def parse_field_catalog(
    lines: Iterable[str],
    *,
    max_records: int = 500_000,
    max_characters: int = 64 * 1024 * 1024,
) -> FieldCatalog:
    """공식 P·F 탭 레코드를 정규화하고 손상된 형식은 거부한다.

    Wireshark 등록 데이터베이스는 같은 프로토콜 또는 필드 약어를 서로
    다른 설명·형식으로 여러 번 노출할 수 있다. Phase 4A는 약어의 존재
    여부만 사용하므로 이를 손상으로 간주하지 않고, 약어별 대표 레코드를
    정렬 키로 선택해 입력 순서와 무관한 결과를 만든다.
    """

    if not 1 <= max_records <= 1_000_000:
        raise FieldCatalogError("필드 카탈로그 레코드 제한이 올바르지 않습니다.")
    if not 1024 <= max_characters <= 256 * 1024 * 1024:
        raise FieldCatalogError("필드 카탈로그 문자 제한이 올바르지 않습니다.")

    protocols: Dict[str, RegisteredProtocol] = {}
    fields: Dict[str, RegisteredField] = {}
    records = 0
    characters = 0
    first = True
    for raw in lines:
        line = _clean_line(raw, first)
        first = False
        characters += len(line) + 1
        if characters > max_characters:
            raise FieldCatalogError("필드 카탈로그 출력이 안전 제한을 초과했습니다.")
        if not line:
            continue
        records += 1
        if records > max_records:
            raise FieldCatalogError("필드 카탈로그 레코드가 안전 제한을 초과했습니다.")
        parts = line.split("\t")
        if parts[0] == "P":
            if len(parts) < 3 or not parts[1] or not parts[2]:
                raise FieldCatalogError("프로토콜 카탈로그 행이 올바르지 않습니다.")
            item = RegisteredProtocol(parts[1], parts[2])
            _keep_canonical(protocols, item.abbreviation, item, _protocol_sort_key)
        elif parts[0] == "F":
            if len(parts) < 7 or not parts[1] or not parts[2] or not parts[3] or not parts[4]:
                raise FieldCatalogError("필드 카탈로그 행이 올바르지 않습니다.")
            item = RegisteredField(
                name=parts[1],
                abbreviation=parts[2],
                field_type=parts[3],
                parent_protocol=parts[4],
                display_base=parts[5],
                bitmask=parts[6],
                blurb="\t".join(parts[7:]) if len(parts) > 7 else "",
            )
            _keep_canonical(fields, item.abbreviation, item, _field_sort_key)
        else:
            raise FieldCatalogError("알 수 없는 필드 카탈로그 레코드입니다.")

    if not protocols or not fields:
        raise FieldCatalogError("필드 카탈로그에 프로토콜 또는 필드가 없습니다.")
    return FieldCatalog(
        protocols=tuple(protocols[key] for key in sorted(protocols, key=str.casefold)),
        fields=tuple(fields[key] for key in sorted(fields, key=str.casefold)),
        records_scanned=records,
        characters_scanned=characters,
    )
