import json
import tempfile
import unittest
from pathlib import Path

from wlan_troubleshooter_ko.tshark.catalog import FieldCatalogError, parse_field_catalog
from wlan_troubleshooter_ko.tshark.fields_output import FieldsOutputError, iter_fields_rows
from wlan_troubleshooter_ko.tshark.profiles import (
    FieldCompatibilityError,
    FieldProfileError,
    load_field_profiles,
    resolve_profile,
)


CATALOG_LINES = [
    "P\tFrame\tframe\n",
    "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tInterface id\tframe.interface_id\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tCapture Length\tframe.cap_len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tFrame Length\tframe.len\tFT_UINT32\tframe\tBASE_DEC\t0x0\t\n",
    "F\tProtocols in frame\tframe.protocols\tFT_STRING\tframe\t\t0x0\t\n",
]


class TSharkCatalogTests(unittest.TestCase):
    def registry_path(self):
        return (
            Path(__file__).resolve().parents[1]
            / "src"
            / "wlan_troubleshooter_ko"
            / "resources"
            / "tshark"
            / "field-profiles.v1.json"
        )

    def resolved_profile(self):
        return resolve_profile(
            load_field_profiles(self.registry_path()),
            parse_field_catalog(CATALOG_LINES),
            "protocol-inventory",
        )

    def test_catalog_and_profile_resolve_deterministically(self):
        catalog = parse_field_catalog(CATALOG_LINES)
        registry = load_field_profiles(self.registry_path())
        resolved = resolve_profile(registry, catalog, "protocol-inventory")
        self.assertEqual(resolved.profile_version, "0.2.0")
        self.assertEqual(resolved.headers()[0], "frame.number")
        self.assertEqual(resolved.output_keys()[-1], "protocols")
        self.assertEqual(resolved.missing_optional_fields, ())
        self.assertTrue(catalog.has_field("frame.protocols"))

    def test_missing_optional_field_is_recorded(self):
        catalog = parse_field_catalog(
            [line for line in CATALOG_LINES if "frame.interface_id" not in line]
        )
        resolved = resolve_profile(
            load_field_profiles(self.registry_path()),
            catalog,
            "protocol-inventory",
        )
        self.assertEqual(resolved.missing_optional_fields, ("interface_id",))
        self.assertNotIn("frame.interface_id", resolved.headers())

    def test_missing_required_field_fails_closed(self):
        catalog = parse_field_catalog(
            [line for line in CATALOG_LINES if "frame.protocols" not in line]
        )
        with self.assertRaises(FieldCompatibilityError):
            resolve_profile(
                load_field_profiles(self.registry_path()),
                catalog,
                "protocol-inventory",
            )

    def test_catalog_normalizes_reused_abbreviations_and_rejects_unknown_record(self):
        aliases = CATALOG_LINES + [
            "P\tAlternate Frame Description\tframe\n",
            "F\tAlternate Frame Number\tframe.number\tFT_STRING\tframe\t\t0x0\t\n",
        ]
        forward = parse_field_catalog(aliases)
        reverse = parse_field_catalog(reversed(aliases))

        self.assertEqual(forward.protocols, reverse.protocols)
        self.assertEqual(forward.fields, reverse.fields)
        self.assertEqual(
            [item.abbreviation for item in forward.protocols].count("frame"),
            1,
        )
        self.assertEqual(forward.field_names().count("frame.number"), 1)
        self.assertTrue(forward.has_field("frame.number"))

        with self.assertRaises(FieldCatalogError):
            parse_field_catalog(CATALOG_LINES + ["X\tunknown\n"])

    def test_catalog_rejects_limits_and_nul(self):
        with self.assertRaises(FieldCatalogError):
            parse_field_catalog(CATALOG_LINES, max_records=2)
        with self.assertRaises(FieldCatalogError):
            parse_field_catalog(CATALOG_LINES + ["F\tBad\tbad.field\x00\tFT_STRING\tbad\t\t0x0\t\n"])

    def test_profile_loader_rejects_unknown_key_and_duplicate_json_key(self):
        original = json.loads(self.registry_path().read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            unknown = Path(directory) / "unknown.json"
            changed = dict(original)
            changed["unexpected"] = True
            unknown.write_text(json.dumps(changed, ensure_ascii=False), encoding="utf-8")
            with self.assertRaises(FieldProfileError):
                load_field_profiles(unknown)

            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text(
                '{"schema_version":1,"schema_version":1,"profile_version":"0.2.0","profiles":[],"protocol_groups":[]}',
                encoding="utf-8",
            )
            with self.assertRaises(FieldProfileError):
                load_field_profiles(duplicate)

    def test_fields_output_accepts_quoted_unquoted_and_mixed_cells(self):
        profile = self.resolved_profile()
        quoted_header = "\t".join('"{0}"'.format(item) for item in profile.headers())
        quoted_row = '"1"\t"0"\t"100"\t"100"\t"eth:ip:udp:dns"'
        self.assertEqual(
            list(iter_fields_rows(quoted_header + "\n" + quoted_row + "\n", profile)),
            [("1", "0", "100", "100", "eth:ip:udp:dns")],
        )

        plain_header = "\t".join(profile.headers())
        plain_row = "1\t0\t100\t100\teth:ip:udp:dns"
        self.assertEqual(
            list(iter_fields_rows(plain_header + "\n" + plain_row + "\n", profile)),
            [("1", "0", "100", "100", "eth:ip:udp:dns")],
        )

        mixed_header = (
            '"frame.number"\tframe.interface_id\t"frame.cap_len"\t'
            'frame.len\t"frame.protocols"'
        )
        mixed_row = '"1"\t\t"100"\t100\teth:arp'
        self.assertEqual(
            list(iter_fields_rows(mixed_header + "\n" + mixed_row + "\n", profile)),
            [("1", "", "100", "100", "eth:arp")],
        )

    def test_fields_output_rejects_ambiguous_quotes_and_wrong_header(self):
        profile = self.resolved_profile()
        header = "\t".join(profile.headers())
        with self.assertRaises(FieldsOutputError):
            list(
                iter_fields_rows(
                    header + '\n1\t0\t100\t100\teth:"dns"\n',
                    profile,
                )
            )
        with self.assertRaises(FieldsOutputError):
            list(
                iter_fields_rows(
                    header + '\n"1"x\t0\t100\t100\teth:dns\n',
                    profile,
                )
            )
        with self.assertRaises(FieldsOutputError):
            list(iter_fields_rows('frame.protocols\ndns\n', profile))


if __name__ == "__main__":
    unittest.main()
