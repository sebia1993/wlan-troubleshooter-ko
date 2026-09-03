import math
from pathlib import Path
import tempfile
import unittest

from wlan_troubleshooter_ko.core.canonical_json import CanonicalJsonError, dump_file, dumps


class CanonicalJsonTests(unittest.TestCase):
    def test_dictionary_order_does_not_change_output(self):
        first = {"나": [3, 2, 1], "가": {"y": 2, "x": 1}}
        second = {"가": {"x": 1, "y": 2}, "나": [3, 2, 1]}

        self.assertEqual(dumps(first), dumps(second))
        self.assertTrue(dumps(first).endswith("\n"))

    def test_non_finite_number_is_rejected(self):
        with self.assertRaises(CanonicalJsonError):
            dumps({"value": math.nan})

    def test_unicode_is_normalized_and_key_collision_is_rejected(self):
        composed = "한글 é"
        decomposed = "한글 e\u0301"
        self.assertEqual(dumps({"text": composed}), dumps({"text": decomposed}))

        with self.assertRaises(CanonicalJsonError):
            dumps({"é": 1, "e\u0301": 2})

    def test_unpaired_surrogate_is_rejected(self):
        with self.assertRaises(CanonicalJsonError):
            dumps({"text": "\ud800"})

    def test_dump_file_is_fixed_utf8_lf_and_preserves_existing_on_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            dump_file(path, {"나": 1})
            self.assertEqual('{"나":1}\n'.encode("utf-8"), path.read_bytes())

            path.write_bytes(b"sentinel")
            with self.assertRaises(CanonicalJsonError):
                dump_file(path, {"value": math.nan})
            self.assertEqual(b"sentinel", path.read_bytes())


if __name__ == "__main__":
    unittest.main()
