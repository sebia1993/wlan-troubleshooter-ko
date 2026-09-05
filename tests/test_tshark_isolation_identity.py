import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from wlan_troubleshooter_ko.tshark import isolation
from wlan_troubleshooter_ko.tshark.errors import TSharkExecutionError


class TSharkIsolationIdentityTests(unittest.TestCase):
    @staticmethod
    def mutable_metadata_changed(snapshot):
        values = list(snapshot)
        values[4] += 4096
        values[5] += 1_000_000
        values[6] += 2_000_000
        values[7] ^= 0x20
        return tuple(values)

    @staticmethod
    def field_changed(snapshot, index, value):
        values = list(snapshot)
        values[index] = value
        return tuple(values)

    def prepared(self, root):
        return isolation._prepare_isolated_environment(root, {})

    def test_validation_ignores_directory_size_times_and_ordinary_attributes(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = self.prepared(Path(directory).resolve() / "isolation")
            changed = replace(
                prepared,
                root_snapshot=self.mutable_metadata_changed(
                    prepared.root_snapshot
                ),
                directory_snapshots=tuple(
                    (path, self.mutable_metadata_changed(snapshot))
                    for path, snapshot in prepared.directory_snapshots
                ),
            )

            isolation._validate_prepared_isolation(changed)

    def test_validation_rejects_changed_directory_object_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = self.prepared(Path(directory).resolve() / "isolation")
            first_path, first_snapshot = prepared.directory_snapshots[0]
            changed_snapshot = self.field_changed(
                first_snapshot,
                1,
                first_snapshot[1] + 1,
            )
            changed = replace(
                prepared,
                directory_snapshots=(
                    (first_path, changed_snapshot),
                    *prepared.directory_snapshots[1:],
                ),
            )

            with self.assertRaises(TSharkExecutionError):
                isolation._validate_prepared_isolation(changed)

    def test_validation_rejects_changed_reparse_state(self):
        with tempfile.TemporaryDirectory() as directory:
            prepared = self.prepared(Path(directory).resolve() / "isolation")
            changed_root = self.field_changed(
                prepared.root_snapshot,
                7,
                prepared.root_snapshot[7] ^ 0x400,
            )
            changed = replace(prepared, root_snapshot=changed_root)

            with self.assertRaises(TSharkExecutionError):
                isolation._validate_prepared_isolation(changed)


if __name__ == "__main__":
    unittest.main()
