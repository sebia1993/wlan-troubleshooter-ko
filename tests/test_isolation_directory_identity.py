import stat
import unittest

from wlan_troubleshooter_ko.tshark.isolation_path import (
    _REPARSE_POINT_FLAG,
    _same_directory_identity,
    _stat_snapshot,
)


class FakeDirectoryStat:
    def __init__(
        self,
        *,
        device=1,
        inode=2,
        mode=None,
        links=1,
        size=0,
        modified_ns=10,
        changed_ns=20,
        attributes=0x10,
    ):
        self.st_dev = device
        self.st_ino = inode
        self.st_mode = stat.S_IFDIR | 0o700 if mode is None else mode
        self.st_nlink = links
        self.st_size = size
        self.st_mtime = modified_ns / 1_000_000_000
        self.st_ctime = changed_ns / 1_000_000_000
        self.st_mtime_ns = modified_ns
        self.st_ctime_ns = changed_ns
        self.st_file_attributes = attributes


class IsolationDirectoryIdentityTests(unittest.TestCase):
    def expected(self):
        return _stat_snapshot(FakeDirectoryStat())

    def test_archive_timestamp_and_size_changes_do_not_mean_replacement(self):
        current = FakeDirectoryStat(
            size=4096,
            modified_ns=999,
            changed_ns=1000,
            attributes=0x10 | 0x20,
        )
        self.assertTrue(_same_directory_identity(current, self.expected()))

    def test_device_inode_type_and_link_count_still_define_identity(self):
        changes = (
            FakeDirectoryStat(device=9),
            FakeDirectoryStat(inode=9),
            FakeDirectoryStat(mode=stat.S_IFREG | 0o600),
            FakeDirectoryStat(links=2),
        )
        for current in changes:
            with self.subTest(current=current):
                self.assertFalse(_same_directory_identity(current, self.expected()))

    def test_reparse_point_transition_is_never_accepted(self):
        current = FakeDirectoryStat(attributes=0x10 | _REPARSE_POINT_FLAG)
        self.assertFalse(_same_directory_identity(current, self.expected()))


if __name__ == "__main__":
    unittest.main()
