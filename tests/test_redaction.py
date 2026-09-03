import json
import unittest

from wlan_troubleshooter_ko.core.logging_policy import UnsafeLogRecord, build_log_record
from wlan_troubleshooter_ko.core.redaction import redact_text


class RedactionTests(unittest.TestCase):
    def test_sensitive_canaries_are_removed(self):
        raw = (
            "Authorization: Bearer-value Cookie=session-value "
            "password=hunter2 person@example.invalid AA:BB:CC:DD:EE:FF "
            "10.20.30.40 /Users/private-user/capture.pcap "
            + "a" * 40
        )

        redacted = redact_text(raw)

        for canary in (
            "Bearer-value",
            "session-value",
            "hunter2",
            "person@example.invalid",
            "AA:BB:CC:DD:EE:FF",
            "10.20.30.40",
            "private-user",
            "a" * 40,
        ):
            self.assertNotIn(canary, redacted)

    def test_log_allowlist_rejects_user_identifier(self):
        with self.assertRaises(UnsafeLogRecord):
            build_log_record("analysis.started", user_id="employee")

        with self.assertRaises(UnsafeLogRecord):
            build_log_record("analysis.started", detail="arbitrary packet text")

        with self.assertRaises(UnsafeLogRecord):
            build_log_record("user.employee-73", status="ok")

    def test_structured_secrets_ipv6_and_cross_platform_paths_are_removed(self):
        canaries = (
            'Authorization: Bearer VERYSECRET',
            '{"Authorization":"Bearer topsecret"}',
            '{"user_id":"employee-73"}',
            'user_id="Jane Doe"',
            "2001:db8:85a3::8a2e:370:7334",
            r"C:\Users\private-user\capture.pcap",
            "C:/Users/private-user/capture.pcap",
            r"\\server\share\customer\capture.pcap",
            "/opt/internal/capture.pcap",
            "aabb.ccdd.eeff",
            '{"user_id":\n "employee-73"}',
        )
        redacted = redact_text("\n".join(canaries))
        for canary in (
            "VERYSECRET",
            "topsecret",
            "employee-73",
            "Jane Doe",
            "2001:db8:85a3::8a2e:370:7334",
            "private-user",
            "server",
            "internal",
            "aabb.ccdd.eeff",
        ):
            self.assertNotIn(canary, redacted)

    def test_safe_metadata_is_canonical_json(self):
        digest = "b" * 64
        record = json.loads(
            build_log_record(
                "capture.validated",
                status="ok",
                size_bytes=24,
                input_sha256=digest,
            )
        )
        self.assertEqual(record["input_sha256"], digest)
        self.assertEqual(record["size_bytes"], 24)

        for invalid_fields in (
            {"input_sha256": 123},
            {"input_sha256": None},
            {"size_bytes": True},
            {"size_bytes": -1},
            {"status": 42},
            {"status": "employee-73"},
            {"ruleset_version": "employee-73"},
            {"error_code": "employee-73"},
        ):
            with self.subTest(fields=invalid_fields):
                with self.assertRaises(UnsafeLogRecord):
                    build_log_record("capture.validated", **invalid_fields)


if __name__ == "__main__":
    unittest.main()
