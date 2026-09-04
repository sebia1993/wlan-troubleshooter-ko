import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.analysis.device_journeys import (
    DeviceJourneyError,
    build_device_journeys,
)


class DeviceJourneyIntegrityTests(unittest.TestCase):
    def attempt(self, evidence=(1, 2)):
        return SimpleNamespace(
            attempt_id="DNS-1-A1",
            protocol="dns",
            state="complete",
            first_frame=1,
            last_frame=2,
            duration_ms=10,
            evidence_frames=tuple(evidence),
            evidence_frames_omitted=0,
            observed_event_types=("dns_query", "dns_response_success"),
            missing_event_types=(),
            next_checks_ko=("DNS 로그 확인",),
            root_cause_confirmed=False,
            device_session_confirmed=False,
        )

    def transaction_report(self, attempt):
        return SimpleNamespace(attempts=(attempt,), complete=True)

    def device_report(
        self,
        attempt,
        *,
        link_evidence=None,
        raw=False,
        secret=False,
        stable=False,
    ):
        evidence = (
            tuple(attempt.evidence_frames)
            if link_evidence is None
            else tuple(link_evidence)
        )
        device = SimpleNamespace(
            alias="DEVICE-1",
            first_frame=1,
            last_frame=2,
            duration_ms=10,
            ap_aliases=("AP-1",),
            linked_attempt_ids=(attempt.attempt_id,),
            device_identity_confirmed=False,
            cross_protocol_session_confirmed=False,
        )
        link = SimpleNamespace(
            attempt_id=attempt.attempt_id,
            state="linked",
            device_alias="DEVICE-1",
            evidence_frames=evidence,
        )
        return SimpleNamespace(
            devices=(device,),
            attempt_links=(link,),
            complete=True,
            raw_identifiers_serialized=raw,
            alias_secret_persisted=secret,
            aliases_stable_across_runs=stable,
        )

    def test_device_report_privacy_flags_must_remain_false(self):
        attempt = self.attempt()
        for values in (
            {"raw": True},
            {"secret": True},
            {"stable": True},
        ):
            with self.subTest(values=values):
                with self.assertRaises(DeviceJourneyError):
                    build_device_journeys(
                        self.device_report(attempt, **values),
                        self.transaction_report(attempt),
                    )

    def test_link_evidence_must_exactly_match_source_attempt(self):
        attempt = self.attempt()
        with self.assertRaises(DeviceJourneyError):
            build_device_journeys(
                self.device_report(attempt, link_evidence=(1,)),
                self.transaction_report(attempt),
            )

    def test_linked_attempt_requires_nonempty_complete_evidence(self):
        empty = self.attempt(evidence=())
        with self.assertRaises(DeviceJourneyError):
            build_device_journeys(
                self.device_report(empty),
                self.transaction_report(empty),
            )

        omitted = self.attempt()
        omitted.evidence_frames_omitted = 1
        with self.assertRaises(DeviceJourneyError):
            build_device_journeys(
                self.device_report(omitted),
                self.transaction_report(omitted),
            )

    def test_valid_link_preserves_all_confirmation_flags_as_false(self):
        attempt = self.attempt()
        report = build_device_journeys(
            self.device_report(attempt),
            self.transaction_report(attempt),
        )
        value = report.to_dict()

        self.assertEqual(value["linked_attempts_total"], 1)
        self.assertFalse(value["raw_identifiers_serialized"])
        self.assertFalse(value["aliases_stable_across_runs"])
        self.assertFalse(value["device_identity_confirmed"])
        self.assertFalse(value["cross_protocol_session_confirmed"])
        self.assertFalse(value["root_cause_confirmed"])
        self.assertFalse(value["journeys"][0]["device_identity_confirmed"])
        self.assertFalse(value["journeys"][0]["cross_protocol_session_confirmed"])
        self.assertFalse(value["journeys"][0]["root_cause_confirmed"])


if __name__ == "__main__":
    unittest.main()
