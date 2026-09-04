import json
import unittest
from types import SimpleNamespace

from wlan_troubleshooter_ko.analysis.eapol_replay_relations import (
    EapolReplayRelationError,
    build_eapol_replay_relations,
)
from wlan_troubleshooter_ko.tshark.profiles import ResolvedField, ResolvedProfile


class EapolReplayRelationTests(unittest.TestCase):
    def profile(self, *, counter=True, missing=()):
        fields = [
            ResolvedField("frame_number", "frame.number"),
            ResolvedField(
                "eapol_key_message",
                "wlan_rsna_eapol.keydes.msgnr",
            ),
        ]
        if counter:
            fields.append(
                ResolvedField(
                    "eapol_replay_counter",
                    "eapol.keydes.replay_counter",
                )
            )
        return ResolvedProfile(
            profile_id="eapol-replay-relations",
            profile_version="0.6.0",
            display_filter_name="capture-overview",
            max_packets=100_000,
            fields=tuple(fields),
            missing_optional_fields=tuple(missing),
        )

    def observation(
        self,
        *,
        frames=(5, 6, 7, 8, 9),
        messages=(1, 2, 3, 3, 4),
        omitted=0,
        raw_key=False,
        raw_id=False,
        same=False,
        install=False,
        crypto=False,
        root=False,
    ):
        return SimpleNamespace(
            observation_id="EAPOL-HS-1",
            device_alias="DEVICE-1",
            ap_alias="AP-1",
            event_count=len(messages),
            evidence_frames=tuple(frames),
            evidence_frames_omitted=omitted,
            observed_message_numbers=tuple(messages),
            raw_key_material_serialized=raw_key,
            raw_identifiers_serialized=raw_id,
            same_handshake_confirmed=same,
            key_installation_confirmed=install,
            cryptographic_success_confirmed=crypto,
            root_cause_confirmed=root,
        )

    def report(self, observation=None, *, complete=True, **flags):
        value = self.observation() if observation is None else observation
        return SimpleNamespace(
            observations=(value,),
            complete=complete,
            raw_key_material_serialized=flags.get("raw_key", False),
            raw_identifiers_serialized=flags.get("raw_id", False),
            same_handshake_confirmed=flags.get("same", False),
            key_installation_confirmed=flags.get("install", False),
            cryptographic_success_confirmed=flags.get("crypto", False),
            root_cause_confirmed=flags.get("root", False),
        )

    def text(self, rows, *, counter=True):
        headers = [
            "frame.number",
            "wlan_rsna_eapol.keydes.msgnr",
        ]
        if counter:
            headers.append("eapol.keydes.replay_counter")
        lines = ["\t".join('"' + item + '"' for item in headers)]
        for row in rows:
            lines.append("\t".join('"' + str(item) + '"' for item in row))
        return "\n".join(lines) + "\n"

    def expected_rows(self):
        return (
            (1, "", ""),
            (5, 1, 10),
            (6, 2, 10),
            (7, 3, 11),
            (8, 3, 11),
            (9, 4, 11),
        )

    def test_expected_pairs_progression_and_repeated_same_counter(self):
        result = build_eapol_replay_relations(
            self.text(self.expected_rows()),
            self.profile(),
            self.report(),
        )
        item = result.observations[0]

        self.assertTrue(result.complete)
        self.assertTrue(result.field_available)
        self.assertEqual(result.rows_observed, 6)
        self.assertEqual(result.key_rows_observed, 5)
        self.assertEqual(item.state, "expected-relations-observed")
        self.assertEqual(item.m1_m2_relation, "equal-observed")
        self.assertEqual(item.m3_m4_relation, "equal-observed")
        self.assertEqual(item.m1_m3_progression, "increased-observed")
        self.assertEqual(len(item.repeated_message_relations), 1)
        self.assertEqual(item.repeated_message_relations[0].message_number, 3)
        self.assertEqual(
            item.repeated_message_relations[0].state,
            "same-counter-observed",
        )
        self.assertEqual(item.frames_with_counter, (5, 6, 7, 8, 9))
        self.assertEqual(item.missing_counter_frames, ())

    def test_pair_mismatch_is_observed_without_root_cause_claim(self):
        rows = list(self.expected_rows())
        rows[2] = (6, 2, 12)
        result = build_eapol_replay_relations(
            self.text(rows),
            self.profile(),
            self.report(),
        )
        item = result.observations[0]

        self.assertEqual(item.state, "relation-mismatch-observed")
        self.assertEqual(item.m1_m2_relation, "mismatch-observed")
        self.assertFalse(item.same_handshake_confirmed)
        self.assertFalse(item.retransmission_confirmed)
        self.assertFalse(item.key_installation_confirmed)
        self.assertFalse(item.cryptographic_success_confirmed)
        self.assertFalse(item.root_cause_confirmed)

    def test_repeated_message_with_different_counter_is_not_retransmission(self):
        rows = list(self.expected_rows())
        rows[4] = (8, 3, 12)
        item = build_eapol_replay_relations(
            self.text(rows),
            self.profile(),
            self.report(),
        ).observations[0]

        self.assertEqual(item.state, "relation-mismatch-observed")
        repeated = item.repeated_message_relations[0]
        self.assertEqual(repeated.state, "different-counters-observed")
        self.assertFalse(item.retransmission_confirmed)

    def test_missing_counter_field_is_unavailable_not_zero(self):
        profile = self.profile(
            counter=False,
            missing=("eapol_replay_counter",),
        )
        text = self.text(
            tuple((row[0], row[1]) for row in self.expected_rows()),
            counter=False,
        )
        result = build_eapol_replay_relations(
            text,
            profile,
            self.report(),
        )

        self.assertFalse(result.field_available)
        self.assertFalse(result.complete)
        self.assertEqual(result.observations[0].state, "unavailable")
        self.assertEqual(
            result.observations[0].m1_m2_relation,
            "unavailable",
        )

    def test_missing_counter_row_makes_partial_result(self):
        rows = [row for row in self.expected_rows() if row[0] != 8]
        item = build_eapol_replay_relations(
            self.text(rows),
            self.profile(),
            self.report(),
        ).observations[0]

        self.assertEqual(item.state, "partial")
        self.assertEqual(item.missing_counter_frames, (8,))
        self.assertFalse(item.retransmission_confirmed)

    def test_observation_with_omitted_evidence_remains_partial(self):
        observation = self.observation(
            frames=(5, 6, 7, 8),
            messages=(1, 2, 3, 3, 4),
            omitted=1,
        )
        item = build_eapol_replay_relations(
            self.text(self.expected_rows()),
            self.profile(),
            self.report(observation, complete=False),
        ).observations[0]

        self.assertEqual(item.state, "partial")
        self.assertFalse(item.same_handshake_confirmed)

    def test_message_number_mismatch_fails_closed(self):
        rows = list(self.expected_rows())
        rows[1] = (5, 2, 10)
        with self.assertRaises(EapolReplayRelationError):
            build_eapol_replay_relations(
                self.text(rows),
                self.profile(),
                self.report(),
            )

    def test_counter_overflow_and_counter_without_message_fail_closed(self):
        cases = (
            ((5, 1, 1 << 64),),
            ((5, "", 10),),
        )
        for rows in cases:
            with self.subTest(rows=rows):
                with self.assertRaises(EapolReplayRelationError):
                    build_eapol_replay_relations(
                        self.text(rows),
                        self.profile(),
                        self.report(),
                    )

    def test_source_privacy_or_confirmation_flag_change_fails_closed(self):
        for flags in (
            {"raw_key": True},
            {"raw_id": True},
            {"same": True},
            {"install": True},
            {"crypto": True},
            {"root": True},
        ):
            with self.subTest(flags=flags):
                with self.assertRaises(EapolReplayRelationError):
                    build_eapol_replay_relations(
                        self.text(self.expected_rows()),
                        self.profile(),
                        self.report(**flags),
                    )

    def test_serialization_contains_relationships_but_no_counter_values(self):
        secret_counter = 18_446_744_073_709_551_614
        rows = (
            (5, 1, secret_counter - 1),
            (6, 2, secret_counter - 1),
            (7, 3, secret_counter),
            (8, 3, secret_counter),
            (9, 4, secret_counter),
        )
        first = build_eapol_replay_relations(
            self.text(rows),
            self.profile(),
            self.report(),
        ).to_dict()
        second = build_eapol_replay_relations(
            self.text(rows),
            self.profile(),
            self.report(),
        ).to_dict()
        rendered = json.dumps(first, ensure_ascii=False)

        self.assertEqual(first, second)
        self.assertIn("expected-relations-observed", rendered)
        self.assertIn("equal-observed", rendered)
        self.assertIn("increased-observed", rendered)
        self.assertNotIn(str(secret_counter), rendered)
        self.assertNotIn(str(secret_counter - 1), rendered)
        self.assertFalse(first["raw_replay_counters_serialized"])
        self.assertFalse(first["replay_counter_values_persisted"])
        self.assertFalse(first["same_handshake_confirmed"])
        self.assertFalse(first["retransmission_confirmed"])
        self.assertFalse(first["key_installation_confirmed"])
        self.assertFalse(first["cryptographic_success_confirmed"])
        self.assertFalse(first["root_cause_confirmed"])


if __name__ == "__main__":
    unittest.main()
