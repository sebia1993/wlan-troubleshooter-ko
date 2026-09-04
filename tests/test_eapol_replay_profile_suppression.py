import unittest

from wlan_troubleshooter_ko.tshark.profiles import (
    ResolvedField,
    ResolvedProfile,
)
from wlan_troubleshooter_ko.tshark.replay_analysis import (
    _suppress_counter_without_message,
)


class EapolReplayProfileSuppressionTests(unittest.TestCase):
    def profile(self, *, missing=()):
        return ResolvedProfile(
            profile_id="eapol-replay-relations",
            profile_version="0.6.0",
            display_filter_name="capture-overview",
            max_packets=100_000,
            fields=(
                ResolvedField("frame_number", "frame.number"),
                ResolvedField(
                    "eapol_replay_counter",
                    "eapol.keydes.replay_counter",
                ),
            ),
            missing_optional_fields=tuple(missing),
        )

    def test_counter_field_is_removed_when_message_field_is_missing(self):
        source = self.profile(missing=("eapol_key_message",))
        result = _suppress_counter_without_message(source)

        self.assertEqual(result.output_keys(), ("frame_number",))
        self.assertEqual(
            result.missing_optional_fields,
            ("eapol_key_message", "eapol_replay_counter"),
        )
        self.assertEqual(source.output_keys(), (
            "frame_number",
            "eapol_replay_counter",
        ))

    def test_available_message_field_keeps_counter_field(self):
        source = self.profile()
        self.assertIs(_suppress_counter_without_message(source), source)


if __name__ == "__main__":
    unittest.main()
