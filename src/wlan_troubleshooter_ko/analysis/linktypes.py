"""사전 점검에서 사용하는 보수적인 Link Type 분류."""

LINK_TYPE_NAMES = {
    0: "NULL/Loopback",
    1: "Ethernet",
    9: "PPP",
    12: "Raw IP (legacy)",
    101: "Raw IP",
    105: "IEEE 802.11",
    108: "Loopback",
    113: "Linux cooked capture",
    127: "IEEE 802.11 + Radiotap",
    163: "IEEE 802.11 + AVS",
    192: "PPI",
    276: "Linux cooked capture v2",
}

WLAN_LINK_TYPES = frozenset({105, 127, 163})
RADIOTAP_LINK_TYPES = frozenset({127})
PPI_LINK_TYPES = frozenset({192})
IP_PATH_LINK_TYPES = frozenset({0, 1, 9, 12, 101, 105, 108, 113, 127, 163, 276})


def link_type_name(link_type: int) -> str:
    return LINK_TYPE_NAMES.get(link_type, "알 수 없는 Link Type")
