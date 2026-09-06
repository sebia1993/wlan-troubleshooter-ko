"""초급 네트워크 엔지니어용 완전 오프라인 Tkinter 화면."""

from wlan_troubleshooter_ko.ui import main_window as _main_window
from wlan_troubleshooter_ko.ui.capture_time_boundaries import (
    install as _install_capture_time_boundaries,
)
from wlan_troubleshooter_ko.ui.eapol_handshakes import (
    install as _install_eapol_handshakes,
)
from wlan_troubleshooter_ko.ui.eapol_replay_relations import (
    install as _install_eapol_replay_relations,
)
from wlan_troubleshooter_ko.ui.observability import install as _install_observability
from wlan_troubleshooter_ko.ui.pcapng_interface_statistics import (
    install as _install_pcapng_interface_statistics,
)

_install_observability(_main_window)
_install_eapol_handshakes(_main_window)
_install_eapol_replay_relations(_main_window)
_install_pcapng_interface_statistics(_main_window)
_install_capture_time_boundaries(_main_window)

del _install_observability
del _install_eapol_handshakes
del _install_eapol_replay_relations
del _install_pcapng_interface_statistics
del _install_capture_time_boundaries
