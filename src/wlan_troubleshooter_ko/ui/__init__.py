"""초급 네트워크 엔지니어용 완전 오프라인 Tkinter 화면."""

from wlan_troubleshooter_ko.ui import main_window as _main_window
from wlan_troubleshooter_ko.ui.observability import install as _install_observability

_install_observability(_main_window)

del _install_observability
