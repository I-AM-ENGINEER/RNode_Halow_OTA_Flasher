import importlib.util
import queue
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from app.models import ServiceEvent


def _load_gui_module():
    fake_tk = types.ModuleType("tkinter")
    fake_tk.END = "end"
    fake_tk.WORD = "word"
    fake_tk.TOP = "top"
    fake_tk.BOTTOM = "bottom"
    fake_tk.LEFT = "left"
    fake_tk.RIGHT = "right"
    fake_tk.X = "x"
    fake_tk.BOTH = "both"
    fake_tk.HORIZONTAL = "horizontal"
    fake_tk.W = "w"

    class _FakeTk:
        pass

    class _FakeWidget:
        def __init__(self, *args, **kwargs):
            pass

    fake_tk.Tk = _FakeTk
    fake_tk.Frame = _FakeWidget
    fake_tk.Label = _FakeWidget
    fake_tk.Text = _FakeWidget
    fake_tk.BooleanVar = _FakeWidget
    fake_tk.DoubleVar = _FakeWidget
    fake_tk.StringVar = _FakeWidget

    fake_ttk = types.ModuleType("tkinter.ttk")
    for name in (
        "LabelFrame",
        "Frame",
        "Button",
        "Radiobutton",
        "Combobox",
        "Checkbutton",
        "Entry",
        "Spinbox",
        "Treeview",
        "Progressbar",
        "Label",
    ):
        setattr(fake_ttk, name, _FakeWidget)

    fake_filedialog = types.ModuleType("tkinter.filedialog")
    fake_filedialog.askopenfilename = lambda **_kwargs: ""

    fake_messagebox = types.ModuleType("tkinter.messagebox")
    fake_messagebox.showerror = lambda *args, **kwargs: None
    fake_messagebox.showinfo = lambda *args, **kwargs: None
    fake_messagebox.showwarning = lambda *args, **kwargs: None
    fake_messagebox.askyesno = lambda *args, **kwargs: False

    root = Path(__file__).resolve().parents[1]
    path = root / "rnode-halow-flasher-gui.py"
    spec = importlib.util.spec_from_file_location("rnode_halow_flasher_gui", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None
    assert spec.loader is not None
    with patch.dict(
        sys.modules,
        {
            "tkinter": fake_tk,
            "tkinter.ttk": fake_ttk,
            "tkinter.filedialog": fake_filedialog,
            "tkinter.messagebox": fake_messagebox,
        },
    ):
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


class GuiAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gui = _load_gui_module()

    def test_should_require_preflash_for_ota_updates(self) -> None:
        self.assertTrue(self.gui.should_require_preflash("ota"))
        self.assertFalse(self.gui.should_require_preflash("bin"))

    def test_flash_selected_requires_preflash_for_rnode_ota(self) -> None:
        app = self.gui.App.__new__(self.gui.App)
        app._busy = threading.Event()
        app._set_busy = lambda *_args, **_kwargs: None
        app._set_progress = lambda *_args, **_kwargs: None
        app._flash_worker = lambda *_args, **_kwargs: None
        app._ensure_selected = lambda: self.gui.DevRow(
            mac="aa:aa:aa:aa:aa:aa",
            iface="eth0",
            iface_id="if0",
            kind="rnode-halow",
        )
        app._ensure_fw_selection = lambda: self.gui.FirmwareSelection(
            source="github",
            mode="ota",
            path=Path("/tmp/fw.tar"),
            label="fw.tar",
            github_tag="v1.2.3",
        )

        thread = Mock()

        with patch.object(self.gui.messagebox, "askyesno", return_value=True), \
             patch.object(self.gui.messagebox, "showerror") as showerror, \
             patch.object(self.gui, "pick_preflash_firmware_name", side_effect=FileNotFoundError("missing preflash")), \
             patch.object(self.gui.threading, "Thread", return_value=thread):
            app._flash_selected()

        showerror.assert_called_once()
        thread.start.assert_not_called()

    def test_device_changed_only_logs_and_device_ip_keeps_current_key(self) -> None:
        app = self.gui.App.__new__(self.gui.App)
        app._q = queue.Queue()
        app._rows = {}
        app._tree_items = {}
        app._selected_key = None

        row = self.gui.DevRow(mac="aa:aa:aa:aa:aa:aa", iface="eth0", iface_id="if0", kind="hgic")
        app._rows[row.key()] = row
        app._tree_items[row.key()] = "item-1"
        app._selected_key = row.key()

        app._emit_service_event(
            row,
            ServiceEvent(
                kind="device_changed",
                message="target MAC changed: aa:aa:aa:aa:aa:aa -> bb:bb:bb:bb:bb:bb",
                data={"old_mac": "aa:aa:aa:aa:aa:aa", "new_mac": "bb:bb:bb:bb:bb:bb"},
            ),
        )

        app._emit_service_event(
            row,
            ServiceEvent(
                kind="device_ip",
                message="192.168.1.50",
                data={"ip": "192.168.1.50", "mac": "bb:bb:bb:bb:bb:bb"},
            ),
        )

        queued = [app._q.get_nowait(), app._q.get_nowait()]

        self.assertEqual(queued[0][0], "log")
        self.assertEqual(queued[-1][0], "devinfo")
        self.assertEqual(queued[-1][1][0], ("aa:aa:aa:aa:aa:aa", "if0"))


if __name__ == "__main__":
    unittest.main()
