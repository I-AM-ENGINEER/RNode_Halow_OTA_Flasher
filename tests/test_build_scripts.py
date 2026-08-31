import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class BuildScriptsTests(unittest.TestCase):
    def test_linux_build_script_builds_gui_and_cli(self) -> None:
        script = (ROOT / "build_linux.sh").read_text(encoding="utf-8")

        self.assertIn('APP_PY_GUI="rnode-halow-flasher-gui.py"', script)
        self.assertIn('APP_PY_CLI="rnode-halow-flasher.py"', script)
        self.assertIn('SPEC_NAME_GUI="rnode-halow-flasher-gui"', script)
        self.assertIn('SPEC_NAME_CLI="rnode-halow-flasher"', script)

    def test_windows_build_script_builds_gui_and_cli(self) -> None:
        script = (ROOT / "build_win.bat").read_text(encoding="utf-8")

        self.assertIn('set "APP_PY_GUI=rnode-halow-flasher-gui.py"', script)
        self.assertIn('set "APP_PY_CLI=rnode-halow-flasher.py"', script)
        self.assertIn('set "SPEC_NAME_GUI=rnode-halow-flasher-gui"', script)
        self.assertIn('set "SPEC_NAME_CLI=rnode-halow-flasher"', script)

    def test_windows_build_script_keeps_console_only_for_cli(self) -> None:
        script = (ROOT / "build_win.bat").read_text(encoding="utf-8")

        self.assertIn('--name "%SPEC_NAME_GUI%" ^', script)
        self.assertIn('--name "%SPEC_NAME_CLI%" ^', script)
        self.assertIn('--noconsole ^', script)


if __name__ == "__main__":
    unittest.main()
