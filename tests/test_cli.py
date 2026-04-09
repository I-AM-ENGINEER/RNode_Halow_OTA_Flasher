import io
import json
import subprocess
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from app.github import GhAsset, GhRelease
from app.models import DeviceRow, FirmwareSelection, ServiceEvent
from app.cli import build_parser, main


class FakeService:
    def __init__(self) -> None:
        self.rows = [
            DeviceRow(mac="aa:aa:aa:aa:aa:aa", iface="eth0", iface_id="if0", kind="hgic"),
        ]
        self.releases = [
            GhRelease(
                tag="v1.2.3",
                prerelease=False,
                assets=[GhAsset(name="firmware.tar", size=123, url="https://example/firmware.tar")],
            ),
            GhRelease(
                tag="v1.2.2",
                prerelease=False,
                assets=[GhAsset(name="firmware.bin", size=111, url="https://example/firmware.bin")],
            ),
            GhRelease(
                tag="v1.2.1",
                prerelease=False,
                assets=[GhAsset(name="firmware.tar", size=100, url="https://example/firmware-121.tar")],
            ),
        ]
        self.calls = []
        self.raise_on_select = None
        self.environment_messages = []

    def validate_environment(self):
        self.calls.append(("validate_environment",))
        return list(self.environment_messages)

    def scan_devices(self, **_kwargs):
        return self.rows, {row.key() for row in self.rows}

    def select_target(self, rows, *, mac, iface=None):
        self.calls.append(("select_target", mac, iface))
        if self.raise_on_select is not None:
            raise self.raise_on_select
        return rows[0]

    def list_releases(self, stable_only=False):
        self.calls.append(("list_releases", stable_only))
        if stable_only:
            return [release for release in self.releases if not release.prerelease]
        return self.releases

    def update_device(self, target, firmware, *, known_rows):
        self.calls.append(("update_device", target.mac, firmware.source, firmware.mode, firmware.path, firmware.github_tag))
        return [ServiceEvent(kind="done", message="flash done")]

    def raw_flash(self, target, firmware, *, known_rows):
        self.calls.append(("raw_flash", target.mac, firmware.mode, firmware.path))
        return [ServiceEvent(kind="done", message="RAW flash done")]

    def get_ip(self, target):
        self.calls.append(("get_ip", target.mac))
        return SimpleNamespace(ip="192.168.1.55", gw="192.168.1.1", mask="255.255.255.0", status=0, version="1.0.0")

    def reboot_device(self, target, *, known_rows):
        self.calls.append(("reboot_device", target.mac))
        return [ServiceEvent(kind="done", message="reboot sent")]

    def open_web(self, target):
        self.calls.append(("open_web", target.mac))
        return True


class CliTests(unittest.TestCase):
    def test_parser_accepts_supported_commands(self) -> None:
        parser = build_parser()

        parser.parse_args(["scan"])
        parser.parse_args(["releases"])
        parser.parse_args(["update", "--mac", "aa:aa:aa:aa:aa:aa", "--release", "latest"])
        parser.parse_args(["update", "--mac", "aa:aa:aa:aa:aa:aa", "--file", "/tmp/fw.tar"])
        parser.parse_args(["raw-flash", "--mac", "aa:aa:aa:aa:aa:aa", "--file", "/tmp/fw.bin"])
        parser.parse_args(["raw-flash", "--mac", "aa:aa:aa:aa:aa:aa", "--release", "latest"])
        parser.parse_args(["get-ip", "--mac", "aa:aa:aa:aa:aa:aa"])
        parser.parse_args(["reboot", "--mac", "aa:aa:aa:aa:aa:aa"])
        parser.parse_args(["open-web", "--mac", "aa:aa:aa:aa:aa:aa"])
        parser.parse_args(["wizard"])

    def test_scan_json_outputs_structured_rows(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()

        exit_code = main(["scan", "--json"], service=service, stdout=out, stderr=err)

        self.assertEqual(exit_code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["devices"][0]["mac"], "aa:aa:aa:aa:aa:aa")
        self.assertEqual(payload["devices"][0]["iface_id"], "if0")

    def test_releases_json_outputs_selected_asset(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()

        exit_code = main(["releases", "--json"], service=service, stdout=out, stderr=err)

        self.assertEqual(exit_code, 0)
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["releases"][0]["tag"], "v1.2.3")
        self.assertEqual(payload["releases"][0]["selected_asset"]["name"], "firmware.tar")

    def test_update_ambiguous_target_returns_error(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        service.raise_on_select = ValueError("ambiguous target")

        exit_code = main(
            ["update", "--mac", "aa:aa:aa:aa:aa:aa", "--file", "/tmp/fw.tar"],
            service=service,
            stdout=out,
            stderr=err,
        )

        self.assertNotEqual(exit_code, 0)
        self.assertIn("ambiguous target", err.getvalue())

    def test_wizard_dispatches_list_releases(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        answers = iter(["1", "5", "0", "0"])

        exit_code = main(
            ["wizard"],
            service=service,
            stdout=out,
            stderr=err,
            input_fn=lambda _prompt: next(answers),
        )

        self.assertEqual(exit_code, 0)
        self.assertIn("v1.2.3", out.getvalue())
        self.assertTrue(any(call and call[0] == "list_releases" for call in service.calls))

    def test_wizard_update_github_enter_uses_latest_release(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        answers = iter(["1", "1", "1", "", ""])

        with patch("app.cli.github_download") as github_download:
            exit_code = main(
                ["wizard"],
                service=service,
                stdout=out,
                stderr=err,
                input_fn=lambda _prompt: next(answers),
            )

        self.assertEqual(exit_code, 0)
        github_download.assert_called_once()
        self.assertIn(("list_releases", True), service.calls)
        self.assertIn(
            ("update_device", "aa:aa:aa:aa:aa:aa", "github", "ota", unittest.mock.ANY, "v1.2.3"),
            service.calls,
        )

    def test_wizard_raw_flash_github_numeric_choice_uses_selected_release(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        answers = iter(["1", "2", "1", "2", ""])

        with patch("app.cli.github_download") as github_download:
            exit_code = main(
                ["wizard"],
                service=service,
                stdout=out,
                stderr=err,
                input_fn=lambda _prompt: next(answers),
            )

        self.assertEqual(exit_code, 0)
        github_download.assert_called_once()
        self.assertIn(("list_releases", True), service.calls)
        self.assertIn(
            ("raw_flash", "aa:aa:aa:aa:aa:aa", "bin", unittest.mock.ANY),
            service.calls,
        )

    def test_wizard_zero_on_action_goes_back_to_device_selection(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        answers = iter(["1", "0", "1", "4"])

        exit_code = main(
            ["wizard"],
            service=service,
            stdout=out,
            stderr=err,
            input_fn=lambda _prompt: next(answers),
        )

        self.assertEqual(exit_code, 0)
        self.assertGreaterEqual(out.getvalue().count("Devices:"), 2)
        self.assertIn(("reboot_device", "aa:aa:aa:aa:aa:aa"), service.calls)

    def test_wizard_zero_on_release_goes_back_to_source_choice(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        answers = iter(["1", "1", "1", "0", "2", "/tmp/fw.tar", ""])

        with patch("app.cli.github_download") as github_download:
            exit_code = main(
                ["wizard"],
                service=service,
                stdout=out,
                stderr=err,
                input_fn=lambda _prompt: next(answers),
            )

        self.assertEqual(exit_code, 0)
        github_download.assert_not_called()
        self.assertIn("GitHub releases:", out.getvalue())
        self.assertIn(
            ("update_device", "aa:aa:aa:aa:aa:aa", "local", "ota", Path("/tmp/fw.tar"), ""),
            service.calls,
        )

    def test_wizard_update_shows_environment_and_confirm_before_running(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        service.environment_messages = ["Raw Ethernet may require sudo or CAP_NET_RAW."]
        answers = iter(["1", "1", "2", "/tmp/fw.tar", ""])

        def ask(prompt: str) -> str:
            out.write(prompt)
            answer = next(answers)
            out.write(answer + "\n")
            return answer

        exit_code = main(
            ["wizard"],
            service=service,
            stdout=out,
            stderr=err,
            input_fn=ask,
        )

        self.assertEqual(exit_code, 0)
        self.assertIn(("validate_environment",), service.calls)
        self.assertIn("Environment:", out.getvalue())
        self.assertIn("Raw Ethernet may require sudo or CAP_NET_RAW.", out.getvalue())
        self.assertIn("Summary:", out.getvalue())
        self.assertIn("Mode: update", out.getvalue())
        self.assertIn("Proceed [Enter=yes, 0=back]>", out.getvalue())

    def test_wizard_raw_flash_confirm_zero_goes_back_before_running(self) -> None:
        out = io.StringIO()
        err = io.StringIO()
        service = FakeService()
        answers = iter(["1", "2", "2", "/tmp/fw.bin", "0", "2", "/tmp/fw.bin", ""])

        def ask(prompt: str) -> str:
            out.write(prompt)
            answer = next(answers)
            out.write(answer + "\n")
            return answer

        exit_code = main(
            ["wizard"],
            service=service,
            stdout=out,
            stderr=err,
            input_fn=ask,
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(out.getvalue().count("Summary:"), 2)
        self.assertIn(("raw_flash", "aa:aa:aa:aa:aa:aa", "bin", Path("/tmp/fw.bin")), service.calls)

    def test_legacy_utils_wrapper_exposes_new_cli_help(self) -> None:
        proc = subprocess.run(
            [".venv/bin/python", "rnode-halow-utils.py", "--help"],
            cwd=str(Path(__file__).resolve().parents[1]),
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(proc.returncode, 0)
        self.assertIn("raw-flash", proc.stdout)


if __name__ == "__main__":
    unittest.main()
