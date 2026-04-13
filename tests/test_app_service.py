import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from app.github import GhAsset, GhRelease
from app.models import DeviceRow, FirmwareSelection, FlashTargetState
from app.service import FlasherService


@dataclass
class FakeScanDevice:
    src_mac: str
    iface_name: str
    iface_id: str
    version_str: str


@dataclass
class FakeIpInfo:
    ip: str
    gw: str = "192.168.1.1"
    mask: str = "255.255.255.0"
    status: int = 0
    version: str = "1.0.0"


@dataclass
class FakeTarInfo:
    has_www_dir: bool


class FakeSession:
    def __init__(self, iface: str, ip_results=None):
        self.iface = iface
        self.host_mac = "de:ad:be:ef:00:01"
        self.flash_calls = []
        self.reboot_calls = []
        self.flash_fs_calls = []
        self.ip_results = list(ip_results or [])

    def flash(self, mac, payload, **kwargs):
        self.flash_calls.append((mac, payload, kwargs))

    def reboot(self, mac, **kwargs):
        self.reboot_calls.append((mac, kwargs))

    def flash_fs(self, mac, payload, **kwargs):
        self.flash_fs_calls.append((mac, payload, kwargs))
        return FakeIpInfo(ip="192.168.1.50")

    def get_ip(self, mac, **kwargs):
        if self.ip_results:
            return self.ip_results.pop(0)
        return None


class FlasherServiceTests(unittest.TestCase):
    def test_list_releases_filters_prereleases_when_requested(self) -> None:
        releases = [
            GhRelease(tag="v9.9.9-beta", prerelease=True, assets=[GhAsset(name="beta.tar", size=1, url="https://example/beta")]),
            GhRelease(tag="v9.9.8", prerelease=False, assets=[GhAsset(name="stable.tar", size=1, url="https://example/stable")]),
        ]

        with patch("app.service.github_list_release_tags", return_value=releases):
            service = FlasherService()
            filtered = service.list_releases(stable_only=True)

        self.assertEqual([release.tag for release in filtered], ["v9.9.8"])

    def test_scan_devices_keeps_existing_ip_and_version(self) -> None:
        service = FlasherService(
            scan_all=lambda **_: [FakeScanDevice("aa:aa:aa:aa:aa:aa", "eth0", "if0", "0.0.0.0")],
        )
        existing = {
            ("aa:aa:aa:aa:aa:aa", "if0"): DeviceRow(
                mac="aa:aa:aa:aa:aa:aa",
                iface="eth0",
                iface_id="if0",
                kind="rnode-halow",
                ip="192.168.1.77",
                ver="v1.0.1",
            )
        }

        rows, seen = service.scan_devices(existing_rows=existing, now=123.0)

        self.assertEqual(seen, {("aa:aa:aa:aa:aa:aa", "if0")})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].ip, "192.168.1.77")
        self.assertEqual(rows[0].ver, "v1.0.1")
        self.assertEqual(rows[0].kind, "rnode-halow")

    def test_select_target_rejects_ambiguous_match(self) -> None:
        service = FlasherService()
        rows = [
            DeviceRow(mac="aa:aa:aa:aa:aa:aa", iface="eth0", iface_id="if0"),
            DeviceRow(mac="aa:aa:aa:aa:aa:aa", iface="eth1", iface_id="if1"),
        ]

        with self.assertRaisesRegex(ValueError, "ambiguous"):
            service.select_target(rows, mac="aa:aa:aa:aa:aa:aa")

    def test_pick_live_target_mac_tracks_mac_changes(self) -> None:
        service = FlasherService(
            scan_iface=lambda *_args, **_kwargs: [
                FakeScanDevice("bb:bb:bb:bb:bb:bb", "eth0", "if0", "1.2.3"),
                FakeScanDevice("cc:cc:cc:cc:cc:cc", "eth0", "if0", "1.2.3"),
            ]
        )
        state = FlashTargetState(
            iface_id="if0",
            current_mac="aa:aa:aa:aa:aa:aa",
            allowed_macs={"aa:aa:aa:aa:aa:aa"},
            blacklist_macs={"cc:cc:cc:cc:cc:cc"},
        )

        picked, events = service.pick_live_target_mac(state, prefer_kind="hgic")

        self.assertEqual(picked, "bb:bb:bb:bb:bb:bb")
        self.assertEqual(state.current_mac, "bb:bb:bb:bb:bb:bb")
        self.assertEqual([event.kind for event in events], ["device_changed"])

    def test_raw_flash_emits_ordered_events(self) -> None:
        session = FakeSession("if0")
        service = FlasherService(session_factory=lambda iface: session)
        target = DeviceRow(mac="aa:aa:aa:aa:aa:aa", iface="eth0", iface_id="if0", kind="hgic")
        firmware = FirmwareSelection(source="local", mode="ota", path=Path("/tmp/fw.tar"), label="fw.tar")

        events = list(service.raw_flash(target, firmware, known_rows=[target]))

        self.assertEqual(
            [event.kind for event in events],
            ["stage", "stage", "done"],
        )
        self.assertEqual([event.message for event in events[:2]], ["RAW flash (ota.tar)", "reboot"])
        self.assertEqual(session.flash_calls[0][0], "aa:aa:aa:aa:aa:aa")
        self.assertEqual(session.reboot_calls[0][0], "aa:aa:aa:aa:aa:aa")

    def test_update_device_emits_ordered_events_for_safe_flow(self) -> None:
        session = FakeSession(
            "if0",
            ip_results=[
                FakeIpInfo(ip="192.168.1.40"),
                FakeIpInfo(ip="192.168.1.41"),
            ],
        )

        scan_sequences = [
            [FakeScanDevice("bb:bb:bb:bb:bb:bb", "eth0", "if0", "1.2.3")],
            [FakeScanDevice("bb:bb:bb:bb:bb:bb", "eth0", "if0", "0.0.0.0")],
            [FakeScanDevice("bb:bb:bb:bb:bb:bb", "eth0", "if0", "0.0.0.0")],
        ]

        def fake_scan_iface(*_args, **_kwargs):
            if scan_sequences:
                return scan_sequences.pop(0)
            return []

        format_calls = []

        service = FlasherService(
            scan_iface=fake_scan_iface,
            session_factory=lambda iface: session,
            inspect_ota_tar=lambda _path: FakeTarInfo(has_www_dir=True),
            read_builtin_firmware=lambda _name: b"preflash-bytes",
            pick_preflash_firmware_name=lambda: "preflash.bin",
            format_littlefs=lambda _session, mac: format_calls.append(mac),
            sleep=lambda _value: None,
        )
        target = DeviceRow(mac="aa:aa:aa:aa:aa:aa", iface="eth0", iface_id="if0", kind="hgic")
        firmware = FirmwareSelection(source="local", mode="ota", path=Path("/tmp/fw.tar"), label="fw.tar")

        events = list(service.update_device(target, firmware, known_rows=[target]))

        self.assertEqual(events[0].message, "flash original firmware")
        self.assertEqual(events[1].message, "reboot original firmware")
        self.assertIn("waiting original firmware reboot", events[2].message)
        self.assertIn("device_changed", [event.kind for event in events])
        self.assertEqual([event.kind for event in events].count("device_ip"), 2)
        self.assertEqual(events[-2].message, "upload filesystem via TFTP")
        self.assertEqual(events[-1].kind, "done")
        self.assertEqual(session.flash_calls[0][1], b"preflash-bytes")
        self.assertEqual(session.flash_calls[1][1], Path("/tmp/fw.tar"))
        self.assertEqual(format_calls, ["bb:bb:bb:bb:bb:bb"])
        self.assertEqual(session.flash_fs_calls[0][0], "bb:bb:bb:bb:bb:bb")

    def test_update_device_preflashes_even_for_rnode_halow_target(self) -> None:
        session = FakeSession(
            "if0",
            ip_results=[
                FakeIpInfo(ip="192.168.1.40"),
                FakeIpInfo(ip="192.168.1.41"),
            ],
        )
        scan_sequences = [
            [FakeScanDevice("aa:aa:aa:aa:aa:aa", "eth0", "if0", "0.0.0.0")],
            [FakeScanDevice("aa:aa:aa:aa:aa:aa", "eth0", "if0", "0.0.0.0")],
        ]

        def fake_scan_iface(*_args, **_kwargs):
            if scan_sequences:
                return scan_sequences.pop(0)
            return []

        service = FlasherService(
            scan_iface=fake_scan_iface,
            session_factory=lambda iface: session,
            inspect_ota_tar=lambda _path: FakeTarInfo(has_www_dir=True),
            read_builtin_firmware=lambda _name: b"preflash-bytes",
            pick_preflash_firmware_name=lambda: "preflash.bin",
            format_littlefs=lambda _session, _mac: None,
            sleep=lambda _value: None,
        )
        target = DeviceRow(mac="aa:aa:aa:aa:aa:aa", iface="eth0", iface_id="if0", kind="rnode-halow")
        firmware = FirmwareSelection(source="local", mode="ota", path=Path("/tmp/fw.tar"), label="fw.tar")

        events = list(service.update_device(target, firmware, known_rows=[target]))

        self.assertEqual(events[0].message, "flash original firmware")
        self.assertEqual(session.flash_calls[0][1], b"preflash-bytes")


if __name__ == "__main__":
    unittest.main()
