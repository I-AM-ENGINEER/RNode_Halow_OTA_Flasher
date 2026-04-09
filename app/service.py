from __future__ import annotations

import os
import struct
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

from scapy.all import AsyncSniffer, Ether, Raw  # type: ignore

from modules import HgicSession, scan_all_parallel
from modules.hgic_device import (
    RawEthernetAccessError,
    async_sniffer_start_safe,
    async_sniffer_stop_safe,
    raw_ethernet_access_message,
    sendp_safe,
    windows_npcap_missing,
    windows_npcap_missing_message,
)
from modules.hgic_ota import ETH_P_OTA
from modules.hgic_ota_tar import inspect_ota_tar
from modules.hgic_scan import scan_iface

from .common import (
    main_timeout,
    make_minimal_ota_tar_from_bin,
    open_external_url,
    pick_preflash_firmware_name,
    read_builtin_firmware,
)
from .github import github_list_release_tags
from .models import DeviceRow, FirmwareSelection, FlashTargetState, ServiceEvent


ETH_P_OTA_FW_FORMAT_LITTLEFS = 0xF2
ETH_P_OTA_FW_FORMAT_LITTLEFS_RESP = 0xF3


def pack_format_littlefs_req() -> bytes:
    return struct.pack("BB", ETH_P_OTA_FW_FORMAT_LITTLEFS, 0)


def parse_format_littlefs_resp_payload(payload: bytes) -> Optional[int]:
    if len(payload) < 2:
        return None
    if payload[0] != int(ETH_P_OTA_FW_FORMAT_LITTLEFS_RESP):
        return None
    return int(payload[1])


def is_rnode_halow_by_scan(ver: str) -> bool:
    return (ver or "").strip() == "0.0.0.0"


def fmt_iface(scan_result: Any) -> str:
    iface = getattr(scan_result, "iface_name", None)
    if not iface:
        iface = getattr(scan_result, "iface_id", None)
    if not iface:
        iface = getattr(scan_result, "iface", None)
    return str(iface) if iface is not None else "?"


def fmt_iface_id(scan_result: Any) -> str:
    iface = getattr(scan_result, "iface_id", None)
    if iface:
        return str(iface)
    return fmt_iface(scan_result)


def fmt_mac(scan_result: Any) -> str:
    return str(getattr(scan_result, "src_mac", "")).lower()


def fmt_scan_ver(scan_result: Any) -> str:
    return str(getattr(scan_result, "version_str", "")).strip()


class FlasherService:
    def __init__(
        self,
        *,
        scan_all: Callable[..., list[Any]] = scan_all_parallel,
        scan_iface: Callable[..., list[Any]] = scan_iface,
        session_factory: Callable[[str], Any] = HgicSession,
        inspect_ota_tar: Callable[[Path], Any] = inspect_ota_tar,
        read_builtin_firmware: Callable[[str], bytes] = read_builtin_firmware,
        pick_preflash_firmware_name: Callable[[], str] = pick_preflash_firmware_name,
        make_minimal_ota_tar_from_bin: Callable[[Path], tuple[Path, Any]] = make_minimal_ota_tar_from_bin,
        format_littlefs: Optional[Callable[[Any, str], None]] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._scan_all = scan_all
        self._scan_iface = scan_iface
        self._session_factory = session_factory
        self._inspect_ota_tar = inspect_ota_tar
        self._read_builtin_firmware = read_builtin_firmware
        self._pick_preflash_firmware_name = pick_preflash_firmware_name
        self._make_minimal_ota_tar_from_bin = make_minimal_ota_tar_from_bin
        self._format_littlefs = format_littlefs or self.format_littlefs
        self._sleep = sleep

    def event(self, kind: str, message: str = "", **data: Any) -> ServiceEvent:
        return ServiceEvent(kind=kind, message=message, data=data)

    def list_releases(self, *, stable_only: bool = False):
        releases = list(github_list_release_tags())
        if stable_only:
            return [release for release in releases if not bool(getattr(release, "prerelease", False))]
        return releases

    def validate_environment(self) -> list[str]:
        messages: list[str] = []
        if windows_npcap_missing():
            messages.append(windows_npcap_missing_message())
            return messages

        if sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() != 0:
            messages.append("Raw Ethernet may require sudo or CAP_NET_RAW.")

        return messages

    def scan_devices(
        self,
        *,
        existing_rows: Optional[dict[tuple[str, str], DeviceRow]] = None,
        now: Optional[float] = None,
    ) -> tuple[list[DeviceRow], set[tuple[str, str]]]:
        existing_rows = existing_rows or {}
        now_ts = time.time() if now is None else float(now)
        scan_results = self._scan_all(
            packet_cnt=10,
            period_sec=main_timeout(0.010),
            sniff_time=main_timeout(0.5),
        )

        seen: set[tuple[str, str]] = set()
        rows: list[DeviceRow] = []
        for result in scan_results or []:
            mac = fmt_mac(result)
            iface = fmt_iface(result)
            iface_id = fmt_iface_id(result)
            kind = "rnode-halow" if is_rnode_halow_by_scan(fmt_scan_ver(result)) else "hgic"
            key = (mac, iface_id)
            seen.add(key)

            row = existing_rows.get(key, DeviceRow(mac=mac, iface=iface, iface_id=iface_id))
            row.iface = iface
            row.kind = kind
            row.last_seen_ts = now_ts
            rows.append(row)

        return rows, seen

    def select_target(self, rows: Sequence[DeviceRow], *, mac: str, iface: str | None = None) -> DeviceRow:
        mac_norm = str(mac or "").strip().lower()
        iface_norm = str(iface or "").strip()
        matches: list[DeviceRow] = []
        for row in rows:
            if str(row.mac or "").lower() != mac_norm:
                continue
            if iface_norm and iface_norm not in {str(row.iface), str(row.iface_id)}:
                continue
            matches.append(row)

        if not matches:
            raise ValueError(f"target not found: {mac_norm}")
        if len(matches) > 1:
            raise ValueError(f"ambiguous target: {mac_norm}")
        return matches[0]

    def get_ip(self, target: DeviceRow):
        session = self._session_factory(target.iface_id)
        return session.get_ip(target.mac, tries=5, timeout=main_timeout(0.4))

    def reboot_device(self, target: DeviceRow, *, known_rows: Sequence[DeviceRow]) -> Iterable[ServiceEvent]:
        events: list[ServiceEvent] = []
        self.run_reboot(target, known_rows=known_rows, emit=events.append)
        return events

    def open_web(self, target: DeviceRow) -> bool:
        info = self.get_ip(target)
        if info is None:
            return False
        ip_s = str(getattr(info, "ip", "") or "")
        if not ip_s or ip_s == "0.0.0.0":
            return False
        return open_external_url(f"http://{ip_s}/")

    def build_flash_target_state(self, target: DeviceRow, known_rows: Sequence[DeviceRow]) -> FlashTargetState:
        current_mac = str(target.mac or "").lower()
        blacklist_macs: set[str] = set()
        for row in known_rows:
            row_mac = str(getattr(row, "mac", "") or "").lower()
            if not row_mac:
                continue
            if str(getattr(row, "iface_id", "") or "") != str(target.iface_id or ""):
                continue
            if row_mac == current_mac:
                continue
            blacklist_macs.add(row_mac)

        return FlashTargetState(
            iface_id=str(target.iface_id or ""),
            current_mac=current_mac,
            allowed_macs={current_mac},
            blacklist_macs=blacklist_macs,
        )

    def scan_live_targets(self, state: FlashTargetState) -> list[tuple[str, str]]:
        scan_results = self._scan_iface(
            state.iface_id,
            packet_cnt=6,
            period_sec=main_timeout(0.010),
            sniff_time=main_timeout(0.35),
        )
        live: list[tuple[str, str]] = []
        seen: set[str] = set()
        for result in scan_results or []:
            mac = fmt_mac(result)
            if not mac or mac in seen or mac in state.blacklist_macs:
                continue
            kind = "rnode-halow" if is_rnode_halow_by_scan(fmt_scan_ver(result)) else "hgic"
            live.append((mac, kind))
            seen.add(mac)
        return live

    def pick_live_target_mac(
        self,
        state: FlashTargetState,
        *,
        prefer_kind: str | None = None,
    ) -> tuple[str | None, list[ServiceEvent]]:
        candidates = self.scan_live_targets(state)
        if not candidates:
            return None, []

        preferred: list[str] = []
        fallback: list[str] = []
        for mac, kind in candidates:
            if prefer_kind is not None and kind == prefer_kind:
                preferred.append(mac)
            else:
                fallback.append(mac)

        ordered = [*preferred, *fallback]
        picked: str | None = None
        if state.current_mac in ordered:
            picked = state.current_mac
        else:
            for mac in ordered:
                if mac in state.allowed_macs:
                    picked = mac
                    break
            if picked is None:
                picked = ordered[0]

        if picked is None:
            return None, []

        events: list[ServiceEvent] = []
        old_mac = state.current_mac
        is_new_mac = picked not in state.allowed_macs
        state.allowed_macs.add(picked)
        state.current_mac = picked

        if is_new_mac and old_mac and old_mac != picked:
            events.append(
                self.event("device_changed", f"target MAC changed: {old_mac} -> {picked}", old_mac=old_mac, new_mac=picked)
            )

        if len(ordered) > 1 and picked != old_mac:
            events.append(self.event("warning", f"multiple non-blacklisted devices visible; using {picked}", mac=picked))

        return picked, events

    def wait_hgic_ready(
        self,
        state: FlashTargetState,
        *,
        overall_timeout_s: float = main_timeout(15.0),
    ) -> tuple[bool, list[ServiceEvent]]:
        events: list[ServiceEvent] = []
        t0 = time.time()
        while time.time() - t0 < overall_timeout_s:
            picked, picked_events = self.pick_live_target_mac(state, prefer_kind="hgic")
            events.extend(picked_events)
            if picked:
                return True, events
            self._sleep(main_timeout(0.20))
        return False, events

    def wait_ip(
        self,
        session: Any,
        state: FlashTargetState,
        *,
        overall_timeout_s: float = main_timeout(60.0),
    ) -> tuple[str | None, list[ServiceEvent]]:
        events: list[ServiceEvent] = []
        t0 = time.time()
        while time.time() - t0 < overall_timeout_s:
            mac, picked_events = self.pick_live_target_mac(state, prefer_kind="rnode-halow")
            events.extend(picked_events)
            if mac is None:
                mac = state.current_mac
            answer = session.get_ip(mac, tries=1, timeout=main_timeout(0.5))
            if answer is not None:
                ip_s = str(getattr(answer, "ip", "") or "")
                if ip_s and ip_s != "0.0.0.0":
                    events.append(self.event("device_ip", ip_s, ip=ip_s, mac=mac))
                    return ip_s, events
            self._sleep(main_timeout(0.4))
        return None, events

    def raw_flash(
        self,
        target: DeviceRow,
        firmware: FirmwareSelection,
        *,
        known_rows: Sequence[DeviceRow],
    ) -> Iterable[ServiceEvent]:
        events: list[ServiceEvent] = []
        self.run_raw_flash(target, firmware, known_rows=known_rows, emit=events.append)
        return events

    def update_device(
        self,
        target: DeviceRow,
        firmware: FirmwareSelection,
        *,
        known_rows: Sequence[DeviceRow],
    ) -> Iterable[ServiceEvent]:
        events: list[ServiceEvent] = []
        self.run_update_device(target, firmware, known_rows=known_rows, emit=events.append)
        return events

    def run_raw_flash(
        self,
        target: DeviceRow,
        firmware: FirmwareSelection,
        *,
        known_rows: Sequence[DeviceRow],
        emit: Callable[[ServiceEvent], None],
    ) -> None:
        session = self._session_factory(target.iface_id)
        state = self.build_flash_target_state(target, known_rows)
        progress_cb, retry_cb = self._build_progress_callbacks(emit)

        if firmware.mode == "ota":
            emit(self.event("stage", "RAW flash (ota.tar)"))
            session.flash(
                state.current_mac,
                firmware.path,
                timeout=main_timeout(5.0),
                retries=5,
                progress_cb=progress_cb,
                retry_cb=retry_cb,
            )
        else:
            emit(self.event("stage", "RAW flash (bin)"))
            tar_path, temp_dir = self._make_minimal_ota_tar_from_bin(Path(firmware.path or ""))
            try:
                session.flash(
                    state.current_mac,
                    tar_path,
                    timeout=main_timeout(5.0),
                    retries=5,
                    progress_cb=progress_cb,
                    retry_cb=retry_cb,
                )
            finally:
                try:
                    temp_dir.cleanup()
                except Exception:
                    pass

        emit(self.event("stage", "reboot"))
        session.reboot(state.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
        emit(self.event("done", "RAW flash done"))

    def run_update_device(
        self,
        target: DeviceRow,
        firmware: FirmwareSelection,
        *,
        known_rows: Sequence[DeviceRow],
        emit: Callable[[ServiceEvent], None],
    ) -> None:
        session = self._session_factory(target.iface_id)
        state = self.build_flash_target_state(target, known_rows)
        info = self._inspect_ota_tar(Path(firmware.path or ""))
        progress_cb, retry_cb = self._build_progress_callbacks(emit)

        if target.kind != "rnode-halow":
            preflash_name = self._pick_preflash_firmware_name()
            emit(self.event("stage", "flash original firmware"))
            session.flash(
                state.current_mac,
                self._read_builtin_firmware(preflash_name),
                timeout=main_timeout(5.45),
                retries=5,
                progress_cb=progress_cb,
                retry_cb=retry_cb,
            )
            emit(self.event("stage", "reboot original firmware"))
            session.reboot(state.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
            emit(self.event("stage", "waiting original firmware reboot..."))
            ready, ready_events = self.wait_hgic_ready(state, overall_timeout_s=main_timeout(15.0))
            for event in ready_events:
                emit(event)
            if not ready:
                raise RuntimeError("original firmware did not return as HGIC within 15 seconds")
            emit(self.event("stage", "waiting original firmware settle..."))
            self._sleep(main_timeout(5.0))

        emit(self.event("stage", "flash rnode-halow firmware"))
        session.flash(
            state.current_mac,
            Path(firmware.path or ""),
            timeout=main_timeout(5.45),
            retries=5,
            progress_cb=progress_cb,
            retry_cb=retry_cb,
        )
        emit(self.event("stage", "reboot"))
        session.reboot(state.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))

        if not bool(getattr(info, "has_www_dir", False)):
            emit(self.event("done", "flash done"))
            return

        emit(self.event("stage", "waiting IP…"))
        ip_s, ip_events = self.wait_ip(session, state, overall_timeout_s=main_timeout(80.0))
        for event in ip_events:
            emit(event)
        if not ip_s:
            raise RuntimeError("IP not acquired (timeout)")

        emit(self.event("stage", "format LittleFS"))
        self._format_littlefs(session, state.current_mac)
        emit(self.event("stage", "reboot after LittleFS format"))
        session.reboot(state.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))

        emit(self.event("stage", "waiting IP after LittleFS format reboot…"))
        ip_s, ip_events = self.wait_ip(session, state, overall_timeout_s=main_timeout(80.0))
        for event in ip_events:
            emit(event)
        if not ip_s:
            raise RuntimeError("IP not acquired after LittleFS format reboot (timeout)")

        emit(self.event("stage", "upload filesystem via TFTP"))

        def stage_cb(message: str) -> None:
            emit(self.event("stage", message))

        session.flash_fs(
            state.current_mac,
            Path(firmware.path or ""),
            stage_cb=stage_cb,
            progress_cb=progress_cb,
        )
        emit(self.event("done", "flash done"))

    def run_reboot(
        self,
        target: DeviceRow,
        *,
        known_rows: Sequence[DeviceRow],
        emit: Callable[[ServiceEvent], None],
    ) -> None:
        session = self._session_factory(target.iface_id)
        state = self.build_flash_target_state(target, known_rows)
        emit(self.event("stage", "reboot"))
        session.reboot(state.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
        emit(self.event("done", "reboot sent"))

    def _build_progress_callbacks(self, emit: Callable[[ServiceEvent], None]) -> tuple[Callable[[int, int, float], None], Callable[[int, int, str], None]]:
        def progress_cb(done: int, total: int, speed: float) -> None:
            pct = (done * 100.0 / total) if total else 0.0
            emit(self.event("progress", pct=pct, done=done, total=total, speed=speed))

        def retry_cb(attempt: int, total: int, err: str) -> None:
            emit(self.event("warning", f"flash attempt {attempt}/{total} failed: {err}; retry in 3s"))

        return progress_cb, retry_cb

    def format_littlefs(self, session: Any, mac: str) -> None:
        dst_mac_s = str(mac or "").lower()
        host_mac_s = str(getattr(session, "host_mac", "") or "").lower()
        payload = pack_format_littlefs_req()

        def is_my_resp(packet) -> bool:
            if not packet.haslayer(Ether) or not packet.haslayer(Raw):
                return False
            eth = packet[Ether]
            if int(eth.type) != int(ETH_P_OTA):
                return False
            return (eth.src or "").lower() == dst_mac_s and (eth.dst or "").lower() == host_mac_s

        frame = Ether(src=host_mac_s, dst=dst_mac_s, type=ETH_P_OTA) / Raw(load=payload)

        for _ in range(3):
            sniffer = AsyncSniffer(iface=session.iface, store=True, lfilter=is_my_resp)
            async_sniffer_start_safe(sniffer)
            try:
                sendp_safe(frame, iface=session.iface, verbose=False)
                sniffer.join(timeout=main_timeout(15.0))
            finally:
                packets = async_sniffer_stop_safe(sniffer) or []

            for packet in packets:
                status = parse_format_littlefs_resp_payload(bytes(packet[Raw].load))
                if status is None:
                    continue
                if status != 0:
                    raise RuntimeError(f"LittleFS format failed: status={status}")
                return

            self._sleep(main_timeout(0.4))

        raise RuntimeError("LittleFS format failed: timeout")
