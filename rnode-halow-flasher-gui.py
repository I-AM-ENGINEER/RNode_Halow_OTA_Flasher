#!/usr/bin/env python3
"""
RNode-HaLow Flasher GUI (tkinter) — refactored

Fixes from user feedback:
1) Update works without pre-known IP (two-stage flow handles IP acquisition).
2) IP is always actively requested (rate-limited) and displayed for rnode-halow devices.
3) Flashing directly from GitHub releases is supported (no asset list; one asset assumed).
4) RAW flash speed: scanning never runs during flash/update (pcap lock); scan is opportunistic (non-blocking lock),
   so it won't starve GET_IP or flash operations.

Firmware sources:
- GitHub release tag (v0.4.0 etc). The tool auto-picks single asset:
  prefer .tar (modern), otherwise .bin (old, labeled RAW).
- Local file (.tar or .bin)

Actions:
- Update selected (recommended): requires OTA .tar
  * if device is NOT rnode-halow: RAW flash -> reboot -> wait IP -> TFTP file upload
  * if device IS rnode-halow: wait IP -> TFTP file upload
- Flash RAW (advanced): allows .tar or .bin (bin wrapped into minimal tar)
- Double click device with IP: open http://<ip>/

Requires "modules/" (same as rnode-halow-utils.py):
- scan_all_parallel
- HgicSession
- modules.hgic_ota_tar.inspect_ota_tar
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from app.common import (
    extract_builtin_firmware,
    file_is_tar,
    is_builtin_source,
    list_builtin_firmware_names,
    main_timeout,
    make_minimal_ota_tar_from_bin,
    open_external_url,
    pick_preflash_firmware_name,
    read_builtin_firmware,
    resolve_path,
)
from app.github import (
    GhRelease,
    REPO_URL,
    github_download,
    github_list_release_tags,
    github_pick_asset,
    gh_release_label,
)
from app.service import FlasherService
from modules import HgicSession
from modules.hgic_device import (
    RawEthernetAccessError,
    raw_ethernet_access_message,
    windows_npcap_missing,
    windows_npcap_missing_message,
    WINDOWS_NPCAP_URL,
)
from modules.hgic_ota_tar import inspect_ota_tar


APP_NAME = "RNode-HaLow Flasher"
APP_VERSION = "1.3.0"

# ----------------------------
# GitHub repo settings
# ----------------------------

# NOTE: GitHub releases are downloaded into a temporary directory per GUI run.
# This avoids accidentally flashing a stale cached file when user switches between
# "GitHub release" and "Local file" modes.

def http_get_json(url: str, timeout_s: float = main_timeout(1.0)) -> Optional[Dict[str, Any]]:
    try:
        import urllib.request
        from app.github import _urlopen  # local import avoids widening the public surface here

        req = urllib.request.Request(url, headers={"User-Agent": "rnode-halow-gui"})
        with _urlopen(req, timeout_s) as r:
            data = r.read()
        return json.loads(data.decode("utf-8", errors="replace"))
    except Exception:
        return None


def pick_version_from_json(obj: Dict[str, Any]) -> Optional[str]:
    for k in ("version", "ver", "fw_ver", "firmware", "fw_version", "build", "sw"):
        v = obj.get(k)
        if isinstance(v, (str, int, float)):
            return str(v)
    for k in ("info", "device", "sys", "system"):
        sub = obj.get(k)
        if isinstance(sub, dict):
            v = pick_version_from_json(sub)
            if v:
                return v
    return None


def is_rnode_halow_by_scan(ver: str) -> bool:
    return (ver or "").strip() == "0.0.0.0"


def should_require_preflash(firmware_mode: str) -> bool:
    return str(firmware_mode or "").strip() == "ota"


# ----------------------------
# Device rows
# ----------------------------

@dataclass
class DevRow:
    mac: str
    iface: str
    iface_id: str
    kind: str = ""      # "rnode-halow" | "hgic"
    ip: str = ""
    ver: str = ""       # rnode-halow HTTP version (best-effort)
    last_seen_ts: float = field(default_factory=time.time)

    def key(self) -> Tuple[str, str]:
        return (self.mac, self.iface_id)


@dataclass(frozen=True)
class FirmwareSelection:
    source: str
    mode: str
    path: Optional[Path]
    label: str
    github_tag: str = ""


# ----------------------------
# App
# ----------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("950x620")
        self.minsize(880, 560)

        self._q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._stop = threading.Event()
        self._service = FlasherService()

        # pcap/network serialization
        self._pcap_lock = threading.RLock()
        self._iface_locks: Dict[str, threading.Lock] = {}

        # device state
        self._rows: Dict[Tuple[str, str], DevRow] = {}
        self._tree_items: Dict[Tuple[str, str], str] = {}
        self._selected_key: Optional[Tuple[str, str]] = None

        # IP polling rate-limit
        self._ip_poll_last: Dict[Tuple[str, str], float] = {}
        self._ip_jobs_inflight: set[Tuple[str, str]] = set()

        # firmware state
        self._fw_source = tk.StringVar(value="github")  # "github"|"local"|"builtin"
        self._fw_path = tk.StringVar(value="")
        self._fw_mode = tk.StringVar(value="")          # "ota"|"bin"|""
        self._fw_info = tk.StringVar(value="")

        # keep all selections; switching radiobuttons must immediately switch mode/info/buttons
        self._fw_local_path: Optional[Path] = None
        self._fw_local_mode: str = ""
        self._fw_local_info: str = ""

        self._fw_gh_path: Optional[Path] = None
        self._fw_gh_mode: str = ""
        self._fw_gh_info: str = ""
        self._fw_gh_tag: str = ""

        builtin_names = list_builtin_firmware_names()
        self._fw_builtin_name = tk.StringVar(value=(builtin_names[0] if builtin_names else ""))
        self._fw_builtin_path: Optional[Path] = None
        self._fw_builtin_mode: str = ""
        self._fw_builtin_info: str = ""

        # temp dirs (per GUI run)
        self._gh_tmp = tempfile.TemporaryDirectory(prefix="rnode_halow_gh_")
        self._gh_tmp_dir = Path(self._gh_tmp.name)
        self._builtin_tmp = tempfile.TemporaryDirectory(prefix="rnode_halow_builtin_")
        self._builtin_tmp_dir = Path(self._builtin_tmp.name)

        # github
        self._gh_status = tk.StringVar(value="GitHub: …")
        self._gh_tags: List[str] = []
        self._gh_rels: Dict[str, GhRelease] = {}
        self._gh_rels_stable: Dict[str, GhRelease] = {}
        self._gh_rels_all: Dict[str, GhRelease] = {}
        self._gh_tags_stable: List[str] = []
        self._gh_tags_all: List[str] = []
        self._gh_display_to_tag: Dict[str, str] = {}
        self._gh_tag_to_display: Dict[str, str] = {}
        self._gh_force_latest_on_refresh = False
        self._gh_tag = tk.StringVar(value="")
        self._gh_show_beta = tk.BooleanVar(value=False)

        # scanning
        self._auto_refresh = tk.BooleanVar(value=True)
        self._scan_interval_s = tk.DoubleVar(value=2.0)

        # busy (UI only)
        self._busy = threading.Event()

        # one-shot warnings
        self._raw_ethernet_warning_queued = threading.Event()
        self._raw_ethernet_warning_shown = False
        self._windows_npcap_warning_queued = threading.Event()
        self._windows_npcap_warning_shown = False
        self._startup_notice_shown = False

        self._build_ui()
        self._refresh_builtin_fw_list()
        self._set_fw_builtin(self._fw_builtin_name.get().strip())

        # timers/threads
        self.after(60, self._poll_queue)
        self.after(120, self._show_startup_notice_once)
        if windows_npcap_missing():
            self._queue_windows_npcap_warning()
        threading.Thread(target=self._scan_loop, daemon=True).start()

        # fetch releases
        self._gh_refresh_async()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI ----------

    def _build_ui(self) -> None:
        fw = ttk.LabelFrame(self, text="Firmware")
        fw.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)

        fw_top = ttk.Frame(fw)
        fw_top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(6, 2))

        ttk.Button(fw_top, text="GitHub", command=lambda: open_external_url(REPO_URL)).pack(side=tk.RIGHT)

        ttk.Radiobutton(
            fw_top, text="GitHub release:", value="github", variable=self._fw_source,
            command=self._fw_source_changed
        ).pack(side=tk.LEFT)

        self._gh_combo = ttk.Combobox(fw_top, textvariable=self._gh_tag, state="readonly", width=22)
        self._gh_combo.pack(side=tk.LEFT, padx=(6, 6))
        self._gh_combo.bind("<<ComboboxSelected>>", self._gh_tag_selected)

        ttk.Button(fw_top, text="Refresh", command=self._gh_refresh_async).pack(side=tk.LEFT)
        ttk.Checkbutton(
            fw_top,
            text="Show beta versions",
            variable=self._gh_show_beta,
            command=self._gh_show_beta_changed,
        ).pack(side=tk.LEFT, padx=(8, 0))

        fw_mid = ttk.Frame(fw)
        fw_mid.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(2, 2))

        ttk.Radiobutton(
            fw_mid, text="Local file:", value="local", variable=self._fw_source,
            command=self._fw_source_changed
        ).pack(side=tk.LEFT)

        self._fw_entry = ttk.Entry(fw_mid, textvariable=self._fw_path)
        self._fw_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))

        self._btn_browse = ttk.Button(fw_mid, text="Browse…", command=self._browse_fw)
        self._btn_browse.pack(side=tk.LEFT)

        fw_builtin = ttk.Frame(fw)
        fw_builtin.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(2, 6))

        ttk.Radiobutton(
            fw_builtin, text="Built-in original:", value="builtin", variable=self._fw_source,
            command=self._fw_source_changed
        ).pack(side=tk.LEFT)

        self._builtin_combo = ttk.Combobox(
            fw_builtin, textvariable=self._fw_builtin_name, state="readonly", width=54, values=[]
        )
        self._builtin_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 6))
        self._builtin_combo.bind("<<ComboboxSelected>>", self._builtin_fw_selected)

        fw_status = tk.Frame(fw)
        fw_status.pack(side=tk.TOP, fill=tk.X, padx=8, pady=(0, 6))
        tk.Label(
            fw_status,
            textvariable=self._fw_info,
            fg="#888",
            bg=self.cget("bg"),
            anchor="w",
        ).pack(side=tk.TOP, fill=tk.X)

        dev = ttk.LabelFrame(self, text="Devices")
        dev.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=(0, 8))

        ctrl = ttk.Frame(dev)
        ctrl.pack(side=tk.TOP, fill=tk.X, padx=6, pady=(6, 6))

        ttk.Checkbutton(ctrl, text="Auto refresh", variable=self._auto_refresh).pack(side=tk.LEFT)
        ttk.Label(ctrl, text="Interval (s):").pack(side=tk.LEFT, padx=(10, 4))
        ttk.Spinbox(ctrl, from_=0.5, to=10.0, increment=0.5, textvariable=self._scan_interval_s, width=5).pack(side=tk.LEFT)
        ttk.Button(ctrl, text="Refresh now", command=self._scan_once_async).pack(side=tk.LEFT, padx=(10, 0))

        self._btn_open_cfg = ttk.Button(ctrl, text="Open configurator", command=self._open_configurator_selected)
        self._btn_open_cfg.pack(side=tk.LEFT, padx=(6, 0))

        self._btn_reboot = ttk.Button(ctrl, text="Reboot", command=self._reboot_selected)
        self._btn_reboot.pack(side=tk.LEFT, padx=(6, 0))

        self._btn_flash = ttk.Button(ctrl, text="Flash", command=self._flash_selected)
        self._btn_flash.pack(side=tk.RIGHT)

        cols = ("mac", "iface", "type", "ip", "version")
        self._tree = ttk.Treeview(dev, columns=cols, show="headings", selectmode="browse")
        for c, txt, w in [
            ("mac", "MAC", 170),
            ("iface", "Interface", 170),
            ("type", "Type", 120),
            ("ip", "IP", 140),
            ("version", "Version", 140),
        ]:
            self._tree.heading(c, text=txt)
            self._tree.column(c, width=w, anchor=tk.W)
        self._tree.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
        self._tree.bind("<<TreeviewSelect>>", self._on_select)
        self._tree.bind("<Double-1>", lambda _e: self._open_configurator_selected())

        bot = ttk.Frame(self)
        bot.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=False, padx=10, pady=(0, 10))

        pbar = ttk.Frame(bot)
        pbar.pack(side=tk.TOP, fill=tk.X)

        self._p = ttk.Progressbar(pbar, orient=tk.HORIZONTAL, mode="determinate")
        self._p.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._p_lbl = ttk.Label(pbar, text="")
        self._p_lbl.pack(side=tk.LEFT, padx=(10, 0))

        self._log = tk.Text(bot, height=9, wrap=tk.WORD)
        self._log.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(8, 0))
        self._log.tag_configure("err", foreground="#ff6666")
        self._log.tag_configure("ok", foreground="#006400")
        self._log.tag_configure("stage", foreground="#66aaff")

        self._fw_source_changed()
        self._refresh_buttons()

    # ---------- UI state ----------

    def _log_line(self, s: str, tag: str = "") -> None:
        self._log.insert(tk.END, s + "\n", tag)
        self._log.see(tk.END)

    def _queue_raw_ethernet_warning(self, msg: Optional[str] = None) -> None:
        if self._raw_ethernet_warning_queued.is_set():
            return
        self._raw_ethernet_warning_queued.set()
        self._q.put(("raw_ethernet_warning", str(msg or raw_ethernet_access_message())))

    def _show_raw_ethernet_warning_once(self, msg: str) -> None:
        if self._raw_ethernet_warning_shown:
            return
        self._raw_ethernet_warning_shown = True
        self._log_line(f"[WARN] {msg.replace(chr(10), ' ')}", "err")
        try:
            messagebox.showwarning("Raw Ethernet access required", msg)
        except Exception:
            pass

    def _queue_windows_npcap_warning(self) -> None:
        if self._windows_npcap_warning_queued.is_set():
            return
        self._windows_npcap_warning_queued.set()
        self._q.put(("windows_npcap_warning", windows_npcap_missing_message()))

    def _show_windows_npcap_warning_once(self, msg: str) -> None:
        if self._windows_npcap_warning_shown:
            return
        self._windows_npcap_warning_shown = True
        self._log_line(f"[WARN] {msg.replace(chr(10), ' ')}", "err")
        try:
            open_now = messagebox.askyesno(
                "Npcap required on Windows",
                msg + "\n\nOpen the Npcap download page now?",
            )
            if open_now:
                open_external_url(WINDOWS_NPCAP_URL)
        except Exception:
            try:
                messagebox.showwarning("Npcap required on Windows", msg)
            except Exception:
                pass

    def _show_startup_notice_once(self) -> None:
        if self._startup_notice_shown:
            return
        self._startup_notice_shown = True

        msg = (
            "The device being updated must be connected to a network with a DHCP server.\n\n"
            "If the device cannot obtain an IP address, the firmware update will still complete, "
            "but the device control panel will not be available."
        )

        try:
            messagebox.showwarning("Important information", msg)
        except Exception:
            pass

    def _set_progress(self, pct: float, done: int = 0, total: int = 0, speed: float = 0.0) -> None:
        pct = max(0.0, min(100.0, float(pct)))
        self._p["value"] = pct
        if total > 0:
            self._p_lbl.config(text=f"{pct:6.2f}%  {done}/{total}  {speed/1024:.1f} KiB/s")
        else:
            self._p_lbl.config(text=f"{pct:6.2f}%")

    def _set_busy(self, b: bool) -> None:
        if b:
            self._busy.set()
        else:
            self._busy.clear()
        self._refresh_buttons()

    def _refresh_buttons(self) -> None:
        mode = self._fw_mode.get().strip()
        busy = self._busy.is_set()

        has_sel = bool(self._selected_key and (self._selected_key in self._rows))
        if hasattr(self, "_btn_open_cfg"):
            self._btn_open_cfg.config(state=("normal" if (has_sel and not busy) else "disabled"))

        if hasattr(self, "_btn_reboot"):
            self._btn_reboot.config(state=("normal" if (has_sel and not busy) else "disabled"))

        if hasattr(self, "_btn_flash"):
            self._btn_flash.config(state=("normal" if (has_sel and (mode in ("ota", "bin")) and not busy) else "disabled"))

    def _apply_fw_view(self) -> None:
        src = self._fw_source.get().strip()
        if src == "github":
            p = self._fw_gh_path
            m = (self._fw_gh_mode or "").strip()
            info = self._fw_gh_info
            if m in ("ota", "bin"):
                self._fw_path.set(str(p) if (p and p.is_file()) else "")
                self._fw_mode.set(m)
                self._fw_info.set(info)
            else:
                self._fw_path.set("")
                self._fw_mode.set("")
                self._fw_info.set(info)
        elif is_builtin_source(src):
            p = self._fw_builtin_path
            m = (self._fw_builtin_mode or "").strip()
            info = self._fw_builtin_info
            if p and p.is_file() and m in ("bin",):
                self._fw_path.set(str(p))
                self._fw_mode.set(m)
                self._fw_info.set(info)
            else:
                self._fw_path.set("")
                self._fw_mode.set("")
                self._fw_info.set(info)
        else:
            p = self._fw_local_path
            m = (self._fw_local_mode or "").strip()
            info = self._fw_local_info
            if p and p.is_file() and m in ("ota", "bin"):
                self._fw_path.set(str(p))
                self._fw_mode.set(m)
                self._fw_info.set(info)
            else:
                # keep the entry text for convenience, but disable actions
                self._fw_mode.set("")
                self._fw_info.set(info)
        self._refresh_buttons()

    def _fw_source_changed(self) -> None:
        src = self._fw_source.get().strip()
        if src == "github":
            self._gh_combo.configure(state="readonly")
            self._fw_entry.configure(state="disabled")
            self._btn_browse.configure(state="disabled")
            self._builtin_combo.configure(state="disabled")
        elif is_builtin_source(src):
            self._gh_combo.configure(state="disabled")
            self._fw_entry.configure(state="disabled")
            self._btn_browse.configure(state="disabled")
            self._builtin_combo.configure(state="readonly")
        else:
            self._gh_combo.configure(state="disabled")
            self._fw_entry.configure(state="normal")
            self._btn_browse.configure(state="normal")
            self._builtin_combo.configure(state="disabled")

        # switching radiobuttons must immediately switch mode/info/buttons
        self._apply_fw_view()

    def _refresh_builtin_fw_list(self) -> None:
        names = list_builtin_firmware_names()
        self._builtin_combo.configure(values=names)
        current = self._fw_builtin_name.get().strip()
        if current not in names:
            self._fw_builtin_name.set(names[0] if names else "")

    def _builtin_fw_selected(self, _evt=None) -> None:
        self._set_fw_builtin(self._fw_builtin_name.get().strip())

    def _set_fw_builtin(self, name: str) -> None:
        name = str(name or "").strip()
        info_s = ""
        mode = ""
        p: Optional[Path] = None

        if name:
            try:
                p = extract_builtin_firmware(name, self._builtin_tmp_dir)
                mode = "bin"
                info_s = f"Built-in original: {name}"
            except Exception as e:
                info_s = f"Built-in missing: {e}"

        self._fw_builtin_name.set(name)
        self._fw_builtin_path = p
        self._fw_builtin_mode = mode
        self._fw_builtin_info = info_s
        if is_builtin_source(self._fw_source.get()):
            self._apply_fw_view()

    # ---------- Firmware: local ----------

    def _browse_fw(self) -> None:
        p = filedialog.askopenfilename(
            title="Select firmware file",
            filetypes=[("OTA tar (.tar)", "*.tar"), ("Firmware bin (.bin)", "*.bin"), ("All files", "*.*")],
        )
        if not p:
            return
        self._set_fw_local(resolve_path(p))

    def _set_fw_local(self, path: Path) -> None:
        ext = path.suffix.lower()
        mode = ""
        if ext == ".tar":
            mode = "ota"
        elif ext == ".bin":
            mode = "bin"

        if mode == "bin":
            if file_is_tar(path):
                messagebox.showerror("Looks like a TAR", "This file looks like a TAR archive but has .bin extension.")
                return
            if not messagebox.askyesno("Confirm BIN", "This is a RAW .bin firmware (NOT an OTA .tar). Proceed?"):
                return

        info_s = ""
        if mode == "ota":
            try:
                inspect_ota_tar(path)
                info_s = f"Local OTA: {path.name}"
            except Exception as e:
                info_s = f"Local OTA invalid: {e}"
        elif mode == "bin":
            info_s = "Local BIN (raw)"

        self._fw_local_path = path
        self._fw_local_mode = mode
        self._fw_local_info = info_s
        if self._fw_source.get().strip() == "local":
            self._apply_fw_view()

    # ---------- Firmware: GitHub ----------

    def _gh_refresh_async(self) -> None:
        self._gh_status.set("GitHub: fetching…")
        threading.Thread(target=self._gh_refresh_worker, daemon=True).start()

    def _gh_refresh_worker(self) -> None:
        try:
            rels_all = github_list_release_tags(timeout_s=main_timeout(8.0))
            rels_stable = [r for r in rels_all if not r.prerelease]
            self._q.put(("gh_rels_cache", (rels_stable, rels_all)))
        except Exception as e:
            self._q.put(("gh_err", str(e)))

    def _gh_apply_visible_releases(self, *, force_latest: bool = False) -> None:
        show_beta = bool(self._gh_show_beta.get())
        rels_map = self._gh_rels_all if show_beta else self._gh_rels_stable
        tags = self._gh_tags_all if show_beta else self._gh_tags_stable

        prev_selected = self._gh_tag.get().strip()
        prev_tag = self._gh_display_to_tag.get(prev_selected, prev_selected)

        self._gh_rels = dict(rels_map)
        self._gh_tags = list(tags)
        self._gh_display_to_tag = {gh_release_label(r): r.tag for r in self._gh_rels.values()}
        self._gh_tag_to_display = {r.tag: gh_release_label(r) for r in self._gh_rels.values()}
        self._gh_combo["values"] = [self._gh_tag_to_display[t] for t in self._gh_tags]

        if force_latest:
            self._gh_tag.set(self._gh_tag_to_display.get(self._gh_tags[0], "") if self._gh_tags else "")
        elif prev_tag and prev_tag in self._gh_rels:
            self._gh_tag.set(self._gh_tag_to_display.get(prev_tag, prev_tag))
        elif self._gh_tags:
            self._gh_tag.set(self._gh_tag_to_display.get(self._gh_tags[0], self._gh_tags[0]))
        else:
            self._gh_tag.set("")

        self._gh_sync_selection()
        suffix = " incl. beta" if show_beta else ""
        self._gh_status.set(f"GitHub: {len(self._gh_tags)} release(s){suffix}")

    def _gh_show_beta_changed(self) -> None:
        if self._gh_rels_all or self._gh_rels_stable:
            self._gh_apply_visible_releases(force_latest=True)
            return
        self._gh_force_latest_on_refresh = True
        self._gh_refresh_async()

    def _gh_asset_for_tag(self, tag: str) -> Tuple[GhRelease, GhAsset]:
        rel = self._gh_rels.get(str(tag or "").strip())
        if not rel:
            raise RuntimeError(f"GitHub tag not found: {tag}")
        asset = github_pick_asset(rel)
        if not asset:
            raise RuntimeError(f"GitHub release has no .tar/.bin asset: {tag}")
        return rel, asset

    def _gh_cached_path(self, tag: str, asset: GhAsset) -> Path:
        return self._gh_tmp_dir / str(tag) / asset.name

    def _gh_cache_is_valid(self, path: Path, asset: GhAsset) -> bool:
        try:
            if not path.is_file():
                return False
            if int(asset.size or 0) > 0:
                return int(path.stat().st_size) == int(asset.size)
            return path.stat().st_size > 0
        except Exception:
            return False

    def _gh_sync_selection(self) -> None:
        selected = self._gh_tag.get().strip()
        tag = self._gh_display_to_tag.get(selected, selected)
        if selected != tag:
            self._gh_tag.set(selected)
        if not tag:
            self._fw_gh_path = None
            self._fw_gh_mode = ""
            self._fw_gh_info = ""
            self._fw_gh_tag = ""
            if self._fw_source.get().strip() == "github":
                self._apply_fw_view()
            return

        try:
            rel, asset = self._gh_asset_for_tag(tag)
        except Exception as e:
            self._fw_gh_path = None
            self._fw_gh_mode = ""
            self._fw_gh_info = f"GitHub {tag}: {e}"
            self._fw_gh_tag = tag
            if self._fw_source.get().strip() == "github":
                self._apply_fw_view()
            return

        cached_path = self._gh_cached_path(tag, asset)
        mode = "ota" if asset.is_tar else "bin"
        if self._gh_cache_is_valid(cached_path, asset):
            suffix = " (cached)"
        else:
            suffix = " (will download on flash)"

        label = gh_release_label(rel)
        if asset.is_bin:
            info = f"GitHub {label} (raw){suffix}"
        else:
            info = f"GitHub {label}{suffix}"

        self._fw_gh_path = cached_path if self._gh_cache_is_valid(cached_path, asset) else None
        self._fw_gh_mode = mode
        self._fw_gh_info = info
        self._fw_gh_tag = tag
        if self._fw_source.get().strip() == "github":
            self._apply_fw_view()

    def _gh_tag_selected(self, _evt=None) -> None:
        self._gh_sync_selection()

    def _gh_get_or_download(self, tag: str, progress_cb=None) -> Tuple[Path, str]:
        _rel, asset = self._gh_asset_for_tag(tag)
        out_path = self._gh_cached_path(tag, asset)
        mode = "ota" if asset.is_tar else "bin"

        if self._gh_cache_is_valid(out_path, asset):
            self._q.put(("fw_set", (str(out_path), mode, tag)))
            return out_path, mode

        self._q.put(("log", (f"[*] GitHub: downloading {tag}", "stage")))
        github_download(asset.url, out_path, progress_cb=progress_cb, timeout_s=main_timeout(30.0))
        self._q.put(("fw_set", (str(out_path), mode, tag)))
        self._q.put(("log", (f"[OK] GitHub ready: {tag}", "ok")))
        return out_path, mode

    def _set_fw_github(self, path: Path, mode: str, tag: str) -> None:
        # store github selection; apply only if github radiobutton is active
        self._fw_gh_path = path
        self._fw_gh_mode = str(mode or "").strip()
        self._fw_gh_tag = str(tag or "").strip()
        label = self._gh_tag_to_display.get(self._fw_gh_tag, self._fw_gh_tag)
        if self._fw_gh_mode == "bin":
            self._fw_gh_info = f"GitHub {label} (raw)"
        elif self._fw_gh_mode == "ota":
            self._fw_gh_info = f"GitHub {label}"
        else:
            self._fw_gh_info = ""

        if self._fw_source.get().strip() == "github":
            self._apply_fw_view()

    # ---------- Devices selection ----------

    def _on_select(self, _evt=None) -> None:
        sel = self._tree.selection()
        if not sel:
            self._selected_key = None
            return
        item = sel[0]
        for k, iid in self._tree_items.items():
            if iid == item:
                self._selected_key = k
                break
        self._refresh_buttons()

    def _open_configurator_selected(self) -> None:
        if not self._selected_key:
            return
        row = self._rows.get(self._selected_key)
        if not row:
            return
        ip = (row.ip or "").strip()
        if not ip:
            self._log_line("[!] no IP for selected device", "err")
            return
        open_external_url(f"http://{ip}/")

    # ---------- Scanning / IP polling ----------

    def _iface_lock(self, iface_id: str) -> threading.Lock:
        if iface_id not in self._iface_locks:
            self._iface_locks[iface_id] = threading.Lock()
        return self._iface_locks[iface_id]

    def _scan_loop(self) -> None:
        while not self._stop.is_set():
            if self._auto_refresh.get():
                self._scan_worker()
            delay = float(self._scan_interval_s.get() or 2.0)
            for _ in range(int(max(1, delay * 10))):
                if self._stop.is_set():
                    break
                time.sleep(main_timeout(0.1))

    def _scan_once_async(self) -> None:
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        # Opportunistic scan: if pcap is in use (flash/get_ip), do not scan.
        if not self._pcap_lock.acquire(blocking=False):
            return
        try:
            rows, seen = self._service.scan_devices(existing_rows=self._rows)
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
            return
        except Exception as e:
            self._q.put(("log", (f"[ERR] scan failed: {e}", "err")))
            return
        finally:
            try:
                self._pcap_lock.release()
            except Exception:
                pass

        self._q.put(("scan", (rows, seen)))

    def _emit_service_event(self, row: DevRow, event: Any) -> None:
        kind = str(getattr(event, "kind", "") or "")
        message = str(getattr(event, "message", "") or "")
        data = dict(getattr(event, "data", {}) or {})

        if kind == "stage":
            self._q.put(("log", ("[*] " + message, "stage")))
            return
        if kind == "warning":
            tag = "err" if "failed" in message else "stage"
            prefix = "[!]" if tag == "err" else "[*]"
            self._q.put(("log", (f"{prefix} {message}", tag)))
            return
        if kind == "progress":
            self._q.put(
                (
                    "progress",
                    (
                        float(data.get("pct") or 0.0),
                        int(data.get("done") or 0),
                        int(data.get("total") or 0),
                        float(data.get("speed") or 0.0),
                    ),
                )
            )
            return
        if kind == "device_changed":
            self._q.put(("log", ("[*] " + message, "stage")))
            return
        if kind == "device_ip":
            self._q.put(("devinfo", (row.key(), str(data.get("ip") or message or ""), "")))
            return
        if kind == "done":
            self._q.put(("log", ("[OK] " + message, "ok")))
            return
        if kind == "error":
            self._q.put(("log", ("[ERR] " + message, "err")))
            return

    def _maybe_poll_ip(self, r: DevRow) -> None:
        key = r.key()
        if r.kind != "rnode-halow":
            return
        if key in self._ip_jobs_inflight:
            return
        now = time.time()
        last = float(self._ip_poll_last.get(key, 0.0))
        # rate limit: 2 seconds
        if (now - last) < main_timeout(2.0):
            return
        self._ip_poll_last[key] = now
        self._ip_jobs_inflight.add(key)
        threading.Thread(target=self._ip_poll_worker, args=(r,), daemon=True).start()

    def _ip_poll_worker(self, r: DevRow) -> None:
        key = r.key()
        try:
            ip_s = ""
            ver_s = ""
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)
                    ans = sess.get_ip(r.mac, tries=1, timeout=main_timeout(0.35))
            if ans is not None:
                ip_s = str(getattr(ans, "ip", "") or "")
                if ip_s == "0.0.0.0":
                    ip_s = ""
                ver_s = str(getattr(ans, "version", "") or "")

            if ip_s and not ver_s:
                for path in ("/api/heartbeat", "/api/version", "/api/info", "/api/get_all"):
                    obj = http_get_json(f"http://{ip_s}{path}", timeout_s=main_timeout(1.0))
                    if isinstance(obj, dict):
                        v = pick_version_from_json(obj)
                        if v:
                            ver_s = v
                            break

            self._q.put(("devinfo", (key, ip_s, ver_s)))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        finally:
            self._ip_jobs_inflight.discard(key)

    # ---------- Actions ----------

    def _ensure_fw_selection(self) -> Optional[FirmwareSelection]:
        src = self._fw_source.get().strip()

        if src == "github":
            selected = self._gh_tag.get().strip()
            tag = self._gh_display_to_tag.get(selected, selected)
            if not tag:
                return None
            if (self._fw_gh_tag or "").strip() != tag:
                self._gh_sync_selection()
            try:
                _rel, asset = self._gh_asset_for_tag(tag)
            except Exception:
                return None
            mode = "ota" if asset.is_tar else "bin"
            path = self._gh_cached_path(tag, asset)
            return FirmwareSelection(
                source=src,
                mode=mode,
                path=(path if self._gh_cache_is_valid(path, asset) else None),
                label=asset.name,
                github_tag=tag,
            )

        if is_builtin_source(src):
            p = self._fw_builtin_path
            mode = (self._fw_builtin_mode or "").strip()
            if not p or not p.is_file() or mode not in ("bin",):
                return None
            return FirmwareSelection(source=src, mode=mode, path=p, label=p.name)

        p = self._fw_local_path
        mode = (self._fw_local_mode or "").strip()
        if not p or not p.is_file() or mode not in ("ota", "bin"):
            return None
        return FirmwareSelection(source=src, mode=mode, path=p, label=p.name)

    def _resolve_selection_path(
        self,
        sel: FirmwareSelection,
        *,
        progress_cb=None,
    ) -> Tuple[Path, str]:
        if sel.source == "github":
            return self._gh_get_or_download(sel.github_tag, progress_cb=progress_cb)
        if not sel.path or not sel.path.is_file():
            raise FileNotFoundError("firmware file not found")
        return sel.path, sel.mode

    def _ensure_selected(self) -> Optional[DevRow]:
        if not self._selected_key:
            messagebox.showinfo("Select device", "Select a device first.")
            return None
        r = self._rows.get(self._selected_key)
        if not r:
            messagebox.showerror("Not found", "Selected device is not available (maybe went offline).")
            return None
        return r

    def _flash_selected(self) -> None:
        r = self._ensure_selected()
        if not r:
            return

        fw = self._ensure_fw_selection()
        if not fw:
            messagebox.showerror("No firmware", "Select a firmware first.")
            return

        needs_preflash = should_require_preflash(fw.mode)
        if needs_preflash:
            try:
                pick_preflash_firmware_name()
            except Exception as e:
                messagebox.showerror("Built-in firmware missing", str(e))
                return

        confirm_msg = f"Device: {r.mac}\n"
        if (r.ip or "").strip():
            confirm_msg += f"IP: {r.ip}\n"
        confirm_msg += f"\nFirmware: {fw.label}\n\nProceed?"

        if not messagebox.askyesno(
            "Confirm flash",
            confirm_msg,
        ):
            return

        if self._busy.is_set():
            return
        self._set_busy(True)
        self._set_progress(0.0, 0, 0, 0.0)
        threading.Thread(
            target=self._flash_worker,
            args=(r, fw),
            daemon=True,
        ).start()

    def _flash_worker(
        self,
        r: DevRow,
        fw_sel: FirmwareSelection,
    ) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    fw_path, mode = self._resolve_selection_path(fw_sel, progress_cb=cb_progress)
                    resolved = FirmwareSelection(
                        source=fw_sel.source,
                        mode=mode,
                        path=fw_path,
                        label=fw_sel.label,
                        github_tag=fw_sel.github_tag,
                    )

                    if mode == "bin":
                        self._service.run_raw_flash(
                            r,
                            resolved,
                            known_rows=list(self._rows.values()),
                            emit=lambda event: self._emit_service_event(r, event),
                        )
                    else:
                        self._service.run_update_device(
                            r,
                            resolved,
                            known_rows=list(self._rows.values()),
                            emit=lambda event: self._emit_service_event(r, event),
                        )

            self._maybe_poll_ip(self._rows.get(r.key(), r))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        except Exception as e:
            self._q.put(("log", (f"[ERR] flash failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
            self._q.put(("busy", False))

    def _reboot_selected(self) -> None:
        r = self._ensure_selected()
        if not r:
            return

        if not messagebox.askyesno(
            "Confirm reboot",
            f"Reboot device via HGIC?\n\nMAC: {r.mac}\nInterface: {r.iface}\n",
        ):
            return

        if self._busy.is_set():
            return
        self._set_busy(True)
        threading.Thread(target=self._reboot_worker, args=(r,), daemon=True).start()

    def _reboot_worker(self, r: DevRow) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    self._service.run_reboot(
                        r,
                        known_rows=list(self._rows.values()),
                        emit=lambda event: self._emit_service_event(r, event),
                    )
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        except Exception as e:
            self._q.put(("log", (f"[ERR] reboot failed: {e}", "err")))
        finally:
            self._q.put(("busy", False))
            self._q.put(("busy", False))

    # ---------- Tree update helpers ----------

    def _row_values(self, r: DevRow) -> Tuple[str, str, str, str, str]:
        return (r.mac, r.iface, r.kind, r.ip, r.ver if r.kind == "rnode-halow" else "")

    def _upsert_row(self, r: DevRow) -> None:
        key = r.key()
        self._rows[key] = r
        vals = self._row_values(r)
        if key in self._tree_items:
            self._tree.item(self._tree_items[key], values=vals)
        else:
            self._tree_items[key] = self._tree.insert("", tk.END, values=vals)

    def _remove_row(self, key: Tuple[str, str]) -> None:
        iid = self._tree_items.pop(key, None)
        if iid:
            try:
                self._tree.delete(iid)
            except Exception:
                pass
        self._rows.pop(key, None)
        self._ip_poll_last.pop(key, None)
        self._ip_jobs_inflight.discard(key)
        if self._selected_key == key:
            self._selected_key = None

    # ---------- Queue polling ----------

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self._q.get_nowait()

                if kind == "scan":
                    rows, seen = payload
                    for r in rows:
                        self._upsert_row(r)
                        self._maybe_poll_ip(r)
                    # remove offline
                    for k in list(self._rows.keys()):
                        if k not in seen:
                            self._remove_row(k)

                    self._refresh_buttons()

                elif kind == "devinfo":
                    key, ip_s, ver_s = payload
                    r = self._rows.get(key)
                    if r:
                        if isinstance(ip_s, str):
                            r.ip = ip_s
                        if isinstance(ver_s, str) and ver_s:
                            r.ver = ver_s
                        self._upsert_row(r)
                        self._refresh_buttons()

                elif kind == "log":
                    s, tag = payload
                    self._log_line(str(s), tag or "")

                elif kind == "raw_ethernet_warning":
                    self._show_raw_ethernet_warning_once(str(payload))

                elif kind == "windows_npcap_warning":
                    self._show_windows_npcap_warning_once(str(payload))

                elif kind == "progress":
                    pct, done, total, speed = payload
                    self._set_progress(float(pct), int(done), int(total), float(speed))

                elif kind == "busy":
                    self._set_busy(bool(payload))

                elif kind == "gh_rels_cache":
                    rels_stable, rels_all = payload
                    self._gh_rels_stable = {r.tag: r for r in rels_stable}
                    self._gh_rels_all = {r.tag: r for r in rels_all}
                    self._gh_tags_stable = [r.tag for r in rels_stable]
                    self._gh_tags_all = [r.tag for r in rels_all]
                    force_latest = bool(self._gh_force_latest_on_refresh)
                    self._gh_force_latest_on_refresh = False
                    self._gh_apply_visible_releases(force_latest=force_latest)

                elif kind == "gh_err":
                    self._gh_status.set("GitHub: error")
                    self._log_line(f"[ERR] GitHub: {payload}", "err")

                elif kind == "gh_confirm_bin":
                    tag, name = payload
                    ok = True
                    if not ok:
                        self._log_line("[*] GitHub download cancelled", "stage")
                        # clear selection
                        self._gh_tag.set("")
                        self._fw_mode.set("")
                        self._fw_info.set("")
                        self._refresh_buttons()

                elif kind == "fw_set":
                    p_str, mode, tag = payload
                    self._set_fw_github(resolve_path(p_str), mode, tag)

        except queue.Empty:
            pass

        self.after(80, self._poll_queue)

    # ---------- Close ----------

    def _on_close(self) -> None:
        self._stop.set()
        try:
            if hasattr(self, "_gh_tmp") and self._gh_tmp is not None:
                self._gh_tmp.cleanup()
        except Exception:
            pass

        try:
            if hasattr(self, "_builtin_tmp") and self._builtin_tmp is not None:
                self._builtin_tmp.cleanup()
        except Exception:
            pass

        try:
            self.destroy()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass


def main() -> None:
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
