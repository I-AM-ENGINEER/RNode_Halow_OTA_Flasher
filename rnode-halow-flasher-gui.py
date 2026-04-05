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
import ssl
import struct
import subprocess
import queue
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List, Set

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import pwd  # type: ignore
except Exception:
    pwd = None  # type: ignore

from scapy.all import Ether, Raw, AsyncSniffer  # type: ignore

from modules import scan_all_parallel
from modules import HgicSession
from modules.hgic_scan import scan_iface
from modules.hgic_device import (
    RawEthernetAccessError,
    async_sniffer_start_safe,
    async_sniffer_stop_safe,
    raw_ethernet_access_message,
    sendp_safe,
    windows_npcap_missing,
    windows_npcap_missing_message,
    WINDOWS_NPCAP_URL,
)
from modules.hgic_ota import ETH_P_OTA
from modules.hgic_ota_tar import inspect_ota_tar


APP_NAME = "RNode-HaLow Flasher"
APP_VERSION = "1.3.0"

# ----------------------------
# GitHub repo settings
# ----------------------------

REPO_OWNER = "I-AM-ENGINEER"
REPO_NAME  = "RNode_Halow_Firmware"
REPO_URL   = f"https://github.com/{REPO_OWNER}/{REPO_NAME}"
RELEASES_URL = f"{REPO_URL}/releases/"
GITHUB_API_RELEASES = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases"

# NOTE: GitHub releases are downloaded into a temporary directory per GUI run.
# This avoids accidentally flashing a stale cached file when user switches between
# "GitHub release" and "Local file" modes.

BUILTIN_PREFLASH_FW_CANDIDATES = [
    "txw8301_v2.4.1.3-38247_2025.11.6_TAIXIN_WNB.bin",
    "E611-orig.bin",
]

# ----------------------------
# OTA / timeouts (main file only)
# ----------------------------

MAIN_TIMEOUT_SCALE = 1.0


def main_timeout(value: float) -> float:
    return float(value) * float(MAIN_TIMEOUT_SCALE)


ETH_P_OTA_FW_CUSTOM_GET_IP              = 0xF0
ETH_P_OTA_FW_CUSTOM_GET_IP_RESP         = 0xF1
ETH_P_OTA_FW_FORMAT_LITTLEFS            = 0xF2
ETH_P_OTA_FW_FORMAT_LITTLEFS_RESP       = 0xF3


def pack_format_littlefs_req() -> bytes:
    return struct.pack("BB", ETH_P_OTA_FW_FORMAT_LITTLEFS, 0)


def parse_format_littlefs_resp_payload(b: bytes) -> Optional[int]:
    if len(b) < 2:
        return None
    if b[0] != int(ETH_P_OTA_FW_FORMAT_LITTLEFS_RESP):
        return None
    return int(b[1])


def open_external_url(url: str) -> bool:
    if not url:
        return False

    if sys.platform.startswith("linux"):
        try:
            opener: Optional[List[str]] = None
            if shutil.which("xdg-open"):
                opener = ["xdg-open", url]
            elif shutil.which("gio"):
                opener = ["gio", "open", url]

            if opener is None:
                return False

            if hasattr(os, "geteuid") and (os.geteuid() == 0):
                sudo_user = str(os.environ.get("SUDO_USER") or "").strip()
                if not sudo_user:
                    return False

                env_cmd: List[str] = ["env"]
                keep_names = [
                    "DISPLAY",
                    "WAYLAND_DISPLAY",
                    "XAUTHORITY",
                    "DBUS_SESSION_BUS_ADDRESS",
                    "XDG_RUNTIME_DIR",
                    "DESKTOP_SESSION",
                    "XDG_SESSION_TYPE",
                ]
                for name in keep_names:
                    value = str(os.environ.get(name) or "").strip()
                    if value:
                        env_cmd.append(f"{name}={value}")

                if pwd is not None:
                    try:
                        env_cmd.append(f"HOME={pwd.getpwnam(sudo_user).pw_dir}")
                    except Exception:
                        pass

                if shutil.which("runuser"):
                    cmd = ["runuser", "-u", sudo_user, "--", *env_cmd, *opener]
                elif shutil.which("sudo"):
                    cmd = ["sudo", "-u", sudo_user, *env_cmd, *opener]
                else:
                    return False

                res = subprocess.run(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=10.0,
                )
                return int(res.returncode) == 0

            res = subprocess.run(
                opener,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10.0,
            )
            return int(res.returncode) == 0
        except Exception:
            return False

    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


# ----------------------------
# Helpers
# ----------------------------


def strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        return s[1:-1].strip()
    return s


def resolve_path(s: str) -> Path:
    p = Path(strip_quotes(s)).expanduser()
    try:
        return p.resolve()
    except Exception:
        return p.absolute()


def file_is_tar(path: Path) -> bool:
    try:
        return tarfile.is_tarfile(path)
    except Exception:
        return False


def make_minimal_ota_tar_from_bin(bin_path: Path) -> Tuple[Path, tempfile.TemporaryDirectory]:
    td = tempfile.TemporaryDirectory(prefix="rnode_halow_tmp_")
    tar_path = Path(td.name) / "ota_from_bin.tar"
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo(name="fw.bin")
        info.size = bin_path.stat().st_size
        info.mtime = int(time.time())
        with bin_path.open("rb") as f:
            tf.addfile(info, fileobj=f)
    return tar_path, td




def _app_base_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent


def _builtin_fw_dir() -> Path:
    return _app_base_dir() / "embedded_fw"


def list_builtin_firmware_names() -> List[str]:
    fw_dir = _builtin_fw_dir()
    if not fw_dir.is_dir():
        return []
    return sorted(p.name for p in fw_dir.glob("*.bin") if p.is_file())


def pick_preflash_firmware_name() -> str:
    names = list_builtin_firmware_names()
    for cand in BUILTIN_PREFLASH_FW_CANDIDATES:
        if cand in names:
            return cand
    if names:
        return names[0]
    raise FileNotFoundError(f"no built-in firmware found in: {_builtin_fw_dir()}")


def extract_builtin_firmware(name: str, dst_dir: Path) -> Path:
    src = _builtin_fw_dir() / str(name)
    if not src.is_file():
        raise FileNotFoundError(f"built-in firmware not found: {src}")

    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    if (not dst.exists()) or (dst.stat().st_size != src.stat().st_size):
        shutil.copy2(src, dst)
    return dst


def read_builtin_firmware(name: str) -> bytes:
    src = _builtin_fw_dir() / str(name)
    if not src.is_file():
        raise FileNotFoundError(f"built-in firmware not found: {src}")
    data = src.read_bytes()
    if not data:
        raise ValueError(f"built-in firmware is empty: {src.name}")
    return data


def is_builtin_source(src: str) -> bool:
    return str(src or "").strip() == "builtin"


def _build_ssl_context() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore
        cafile = str(certifi.where())
        if cafile:
            return ssl.create_default_context(cafile=cafile)
    except Exception:
        pass
    return ssl.create_default_context()


def _normalize_network_error(exc: BaseException) -> BaseException:
    reason = getattr(exc, "reason", None)
    if isinstance(exc, ssl.SSLCertVerificationError) or isinstance(reason, ssl.SSLCertVerificationError):
        return RuntimeError(
            "TLS certificate verification failed for GitHub. "
            "Install or update the system CA certificates, or install the Python package 'certifi'."
        )
    return exc


def _urlopen(req, timeout_s: float):
    import urllib.request
    try:
        return urllib.request.urlopen(req, timeout=float(timeout_s), context=_build_ssl_context())
    except Exception as exc:
        raise _normalize_network_error(exc) from exc


def http_get_json(url: str, timeout_s: float = main_timeout(1.0)) -> Optional[Dict[str, Any]]:
    try:
        import urllib.request
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


def fmt_iface(d: Any) -> str:
    iface = getattr(d, "iface_name", None)
    if not iface:
        iface = getattr(d, "iface_id", None)
    if not iface:
        iface = getattr(d, "iface", None)
    return str(iface) if iface is not None else "?"


def fmt_iface_id(d: Any) -> str:
    iface = getattr(d, "iface_id", None)
    if iface:
        return str(iface)
    return fmt_iface(d)


def fmt_mac(d: Any) -> str:
    return str(getattr(d, "src_mac", "")).lower()


def fmt_scan_ver(d: Any) -> str:
    return str(getattr(d, "version_str", "")).strip()


# ----------------------------
# GitHub API (single asset)
# ----------------------------

@dataclass
class GhAsset:
    name: str
    size: int
    url: str

    @property
    def ext(self) -> str:
        return Path(self.name).suffix.lower()

    @property
    def is_tar(self) -> bool:
        return self.ext == ".tar"

    @property
    def is_bin(self) -> bool:
        return self.ext == ".bin"


@dataclass
class GhRelease:
    tag: str
    assets: List[GhAsset]
    prerelease: bool = False


def gh_release_label(rel: GhRelease) -> str:
    tag = str(rel.tag or "").strip()
    if rel.prerelease:
        return f"{tag} (beta)"
    return tag


def github_list_release_tags(
    *,
    timeout_s: float = main_timeout(8.0),
) -> List[GhRelease]:
    import urllib.request
    req = urllib.request.Request(GITHUB_API_RELEASES, headers={"User-Agent": "rnode-halow-gui"})
    with _urlopen(req, timeout_s) as r:
        data = r.read()
    obj = json.loads(data.decode("utf-8", errors="replace"))
    if not isinstance(obj, list):
        return []

    rels: List[GhRelease] = []
    for rr in obj:
        if not isinstance(rr, dict):
            continue
        tag = str(rr.get("tag_name") or "").strip()
        if not tag:
            continue

        prerelease = bool(rr.get("prerelease"))

        assets: List[GhAsset] = []
        a_raw = rr.get("assets")
        if isinstance(a_raw, list):
            for a in a_raw:
                if not isinstance(a, dict):
                    continue
                nm = str(a.get("name") or "").strip()
                url = str(a.get("browser_download_url") or "").strip()
                sz = int(a.get("size") or 0)
                if not nm or not url:
                    continue
                ext = Path(nm).suffix.lower()
                if ext not in (".tar", ".bin"):
                    continue
                assets.append(GhAsset(name=nm, size=sz, url=url))

        rels.append(GhRelease(tag=tag, assets=assets, prerelease=prerelease))

    return rels


def github_pick_asset(rel: GhRelease) -> Optional[GhAsset]:
    # Prefer modern OTA tar
    for a in rel.assets:
        if a.is_tar:
            return a
    for a in rel.assets:
        if a.is_bin:
            return a
    return None


def github_download(url: str, out_path: Path, progress_cb=None, timeout_s: float = main_timeout(30.0)) -> None:
    import urllib.request

    out_path.parent.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "rnode-halow-gui",
            "Accept": "application/octet-stream",
        },
    )

    with _urlopen(req, timeout_s) as r:
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        t0 = time.time()

        with out_path.open("wb") as f:
            while True:
                chunk = r.read(64 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)

                if progress_cb:
                    dt = max(0.001, time.time() - t0)
                    speed = done / dt
                    progress_cb(done, total, speed)


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


@dataclass
class FlashTargetState:
    iface_id: str
    current_mac: str
    allowed_macs: Set[str] = field(default_factory=set)
    blacklist_macs: Set[str] = field(default_factory=set)


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
            devs = scan_all_parallel(packet_cnt=10, period_sec=main_timeout(0.010), sniff_time=main_timeout(0.5))
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

        now = time.time()
        seen: set[Tuple[str, str]] = set()
        rows: List[DevRow] = []

        for d in devs or []:
            mac = fmt_mac(d)
            iface = fmt_iface(d)
            iface_id = fmt_iface_id(d)
            ver = fmt_scan_ver(d)
            kind = "rnode-halow" if is_rnode_halow_by_scan(ver) else "hgic"

            key = (mac, iface_id)
            seen.add(key)

            r = self._rows.get(key, DevRow(mac=mac, iface=iface, iface_id=iface_id))
            r.iface = iface
            r.kind = kind
            r.last_seen_ts = now
            rows.append(r)

        self._q.put(("scan", (rows, seen)))

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

        needs_preflash = not is_builtin_source(fw.source)
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
                    sess = HgicSession(r.iface_id)
                    target = self._build_flash_target_state(r)
                    if target.blacklist_macs:
                        self._q.put(("log", (f"[*] blacklist active: {', '.join(sorted(target.blacklist_macs))}", "stage")))

                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    def cb_stage(msg: str) -> None:
                        self._q.put(("log", ("[*] " + msg, "stage")))

                    def cb_retry(attempt: int, total: int, err: str) -> None:
                        self._q.put(("log", (f"[!] flash attempt {attempt}/{total} failed: {err}; retry in 3s", "err")))

                    fw_path, mode = self._resolve_selection_path(fw_sel, progress_cb=cb_progress)
                    needs_preflash = not is_builtin_source(fw_sel.source)
                    has_www_dir = False
                    if mode == "ota":
                        info = inspect_ota_tar(fw_path)
                        has_www_dir = bool(info.has_www_dir)

                    if needs_preflash:
                        preflash_name = pick_preflash_firmware_name()
                        self._q.put(("log", (f'[*] flash original firmware "{preflash_name}"', "stage")))
                        sess.flash(target.current_mac, read_builtin_firmware(preflash_name), timeout=main_timeout(5.45), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                        self._q.put(("log", ("[OK] original firmware flashed", "ok")))
                        self._q.put(("log", ("[*] reboot original firmware", "stage")))
                        sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                        self._q.put(("log", ("[*] waiting original firmware reboot...", "stage")))
                        if not self._wait_hgic_ready(target, overall_timeout_s=main_timeout(15.0)):
                            raise RuntimeError("original firmware did not return as HGIC within 15 seconds")
                        self._q.put(("log", ("[*] waiting original firmware settle...", "stage")))
                        time.sleep(main_timeout(5.0))
                        self._q.put(("log", ("[OK] original firmware is back online", "ok")))

                    if mode == "bin":
                        self._q.put(("log", ("[*] flash rnode-halow firmware", "stage")))
                        tar_p, td = make_minimal_ota_tar_from_bin(fw_path)
                        try:
                            sess.flash(target.current_mac, tar_p, timeout=main_timeout(5.0), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                            self._q.put(("log", ("[OK] rnode-halow firmware flashed", "ok")))
                        finally:
                            try:
                                td.cleanup()
                            except Exception:
                                pass

                        self._q.put(("log", ("[*] reboot", "stage")))
                        sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                        self._q.put(("log", ("[OK] reboot sent", "ok")))
                        return

                    # mode == "ota"
                    self._q.put(("log", ("[*] flash rnode-halow firmware", "stage")))
                    sess.flash(target.current_mac, fw_path, timeout=main_timeout(5.45), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                    self._q.put(("log", ("[OK] rnode-halow firmware flashed", "ok")))

                    self._q.put(("log", ("[*] reboot", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))

                    if not has_www_dir:
                        self._q.put(("log", ("[OK] flash done", "ok")))
                        return

                    self._q.put(("log", ("[*] waiting IP…", "stage")))
                    ip_s = self._wait_ip(sess, target, overall_timeout_s=main_timeout(80.0))
                    if not ip_s:
                        self._q.put(("log", ("[ERR] IP not acquired (timeout).", "err")))
                        return
                    self._q.put(("devinfo", (r.key(), ip_s, "")))

                    self._q.put(("log", ("[*] format LittleFS", "stage")))
                    self._format_littlefs(sess, target.current_mac)
                    self._q.put(("log", ("[OK] LittleFS formatted", "ok")))
                    self._q.put(("log", ("[*] reboot after LittleFS format", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                    self._q.put(("log", ("[*] waiting IP after LittleFS format reboot…", "stage")))
                    ip_s = self._wait_ip(sess, target, overall_timeout_s=main_timeout(80.0))
                    if not ip_s:
                        self._q.put(("log", ("[ERR] IP not acquired after LittleFS format reboot (timeout).", "err")))
                        return
                    self._q.put(("devinfo", (r.key(), ip_s, "")))
                    self._q.put(("log", ("[*] upload filesystem via TFTP", "stage")))
                    sess.flash_fs(target.current_mac, fw_path, stage_cb=cb_stage, progress_cb=cb_progress)
                    self._q.put(("log", ("[OK] flash done", "ok")))

            self._maybe_poll_ip(self._rows.get(r.key(), r))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        except Exception as e:
            self._q.put(("log", (f"[ERR] flash failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
            self._q.put(("busy", False))

    def _build_flash_target_state(self, r: DevRow) -> FlashTargetState:
        current_mac = str(r.mac or "").lower()
        blacklist_macs: Set[str] = set()

        for row in self._rows.values():
            row_mac = str(getattr(row, "mac", "") or "").lower()
            if not row_mac:
                continue
            if str(getattr(row, "iface_id", "") or "") != str(r.iface_id or ""):
                continue
            if row_mac == current_mac:
                continue
            blacklist_macs.add(row_mac)

        return FlashTargetState(
            iface_id=str(r.iface_id or ""),
            current_mac=current_mac,
            allowed_macs={current_mac},
            blacklist_macs=blacklist_macs,
        )

    def _scan_live_targets(self, state: FlashTargetState) -> List[Tuple[str, str]]:
        try:
            devs = scan_iface(state.iface_id, packet_cnt=6, period_sec=main_timeout(0.010), sniff_time=main_timeout(0.35))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
            return []
        except Exception:
            return []

        out: List[Tuple[str, str]] = []
        seen: Set[str] = set()
        for d in devs or []:
            mac = fmt_mac(d)
            if not mac or mac in seen or mac in state.blacklist_macs:
                continue
            kind = "rnode-halow" if is_rnode_halow_by_scan(fmt_scan_ver(d)) else "hgic"
            out.append((mac, kind))
            seen.add(mac)
        return out

    def _pick_live_target_mac(self, state: FlashTargetState, *, prefer_kind: Optional[str] = None) -> Optional[str]:
        candidates = self._scan_live_targets(state)
        if not candidates:
            return None

        ordered: List[str] = []
        preferred: List[str] = []
        fallback: List[str] = []

        for mac, kind in candidates:
            if prefer_kind is not None and kind == prefer_kind:
                preferred.append(mac)
            else:
                fallback.append(mac)

        ordered.extend(preferred)
        ordered.extend(fallback)

        picked: Optional[str] = None
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
            return None

        old_mac = state.current_mac
        is_new_mac = picked not in state.allowed_macs
        state.allowed_macs.add(picked)
        state.current_mac = picked

        if is_new_mac and old_mac and old_mac != picked:
            self._q.put(("log", (f"[*] target MAC changed: {old_mac} -> {picked}", "stage")))
        if len(ordered) > 1 and picked != old_mac:
            self._q.put(("log", (f"[!] multiple non-blacklisted devices visible; using {picked}", "err")))

        return picked

    def _wait_hgic_ready(self, state: FlashTargetState, *, overall_timeout_s: float = main_timeout(15.0)) -> bool:
        t0 = time.time()
        while time.time() - t0 < overall_timeout_s:
            if self._pick_live_target_mac(state, prefer_kind="hgic"):
                return True
            time.sleep(main_timeout(0.20))
        return False

    def _wait_ip(self, sess: HgicSession, state: FlashTargetState, *, overall_timeout_s: float = main_timeout(60.0)) -> Optional[str]:
        t0 = time.time()
        while time.time() - t0 < overall_timeout_s:
            mac = self._pick_live_target_mac(state, prefer_kind="rnode-halow")
            if mac is None:
                mac = state.current_mac
            try:
                ans = sess.get_ip(mac, tries=1, timeout=main_timeout(0.5))
            except RawEthernetAccessError as e:
                self._queue_raw_ethernet_warning(str(e))
                ans = None
            except Exception:
                ans = None
            if ans is not None:
                ip_s = str(getattr(ans, "ip", "") or "")
                if ip_s and ip_s != "0.0.0.0":
                    return ip_s
            time.sleep(main_timeout(0.4))
        return None

    def _format_littlefs(self, sess: HgicSession, mac: str) -> None:
        dst_mac_s = str(mac or "").lower()
        host_mac_s = str(sess.host_mac or "").lower()
        payload = pack_format_littlefs_req()

        def is_my_resp(p) -> bool:
            if not p.haslayer(Ether) or not p.haslayer(Raw):
                return False
            eth = p[Ether]
            if int(eth.type) != int(ETH_P_OTA):
                return False
            return (eth.src or "").lower() == dst_mac_s and (eth.dst or "").lower() == host_mac_s

        frame = Ether(src=host_mac_s, dst=dst_mac_s, type=ETH_P_OTA) / Raw(load=payload)

        for _ in range(3):
            sn = AsyncSniffer(iface=sess.iface, store=True, lfilter=is_my_resp)
            async_sniffer_start_safe(sn)
            try:
                sendp_safe(frame, iface=sess.iface, verbose=False)
                sn.join(timeout=main_timeout(15.0))
            finally:
                pkts = async_sniffer_stop_safe(sn) or []

            for p in pkts:
                status = parse_format_littlefs_resp_payload(bytes(p[Raw].load))
                if status is None:
                    continue
                if status != 0:
                    raise RuntimeError(f"LittleFS format failed: status={status}")
                return

            time.sleep(main_timeout(0.4))

        raise RuntimeError("LittleFS format failed: timeout")

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
                    sess = HgicSession(r.iface_id)
                    target = self._build_flash_target_state(r)
                    if target.blacklist_macs:
                        self._q.put(("log", (f"[*] blacklist active: {', '.join(sorted(target.blacklist_macs))}", "stage")))
                    self._q.put(("log", ("[*] reboot", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                    self._q.put(("log", ("[OK] reboot sent", "ok")))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        except Exception as e:
            self._q.put(("log", (f"[ERR] reboot failed: {e}", "err")))
        finally:
            self._q.put(("busy", False))


    def _update_worker(self, r: DevRow, tar_path: Path) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)
                    target = self._build_flash_target_state(r)
                    if target.blacklist_macs:
                        self._q.put(("log", (f"[*] blacklist active: {', '.join(sorted(target.blacklist_macs))}", "stage")))

                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    def cb_stage(msg: str) -> None:
                        self._q.put(("log", ("[*] " + msg, "stage")))

                    def cb_retry(attempt: int, total: int, err: str) -> None:
                        self._q.put(("log", (f"[!] flash attempt {attempt}/{total} failed: {err}; retry in 3s", "err")))

                    info = inspect_ota_tar(tar_path)

                    preflash_name = pick_preflash_firmware_name()
                    self._q.put(("log", (f'[*] flash original firmware "{preflash_name}"', "stage")))
                    sess.flash(target.current_mac, read_builtin_firmware(preflash_name), timeout=main_timeout(5.45), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                    self._q.put(("log", ("[OK] original firmware flashed", "ok")))
                    self._q.put(("log", ("[*] reboot original firmware", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                    self._q.put(("log", ("[*] waiting original firmware reboot...", "stage")))
                    if not self._wait_hgic_ready(target, overall_timeout_s=main_timeout(15.0)):
                        raise RuntimeError("original firmware did not return as HGIC within 15 seconds")
                    self._q.put(("log", ("[*] waiting original firmware settle...", "stage")))
                    time.sleep(main_timeout(5.0))
                    self._q.put(("log", ("[OK] original firmware is back online", "ok")))

                    # Stage 1: always flash firmware first via HGIC (fw.bin from ota.tar)
                    self._q.put(("log", ("[*] flash rnode-halow firmware", "stage")))
                    # slightly lower retries vs old GUI to avoid "unnecessary retries"
                    sess.flash(target.current_mac, tar_path, timeout=main_timeout(5.45), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                    self._q.put(("log", ("[OK] rnode-halow firmware flashed", "ok")))

                    self._q.put(("log", ("[*] reboot", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))

                    if not info.has_www_dir:
                        self._q.put(("log", ("[OK] flash done", "ok")))
                        return

                    self._q.put(("log", ("[*] waiting IP…", "stage")))
                    ip_s = self._wait_ip(sess, target, overall_timeout_s=main_timeout(80.0))
                    if not ip_s:
                        self._q.put(("log", ("[ERR] IP not acquired (timeout).", "err")))
                        return
                    self._q.put(("devinfo", (r.key(), ip_s, "")))

                    # Stage 2 (TFTP): upload filesystem files directly from ota.tar
                    self._q.put(("log", ("[*] format LittleFS", "stage")))
                    self._format_littlefs(sess, target.current_mac)
                    self._q.put(("log", ("[OK] LittleFS formatted", "ok")))
                    self._q.put(("log", ("[*] reboot after LittleFS format", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                    self._q.put(("log", ("[*] waiting IP after LittleFS format reboot…", "stage")))
                    ip_s = self._wait_ip(sess, target, overall_timeout_s=main_timeout(80.0))
                    if not ip_s:
                        self._q.put(("log", ("[ERR] IP not acquired after LittleFS format reboot (timeout).", "err")))
                        return
                    self._q.put(("devinfo", (r.key(), ip_s, "")))
                    self._q.put(("log", ("[*] upload filesystem via TFTP", "stage")))
                    sess.flash_fs(target.current_mac, tar_path, stage_cb=cb_stage, progress_cb=cb_progress)
                    self._q.put(("log", ("[OK] flash done", "ok")))

            # refresh ip/version (best-effort)
            self._maybe_poll_ip(self._rows.get(r.key(), r))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        except Exception as e:
            self._q.put(("log", (f"[ERR] update failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
            self._q.put(("busy", False))

    def _raw_worker(self, r: DevRow, fw_path: Path, mode: str) -> None:
        try:
            with self._pcap_lock:
                with self._iface_lock(r.iface_id):
                    sess = HgicSession(r.iface_id)
                    target = self._build_flash_target_state(r)
                    if target.blacklist_macs:
                        self._q.put(("log", (f"[*] blacklist active: {', '.join(sorted(target.blacklist_macs))}", "stage")))

                    def cb_progress(done: int, total: int, speed: float) -> None:
                        pct = (done * 100.0 / total) if total else 0.0
                        self._q.put(("progress", (pct, done, total, speed)))

                    def cb_retry(attempt: int, total: int, err: str) -> None:
                        self._q.put(("log", (f"[!] flash attempt {attempt}/{total} failed: {err}; retry in 3s", "err")))

                    if mode == "ota":
                        self._q.put(("log", ("[*] RAW flash (ota.tar)", "stage")))
                        sess.flash(target.current_mac, fw_path, timeout=main_timeout(5.0), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                        self._q.put(("log", ("[OK] RAW flash done", "ok")))
                    else:
                        self._q.put(("log", ("[*] RAW flash (bin)", "stage")))
                        tar_p, td = make_minimal_ota_tar_from_bin(fw_path)
                        try:
                            sess.flash(target.current_mac, tar_p, timeout=main_timeout(5.0), retries=5, progress_cb=cb_progress, retry_cb=cb_retry)
                            self._q.put(("log", ("[OK] RAW flash done", "ok")))
                        finally:
                            try:
                                td.cleanup()
                            except Exception:
                                pass


                    self._q.put(("log", ("[*] reboot", "stage")))
                    sess.reboot(target.current_mac, flags=0, count=3, period_sec=main_timeout(0.05))
                    self._q.put(("log", ("[OK] reboot sent", "ok")))
        except RawEthernetAccessError as e:
            self._queue_raw_ethernet_warning(str(e))
        except Exception as e:
            self._q.put(("log", (f"[ERR] RAW flash failed: {e}", "err")))
        finally:
            self._q.put(("progress", (0.0, 0, 0, 0.0)))
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
