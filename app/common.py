from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import webbrowser
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import pwd  # type: ignore
except Exception:
    pwd = None  # type: ignore


MAIN_TIMEOUT_SCALE = 1.0

BUILTIN_PREFLASH_FW_CANDIDATES = [
    "txw8301_v2.4.1.3-38247_2025.11.6_TAIXIN_WNB.bin",
    "E611-orig.bin",
]


def main_timeout(value: float) -> float:
    return float(value) * float(MAIN_TIMEOUT_SCALE)


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


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS"))
    return Path(__file__).resolve().parent.parent


def builtin_fw_dir() -> Path:
    return app_base_dir() / "embedded_fw"


def list_builtin_firmware_names() -> list[str]:
    fw_dir = builtin_fw_dir()
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
    raise FileNotFoundError(f"no built-in firmware found in: {builtin_fw_dir()}")


def extract_builtin_firmware(name: str, dst_dir: Path) -> Path:
    src = builtin_fw_dir() / str(name)
    if not src.is_file():
        raise FileNotFoundError(f"built-in firmware not found: {src}")

    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / src.name
    if (not dst.exists()) or (dst.stat().st_size != src.stat().st_size):
        shutil.copy2(src, dst)
    return dst


def read_builtin_firmware(name: str) -> bytes:
    src = builtin_fw_dir() / str(name)
    if not src.is_file():
        raise FileNotFoundError(f"built-in firmware not found: {src}")
    data = src.read_bytes()
    if not data:
        raise ValueError(f"built-in firmware is empty: {src.name}")
    return data


def is_builtin_source(src: str) -> bool:
    return str(src or "").strip() == "builtin"
