from __future__ import annotations

import json
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Optional

from .common import main_timeout


REPO_OWNER = "I-AM-ENGINEER"
REPO_NAME = "RNode_Halow_Firmware"
REPO_URL = f"https://github.com/{REPO_OWNER}/{REPO_NAME}"
RELEASES_URL = f"{REPO_URL}/releases/"
GITHUB_API_RELEASES = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/releases"
USER_AGENT = "rnode-halow-gui"


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class GhRelease:
    tag: str
    assets: List[GhAsset]
    prerelease: bool = False


def gh_release_label(rel: GhRelease) -> str:
    tag = str(rel.tag or "").strip()
    if rel.prerelease:
        return f"{tag} (beta)"
    return tag


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


def parse_github_releases_payload(payload: Any) -> list[GhRelease]:
    if not isinstance(payload, list):
        return []

    rels: list[GhRelease] = []
    for rr in payload:
        if not isinstance(rr, dict):
            continue
        tag = str(rr.get("tag_name") or "").strip()
        if not tag:
            continue

        prerelease = bool(rr.get("prerelease"))
        assets: list[GhAsset] = []
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


def github_list_release_tags(*, timeout_s: float = main_timeout(8.0)) -> list[GhRelease]:
    import urllib.request

    req = urllib.request.Request(GITHUB_API_RELEASES, headers={"User-Agent": USER_AGENT})
    with _urlopen(req, timeout_s) as r:
        data = r.read()
    obj = json.loads(data.decode("utf-8", errors="replace"))
    return parse_github_releases_payload(obj)


def github_pick_asset(rel: GhRelease) -> Optional[GhAsset]:
    for asset in rel.assets:
        if asset.is_tar:
            return asset
    for asset in rel.assets:
        if asset.is_bin:
            return asset
    return None


def github_download(url: str, out_path: Path, progress_cb=None, timeout_s: float = main_timeout(30.0)) -> None:
    import urllib.request

    out_path.parent.mkdir(parents=True, exist_ok=True)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
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
