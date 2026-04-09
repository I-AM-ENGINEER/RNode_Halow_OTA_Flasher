from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence, TextIO

from .common import file_is_tar
from .github import GhRelease, github_download, github_pick_asset
from .models import DeviceRow, FirmwareSelection, ServiceEvent
from .service import FlasherService

RAW_ETHERNET_COMMANDS = {"scan", "update", "raw-flash", "get-ip", "reboot", "open-web"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rnode-halow-flasher")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--json", action="store_true")
    scan_parser.add_argument("--quiet", action="store_true")

    releases_parser = subparsers.add_parser("releases")
    releases_parser.add_argument("--json", action="store_true")
    releases_parser.add_argument("--quiet", action="store_true")

    update_parser = subparsers.add_parser("update")
    _add_target_args(update_parser)
    source = update_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--release")
    source.add_argument("--file")
    update_parser.add_argument("--json", action="store_true")
    update_parser.add_argument("--quiet", action="store_true")

    raw_parser = subparsers.add_parser("raw-flash")
    _add_target_args(raw_parser)
    raw_source = raw_parser.add_mutually_exclusive_group(required=True)
    raw_source.add_argument("--release")
    raw_source.add_argument("--file")
    raw_parser.add_argument("--json", action="store_true")
    raw_parser.add_argument("--quiet", action="store_true")

    get_ip_parser = subparsers.add_parser("get-ip")
    _add_target_args(get_ip_parser)
    get_ip_parser.add_argument("--json", action="store_true")
    get_ip_parser.add_argument("--quiet", action="store_true")

    reboot_parser = subparsers.add_parser("reboot")
    _add_target_args(reboot_parser)
    reboot_parser.add_argument("--json", action="store_true")
    reboot_parser.add_argument("--quiet", action="store_true")

    open_web_parser = subparsers.add_parser("open-web")
    _add_target_args(open_web_parser)
    open_web_parser.add_argument("--json", action="store_true")
    open_web_parser.add_argument("--quiet", action="store_true")

    wizard_parser = subparsers.add_parser("wizard")
    wizard_parser.add_argument("--quiet", action="store_true")

    return parser


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mac", required=True)
    parser.add_argument("--iface")


def main(
    argv: Sequence[str] | None = None,
    *,
    service: Any | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    input_fn: Callable[[str], str] = input,
) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    stdout = stdout or __import__("sys").stdout
    stderr = stderr or __import__("sys").stderr
    service = service or FlasherService()

    try:
        if getattr(args, "command", "") in RAW_ETHERNET_COMMANDS:
            _emit_environment_warnings(service, stderr)
        if args.command == "scan":
            return _cmd_scan(service, args, stdout)
        if args.command == "releases":
            return _cmd_releases(service, args, stdout)
        if args.command == "update":
            return _cmd_update(service, args, stdout, stderr)
        if args.command == "raw-flash":
            return _cmd_raw_flash(service, args, stdout, stderr)
        if args.command == "get-ip":
            return _cmd_get_ip(service, args, stdout, stderr)
        if args.command == "reboot":
            return _cmd_reboot(service, args, stdout, stderr)
        if args.command == "open-web":
            return _cmd_open_web(service, args, stdout, stderr)
        if args.command == "wizard":
            return _cmd_wizard(service, stdout, stderr, input_fn)
    except ValueError as exc:
        print(str(exc), file=stderr)
        return 2
    except FileNotFoundError as exc:
        print(str(exc), file=stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=stderr)
        return 1

    print(f"unknown command: {args.command}", file=stderr)
    return 2


def _emit_environment_warnings(service: Any, stderr: TextIO) -> None:
    for message in list(getattr(service, "validate_environment", lambda: [])() or []):
        print(message, file=stderr)


def _cmd_scan(service: Any, args: Any, stdout: TextIO) -> int:
    rows, _seen = service.scan_devices(existing_rows={})
    if args.json:
        print(json.dumps({"devices": [_row_to_dict(row) for row in rows]}), file=stdout)
        return 0

    if not args.quiet:
        for idx, row in enumerate(rows, start=1):
            print(f"{idx:>2}. {row.mac}  {row.iface}  {row.kind}  {row.ip}  {row.ver}", file=stdout)
    return 0


def _cmd_releases(service: Any, args: Any, stdout: TextIO) -> int:
    releases = list(service.list_releases(stable_only=False))
    if args.json:
        print(
            json.dumps(
                {
                    "releases": [
                        {
                            "tag": release.tag,
                            "prerelease": release.prerelease,
                            "selected_asset": _asset_to_dict(github_pick_asset(release)),
                        }
                        for release in releases
                    ]
                }
            ),
            file=stdout,
        )
        return 0

    if not args.quiet:
        for release in releases:
            asset = github_pick_asset(release)
            asset_name = asset.name if asset is not None else "-"
            print(f"{release.tag}  {asset_name}", file=stdout)
    return 0


def _cmd_update(service: Any, args: Any, stdout: TextIO, stderr: TextIO) -> int:
    rows, _seen = service.scan_devices(existing_rows={})
    target = service.select_target(rows, mac=args.mac, iface=args.iface)

    if args.file:
        firmware_path = Path(args.file).expanduser()
        firmware = FirmwareSelection(source="local", mode="ota", path=firmware_path, label=firmware_path.name)
        return _render_events(service.update_device(target, firmware, known_rows=rows), stdout, stderr, args)

    release_tag = str(args.release or "").strip()
    releases = list(service.list_releases(stable_only=(release_tag == "latest")))
    release = _pick_release(releases, release_tag)
    asset = github_pick_asset(release)
    if asset is None:
        raise ValueError(f"release has no usable asset: {release.tag}")

    with tempfile.TemporaryDirectory(prefix="rnode-halow-cli-") as td:
        download_path = Path(td) / asset.name
        github_download(asset.url, download_path)
        firmware = FirmwareSelection(
            source="github",
            mode=("ota" if asset.is_tar else "bin"),
            path=download_path,
            label=asset.name,
            github_tag=release.tag,
        )
        if firmware.mode != "ota":
            raise ValueError("update requires an OTA tar release asset")
        return _render_events(service.update_device(target, firmware, known_rows=rows), stdout, stderr, args)


def _cmd_raw_flash(service: Any, args: Any, stdout: TextIO, stderr: TextIO) -> int:
    rows, _seen = service.scan_devices(existing_rows={})
    target = service.select_target(rows, mac=args.mac, iface=args.iface)
    if args.file:
        firmware_path = Path(args.file).expanduser()
        firmware = FirmwareSelection(
            source="local",
            mode=("ota" if file_is_tar(firmware_path) else "bin"),
            path=firmware_path,
            label=firmware_path.name,
        )
        return _render_events(service.raw_flash(target, firmware, known_rows=rows), stdout, stderr, args)

    release_tag = str(args.release or "").strip()
    releases = list(service.list_releases(stable_only=(release_tag == "latest")))
    release = _pick_release(releases, release_tag)
    asset = github_pick_asset(release)
    if asset is None:
        raise ValueError(f"release has no usable asset: {release.tag}")

    with tempfile.TemporaryDirectory(prefix="rnode-halow-cli-") as td:
        download_path = Path(td) / asset.name
        github_download(asset.url, download_path)
        firmware = FirmwareSelection(
            source="github",
            mode=("ota" if asset.is_tar else "bin"),
            path=download_path,
            label=asset.name,
            github_tag=release.tag,
        )
        return _render_events(service.raw_flash(target, firmware, known_rows=rows), stdout, stderr, args)


def _cmd_get_ip(service: Any, args: Any, stdout: TextIO, _stderr: TextIO) -> int:
    rows, _seen = service.scan_devices(existing_rows={})
    target = service.select_target(rows, mac=args.mac, iface=args.iface)
    info = service.get_ip(target)
    if info is None:
        return 1
    payload = {
        "ip": str(getattr(info, "ip", "")),
        "gw": str(getattr(info, "gw", "")),
        "mask": str(getattr(info, "mask", "")),
        "status": int(getattr(info, "status", 0)),
        "version": str(getattr(info, "version", "")),
    }
    if args.json:
        print(json.dumps(payload), file=stdout)
    elif not args.quiet:
        print(json.dumps(payload, ensure_ascii=True), file=stdout)
    return 0


def _cmd_reboot(service: Any, args: Any, stdout: TextIO, stderr: TextIO) -> int:
    rows, _seen = service.scan_devices(existing_rows={})
    target = service.select_target(rows, mac=args.mac, iface=args.iface)
    return _render_events(service.reboot_device(target, known_rows=rows), stdout, stderr, args)


def _cmd_open_web(service: Any, args: Any, stdout: TextIO, stderr: TextIO) -> int:
    rows, _seen = service.scan_devices(existing_rows={})
    target = service.select_target(rows, mac=args.mac, iface=args.iface)
    ok = bool(service.open_web(target))
    if args.json:
        print(json.dumps({"opened": ok}), file=stdout)
    elif not args.quiet:
        print("opened" if ok else "not opened", file=stdout)
    return 0 if ok else 1


def _cmd_wizard(service: Any, stdout: TextIO, stderr: TextIO, input_fn: Callable[[str], str]) -> int:
    for idx, message in enumerate(list(service.validate_environment() or [])):
        if idx == 0:
            print("Environment:", file=stdout)
        print(message, file=stdout)

    rows, _seen = service.scan_devices(existing_rows={})
    if not rows:
        print("No devices discovered", file=stderr)
        return 1

    while True:
        print("Devices:", file=stdout)
        for idx, row in enumerate(rows, start=1):
            print(f"{idx}. {row.mac}  {row.iface}  {row.kind}", file=stdout)
        selected = _prompt_index_or_zero(input_fn("Select device [0=exit]> "), len(rows))
        if selected == 0:
            return 0
        target = rows[selected - 1]

        while True:
            print("Actions:", file=stdout)
            print("1. Update", file=stdout)
            print("2. RAW flash", file=stdout)
            print("3. Get IP", file=stdout)
            print("4. Reboot", file=stdout)
            print("5. List releases", file=stdout)
            action = _prompt_index_or_zero(input_fn("Select action [0=back]> "), 5)

            if action == 0:
                break
            if action == 5:
                _cmd_releases(service, argparse.Namespace(json=False, quiet=False), stdout)
                continue
            if action == 3:
                return _cmd_get_ip(
                    service,
                    argparse.Namespace(mac=target.mac, iface=target.iface_id, json=False, quiet=False),
                    stdout,
                    stderr,
                )
            if action == 4:
                return _cmd_reboot(
                    service,
                    argparse.Namespace(mac=target.mac, iface=target.iface_id, json=False, quiet=False),
                    stdout,
                    stderr,
                )
            if action == 2:
                result = _run_wizard_flash_flow(
                    service,
                    stdout,
                    stderr,
                    input_fn,
                    target,
                    command_name="raw-flash",
                    local_prompt="Local firmware (.tar or .bin) [0=back]> ",
                )
                if result is None:
                    continue
                return result

            result = _run_wizard_flash_flow(
                service,
                stdout,
                stderr,
                input_fn,
                target,
                command_name="update",
                local_prompt="Local ota.tar [0=back]> ",
            )
            if result is None:
                continue
            return result


def _row_to_dict(row: DeviceRow) -> dict[str, Any]:
    return {
        "mac": row.mac,
        "iface": row.iface,
        "iface_id": row.iface_id,
        "kind": row.kind,
        "ip": row.ip,
        "version": row.ver,
    }


def _asset_to_dict(asset: Any) -> dict[str, Any] | None:
    if asset is None:
        return None
    return {"name": asset.name, "size": asset.size, "url": asset.url}


def _render_events(events: Iterable[ServiceEvent], stdout: TextIO, stderr: TextIO, args: Any) -> int:
    rendered = []
    for event in events:
        rendered.append({"kind": event.kind, "message": event.message, "data": event.data})
        if args.json:
            continue
        if args.quiet and event.kind not in {"error", "done"}:
            continue
        stream = stderr if event.kind == "error" else stdout
        print(_format_event(event), file=stream)

    if args.json:
        print(json.dumps({"events": rendered}), file=stdout)

    for event in reversed(rendered):
        if event["kind"] == "error":
            return 1
        if event["kind"] == "done":
            return 0
    return 0


def _format_event(event: ServiceEvent) -> str:
    if event.kind == "stage":
        return f"[*] {event.message}"
    if event.kind == "warning":
        return f"[!] {event.message}"
    if event.kind == "progress":
        pct = float(event.data.get("pct") or 0.0)
        done = int(event.data.get("done") or 0)
        total = int(event.data.get("total") or 0)
        return f"[{pct:6.2f}%] {done}/{total}"
    if event.kind == "device_changed":
        return f"[*] {event.message}"
    if event.kind == "device_ip":
        return f"[+] IP {event.data.get('ip') or event.message}"
    if event.kind == "done":
        return f"[OK] {event.message}"
    if event.kind == "error":
        return f"[ERR] {event.message}"
    return event.message


def _pick_release(releases: Sequence[GhRelease], tag: str) -> GhRelease:
    if not releases:
        raise ValueError("no releases available")
    if tag == "latest":
        return releases[0]
    for release in releases:
        if release.tag == tag:
            return release
    raise ValueError(f"release not found: {tag}")


def _prompt_index(raw: str, upper_bound: int) -> int:
    selected = int(raw, 10)
    if not (1 <= selected <= upper_bound):
        raise ValueError("selection out of range")
    return selected


def _prompt_index_or_zero(raw: str, upper_bound: int) -> int:
    selected = int(raw, 10)
    if not (0 <= selected <= upper_bound):
        raise ValueError("selection out of range")
    return selected


def _prompt_source_choice(input_fn: Callable[[str], str], action_name: str) -> str:
    raw = input_fn(f"{action_name} source: 1) GitHub 2) Local [0=back] > ").strip()
    if raw == "0":
        return "back"
    if raw == "1":
        return "github"
    if raw == "2":
        return "local"
    raise ValueError("selection out of range")


def _prompt_github_release(service: Any, stdout: TextIO, input_fn: Callable[[str], str], *, limit: int = 5) -> str:
    releases = list(service.list_releases(stable_only=True))
    if not releases:
        raise ValueError("no releases available")

    visible = list(releases[:limit])
    print("GitHub releases:", file=stdout)
    for idx, release in enumerate(visible, start=1):
        asset = github_pick_asset(release)
        asset_name = asset.name if asset is not None else "-"
        print(f"{idx}. {release.tag}  {asset_name}", file=stdout)

    raw = input_fn(f"Select release [Enter=latest, 0=back, 1-{len(visible)}]> ").strip()
    if raw == "":
        return visible[0].tag
    selected = _prompt_index_or_zero(raw, len(visible))
    if selected == 0:
        return ""
    return visible[selected - 1].tag


def _prompt_local_path(input_fn: Callable[[str], str], prompt: str) -> Path | None:
    raw = input_fn(prompt).strip()
    if raw == "0":
        return None
    return Path(raw).expanduser()


def _confirm_wizard_operation(
    stdout: TextIO,
    input_fn: Callable[[str], str],
    *,
    target: DeviceRow,
    mode: str,
    source_label: str,
) -> bool:
    print("Summary:", file=stdout)
    print(f"Mode: {mode}", file=stdout)
    print(f"Device: {target.mac}", file=stdout)
    print(f"Interface: {target.iface}", file=stdout)
    print(f"Firmware: {source_label}", file=stdout)
    raw = input_fn("Proceed [Enter=yes, 0=back]> ").strip()
    if raw == "":
        return True
    if raw == "0":
        return False
    raise ValueError("selection out of range")


def _run_wizard_flash_flow(
    service: Any,
    stdout: TextIO,
    stderr: TextIO,
    input_fn: Callable[[str], str],
    target: DeviceRow,
    *,
    command_name: str,
    local_prompt: str,
) -> int | None:
    action_name = "RAW flash" if command_name == "raw-flash" else "Update"

    while True:
        source = _prompt_source_choice(input_fn, action_name)
        if source == "back":
            return None
        if source == "github":
            tag = _prompt_github_release(service, stdout, input_fn)
            if tag == "":
                continue
            if not _confirm_wizard_operation(
                stdout,
                input_fn,
                target=target,
                mode=command_name,
                source_label=f"GitHub {tag}",
            ):
                continue
            if command_name == "raw-flash":
                return _cmd_raw_flash(
                    service,
                    argparse.Namespace(mac=target.mac, iface=target.iface_id, release=tag, file=None, json=False, quiet=False),
                    stdout,
                    stderr,
                )
            return _cmd_update(
                service,
                argparse.Namespace(mac=target.mac, iface=target.iface_id, release=tag, file=None, json=False, quiet=False),
                stdout,
                stderr,
            )

        file_path = _prompt_local_path(input_fn, local_prompt)
        if file_path is None:
            continue
        if not _confirm_wizard_operation(
            stdout,
            input_fn,
            target=target,
            mode=command_name,
            source_label=str(file_path),
        ):
            continue
        if command_name == "raw-flash":
            return _cmd_raw_flash(
                service,
                argparse.Namespace(mac=target.mac, iface=target.iface_id, release=None, file=str(file_path), json=False, quiet=False),
                stdout,
                stderr,
            )
        return _cmd_update(
            service,
            argparse.Namespace(mac=target.mac, iface=target.iface_id, release=None, file=str(file_path), json=False, quiet=False),
            stdout,
            stderr,
        )
