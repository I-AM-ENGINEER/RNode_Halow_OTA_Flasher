from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class DeviceRow:
    mac: str
    iface: str
    iface_id: str
    kind: str = ""
    ip: str = ""
    ver: str = ""
    last_seen_ts: float = 0.0

    def key(self) -> tuple[str, str]:
        return (self.mac, self.iface_id)


@dataclass
class FlashTargetState:
    iface_id: str
    current_mac: str
    allowed_macs: set[str] = field(default_factory=set)
    blacklist_macs: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class FirmwareSelection:
    source: str
    mode: str
    path: Path | None
    label: str
    github_tag: str = ""


@dataclass(frozen=True)
class ServiceEvent:
    kind: str
    message: str = ""
    data: dict[str, Any] = field(default_factory=dict)
