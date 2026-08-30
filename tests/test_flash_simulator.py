#!/usr/bin/env python3
"""Virtual-device simulator for HgicFlasher.flash_firmware().

No hardware and no network are involved: only the transport (scapy send +
AsyncSniffer) is replaced by a scripted virtual device. Everything else —
pack_fw_data_req, ACK parsing, timeouts, retries — is the real production code
from modules/hgic_flash.py.

The virtual device:
- receives FW_DATA frames exactly as sent by the host,
- writes chunks strictly sequentially (any out-of-order write is recorded as a
  violation — a healthy device must never see one),
- answers with FW_DATA_RESP (0x05) ACK frames according to a per-chunk script:
    ("ack", delay[, dup_delay])  ACK after `delay` seconds, optional duplicate
    ("stall", delay)             ACK much later than the flasher timeout
    ("drop",)                    frame lost in transit, never ACKed

Run:  python tests/test_flash_simulator.py
"""

from __future__ import annotations

import random
import struct
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scapy.all import Ether, Raw  # type: ignore

from modules import hgic_flash as hf
from modules.hgic_ota import ETH_P_OTA

HOST_MAC = "aa:bb:cc:dd:ee:ff"
DEV_MAC = "d6:dd:35:8b:a5:10"
CHUNK = 1400  # must match HgicFlasher.flash_firmware

# Script behavior: returns a tuple describing what the device does with the
# given transmission (off, attempt_no). Default: ACK after 4 ms.
Script = Callable[[int, int], tuple]


def build_ack(off: int, status: int = 0) -> bytes:
    """FW_DATA_RESP payload shaped like parse_fw_ack_payload expects."""
    return b"".join([
        struct.pack(">BB", 0x05, status),
        b"\x00\x00\x00\x00",               # reserved
        struct.pack(">I", off),            # offset, BE
        struct.pack(">I", 0),              # tot_len (not checked by flasher)
        struct.pack(">H", 0),              # length
        struct.pack("<H", 0),              # checksum
        struct.pack(">H", 0x4002),         # chipid
        struct.pack(">H", 0),              # first_word
    ])


class Simulator:
    """Scripted virtual device + fake sniffer transport."""

    def __init__(self, script: Optional[Script] = None, *, fail_bpf: bool = False):
        self.script = script
        self.fail_bpf = fail_bpf

        self.iface = "sim0"
        self.host_mac = HOST_MAC
        self.dev_mac = DEV_MAC

        self.lock = threading.Lock()
        self.events: List[Tuple[float, int, int]] = []  # (due, off, status)
        self.prn = None
        self._dispatch: Optional[threading.Thread] = None

        self.running = False
        self.bpf_starts = 0
        self.attempts: Dict[int, int] = {}      # off -> transmissions seen
        self.written: Dict[int, bytes] = {}     # off -> data written to "flash"
        self.next_off = 0
        self.violations: List[Tuple[int, int]] = []  # (got_off, expected_off)

    # ---------- device side (called from HgicDevice.send) ----------

    def send(self, *, dst_mac: str, payload: bytes) -> None:
        if payload[0] != 0x04:  # only FW_DATA is answered
            return
        off = int.from_bytes(payload[6:10], "big")
        fw_len = int.from_bytes(payload[14:16], "big")
        data = bytes(payload[20:20 + fw_len])

        with self.lock:
            n = self.attempts.get(off, 0) + 1
            self.attempts[off] = n
            beh = self.script(off, n) if self.script else ("ack", 0.004)

            if beh[0] == "drop":
                return  # frame lost: not written, never ACKed

            if off != self.next_off:
                # Device can only write sequentially; out-of-order chunk means
                # the host skipped ahead (e.g. accepted a stale ACK).
                self.violations.append((off, self.next_off))
                return

            self.written[off] = data
            self.next_off = off + len(data)

            if beh[0] == "stall":
                self._schedule(off, delay=beh[1])
            elif beh[0] == "ack":
                self._schedule(off, delay=beh[1])
                if len(beh) > 2:  # duplicate ACK after dup_delay
                    self._schedule(off, delay=beh[2])
            else:
                raise ValueError(f"bad behavior: {beh!r}")

    def _schedule(self, off: int, *, delay: float, status: int = 0) -> None:
        self.events.append((time.monotonic() + delay, off, status))

    # ---------- sniffer side (dispatches ACK frames to prn) ----------

    def start_sniffer(self, prn) -> None:
        self.prn = prn
        self.running = True
        self._dispatch = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatch.start()

    def stop_sniffer(self, **_kw) -> list:
        self.running = False
        if self._dispatch is not None:
            self._dispatch.join(timeout=2.0)
            self._dispatch = None
        return []

    def _dispatch_loop(self) -> None:
        while self.running:
            now = time.monotonic()
            with self.lock:
                due = [e for e in self.events if e[0] <= now]
                if due:
                    self.events = [e for e in self.events if e[0] > now]
            for _due, off, status in due:
                frame = (
                    Ether(src=self.dev_mac, dst=self.host_mac, type=ETH_P_OTA)
                    / Raw(load=build_ack(off, status))
                )
                if self.prn:
                    self.prn(frame)
            time.sleep(0.001)

    # ---------- checks ----------

    def assert_wrote_image(self, fw: bytes) -> None:
        offs = sorted(self.written)
        assert offs == list(range(0, len(fw), CHUNK)), (
            f"device wrote unexpected offsets: {len(offs)} chunks")
        image = b"".join(self.written[off] for off in offs)
        assert image == fw, "device flash content differs from source image"


# ---------------------------- patching ----------------------------

_CURRENT: Optional[Simulator] = None
_ORIG = {}


class _FakeSniffer:
    def __init__(self, iface=None, store=False, prn=None, filter=None, **kw):
        self.prn = prn
        self.filter = filter
        self.running = False

    def start(self):
        sim = _CURRENT
        assert sim is not None
        if self.filter is not None:
            sim.bpf_starts += 1
            if sim.fail_bpf and sim.bpf_starts == 1:
                raise RuntimeError("simulated BPF setup failure")
        sim.start_sniffer(self.prn)
        self.running = True

    def stop(self, **kw):
        sim = _CURRENT
        assert sim is not None
        sim.stop_sniffer(**kw)
        self.running = False
        return []


def _install(sim: Simulator) -> None:
    global _CURRENT
    _CURRENT = sim
    _ORIG.update(
        HgicDevice=hf.HgicDevice,
        AsyncSniffer=hf.AsyncSniffer,
        start=hf.async_sniffer_start_safe,
        stop=hf.async_sniffer_stop_safe,
    )
    hf.HgicDevice = lambda iface: sim
    hf.AsyncSniffer = _FakeSniffer
    hf.async_sniffer_start_safe = lambda sniffer: sniffer.start()
    hf.async_sniffer_stop_safe = lambda sniffer, **kw: sniffer.stop(**kw)


def _restore() -> None:
    hf.HgicDevice = _ORIG["HgicDevice"]
    hf.AsyncSniffer = _ORIG["AsyncSniffer"]
    hf.async_sniffer_start_safe = _ORIG["start"]
    hf.async_sniffer_stop_safe = _ORIG["stop"]


# ---------------------------- scenarios ----------------------------

def make_fw(chunks: int) -> bytes:
    return random.Random(2026).randbytes(chunks * CHUNK)


def run_scenario(
    name: str,
    *,
    script: Optional[Script] = None,
    retries: int,
    timeout: float = 0.4,
    chunks: int = 160,
    fail_bpf: bool = False,
    expect_bpf_fallback: bool = False,
    expect_error: bool = False,
) -> bool:
    sim = Simulator(script, fail_bpf=fail_bpf)
    fw = make_fw(chunks)
    t0 = time.monotonic()
    _install(sim)
    try:
        flasher = hf.HgicFlasher("sim0")
        progress: List[int] = []
        if expect_error:
            try:
                flasher.flash_firmware(
                    DEV_MAC, fw, timeout=timeout, retries=retries,
                    progress_cb=lambda d, t, s: progress.append(d),
                )
            except RuntimeError as e:
                assert "No FW ACK" in str(e), f"unexpected error: {e}"
                print(f"[PASS] {name}: aborted as expected ({e}) "
                      f"[{time.monotonic() - t0:.1f}s]")
                return True
            raise AssertionError("expected RuntimeError, flash completed instead")

        flasher.flash_firmware(
            DEV_MAC, fw, timeout=timeout, retries=retries,
            progress_cb=lambda d, t, s: progress.append(d),
        )

        assert progress and progress[-1] == len(fw), (
            f"progress ended at {progress[-1] if progress else None}/{len(fw)}")
        sim.assert_wrote_image(fw)
        assert not sim.violations, (
            f"device saw out-of-order writes: {sim.violations[:5]}")
        if expect_bpf_fallback:
            # Exactly one BPF attempt (it failed in the simulator); completion
            # proves the fallback re-created the sniffer without a filter.
            assert sim.bpf_starts == 1, (
                f"expected one BPF start attempt, got bpf_starts={sim.bpf_starts}")
        print(f"[PASS] {name}: {chunks} chunks OK, progress 100%, "
              f"image verified, violations=0 [{time.monotonic() - t0:.1f}s]")
        return True
    except AssertionError as e:
        print(f"[FAIL] {name}: {e} [{time.monotonic() - t0:.1f}s]")
        return False
    except Exception as e:
        print(f"[FAIL] {name}: unexpected {type(e).__name__}: {e} "
              f"[{time.monotonic() - t0:.1f}s]")
        return False
    finally:
        _restore()


def ack_script(per_attempt: Dict[Tuple[int, int], tuple], default_delay: float = 0.004) -> Script:
    def script(off: int, n: int) -> tuple:
        return per_attempt.get((off, n), ("ack", default_delay))
    return script


def flaky_script() -> Script:
    """Reproduces the field failure: lost chunks and erase stalls."""
    def script(off: int, n: int) -> tuple:
        if off > 0 and off % (25 * CHUNK) == 0 and n == 1:
            return ("drop",)                       # lost frame -> needs resend
        if off == 100 * CHUNK and n == 1:
            return ("stall", 1.2)                  # erase stall > flasher timeout
        return ("ack", 0.004)
    return script


def stale_ack_script() -> Script:
    """Late duplicate ACK for a previous chunk while the next chunk is lost."""
    def script(off: int, n: int) -> tuple:
        if off == 29 * CHUNK and n == 1:
            return ("ack", 0.004, 0.2)             # duplicate arrives late
        if off == 30 * CHUNK and n == 1:
            return ("drop",)                       # this chunk is lost
        return ("ack", 0.004)
    return script


def soak_script(seed: int = 1234) -> Script:
    rng = random.Random(seed)
    decided: Dict[int, tuple] = {}

    def script(off: int, n: int) -> tuple:
        if n > 1:
            return ("ack", 0.004)                  # resends always succeed
        if off not in decided:
            r = rng.random()
            if r < 0.02:
                decided[off] = ("drop",)
            elif r < 0.03:
                decided[off] = ("stall", 0.7)
            else:
                decided[off] = ("ack", 0.004)
        return decided[off]
    return script


def main() -> int:
    results: List[Tuple[str, bool]] = []

    results.append(("T1 happy path",
                    run_scenario("T1 happy path (all ACKs fast)", retries=2)))
    results.append(("T2 flaky device",
                    run_scenario("T2 flaky device: drops + erase stall", script=flaky_script(), retries=5)))
    results.append(("T3 stale ACK trap",
                    run_scenario("T3 stale ACK duplicate must not skip a chunk", script=stale_ack_script(), retries=5)))
    results.append(("T4 old behavior regression",
                    run_scenario("T4 retries=1 must abort on lost chunk (old bug)",
                                 script=flaky_script(), retries=1, expect_error=True)))
    results.append(("T5 seeded soak",
                    run_scenario("T5 soak: 2% drops + 1% stalls", script=soak_script(), retries=6)))
    results.append(("T6 BPF fallback",
                    run_scenario("T6 BPF filter failure falls back to unfiltered",
                                 fail_bpf=True, expect_bpf_fallback=True, retries=2)))

    print("-" * 60)
    failed = [name for name, ok in results if not ok]
    ok_n = len(results) - len(failed)
    print(f"{ok_n}/{len(results)} scenarios passed" + (f"; FAILED: {failed}" if failed else ""))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
