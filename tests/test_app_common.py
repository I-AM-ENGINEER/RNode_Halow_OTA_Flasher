import tarfile
import tempfile
import unittest
from pathlib import Path

from app.common import make_minimal_ota_tar_from_bin, resolve_path


class ResolvePathTests(unittest.TestCase):
    def test_resolve_path_expands_user_and_returns_absolute_path(self) -> None:
        home = Path.home()
        resolved = resolve_path("~/firmware.tar")
        self.assertEqual(resolved, home / "firmware.tar")


class MakeMinimalOtaTarTests(unittest.TestCase):
    def test_make_minimal_ota_tar_from_bin_wraps_fw_bin(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            bin_path = Path(td) / "firmware.bin"
            payload = b"firmware-payload"
            bin_path.write_bytes(payload)

            tar_path, temp_dir = make_minimal_ota_tar_from_bin(bin_path)
            self.addCleanup(temp_dir.cleanup)

            self.assertTrue(tar_path.is_file())

            with tarfile.open(tar_path, "r") as tf:
                names = tf.getnames()
                self.assertEqual(names, ["fw.bin"])
                extracted = tf.extractfile("fw.bin")
                self.assertIsNotNone(extracted)
                self.assertEqual(extracted.read(), payload)


if __name__ == "__main__":
    unittest.main()
