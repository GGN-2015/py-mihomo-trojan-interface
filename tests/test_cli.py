from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mihomo_trojan_interface.cli import ensure_executable_file, resolve_executable


class CliTests(unittest.TestCase):
    def test_resolve_executable_accepts_existing_file_without_execute_bit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mihomo"
            path.write_text("#!/bin/sh\n", encoding="utf-8")
            if os.name != "nt":
                path.chmod(0o600)

            self.assertEqual(resolve_executable(str(path)), path.resolve())

    @unittest.skipIf(os.name == "nt", "POSIX execute bits are not used on Windows")
    def test_ensure_executable_file_adds_execute_bits(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mihomo"
            path.write_text("#!/bin/sh\n", encoding="utf-8")
            path.chmod(0o600)

            self.assertTrue(ensure_executable_file(path))
            self.assertEqual(path.stat().st_mode & 0o111, 0o111)
            self.assertFalse(ensure_executable_file(path))


if __name__ == "__main__":
    unittest.main()
