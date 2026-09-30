#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "secure_extract_zip.py"
SPEC = importlib.util.spec_from_file_location("secure_extract_zip", MODULE_PATH)
assert SPEC and SPEC.loader
secure_extract_zip = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secure_extract_zip)


class SecureExtractZipTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="task-secure-zip-")
        self.root = Path(self.temp.name)
        self.archive = self.root / "distribution.zip"
        self.destination = self.root / "output"
        self.destination.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_entries(self, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> None:
        with zipfile.ZipFile(self.archive, "w") as handle:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                for name, payload in entries:
                    handle.writestr(name, payload)

    def extract(self, *, max_files: int = 100, max_bytes: int = 1024 * 1024) -> None:
        secure_extract_zip.extract(
            self.archive,
            self.destination,
            max_files=max_files,
            max_uncompressed_bytes=max_bytes,
        )

    def assert_rejected(self, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> None:
        self.write_entries(entries)
        with self.assertRaises(secure_extract_zip.ArchiveError):
            self.extract()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_extracts_regular_tree(self) -> None:
        self.write_entries([
            ("release.env", b"name=value\n"),
            ("payload/", b""),
            ("payload/image.tar", b"image"),
        ])
        self.extract()
        self.assertEqual((self.destination / "payload" / "image.tar").read_bytes(), b"image")

    def test_rejects_traversal_absolute_backslash_and_control_names(self) -> None:
        for name in ("../escape", "/absolute", "folder\\file", "line\nbreak"):
            with self.subTest(name=name):
                self.assert_rejected([(name, b"bad")])

    def test_rejects_symlink_and_special_file(self) -> None:
        symlink = zipfile.ZipInfo("payload/link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assert_rejected([(symlink, b"target")])

        special = zipfile.ZipInfo("payload/device")
        special.create_system = 3
        special.external_attr = (stat.S_IFCHR | 0o600) << 16
        self.assert_rejected([(special, b"")])

    def test_rejects_duplicate_and_casefold_collision(self) -> None:
        self.assert_rejected([("same", b"one"), ("same", b"two")])
        self.assert_rejected([("Payload", b"one"), ("payload", b"two")])

    def test_rejects_file_used_as_parent_directory(self) -> None:
        self.assert_rejected([("payload", b"file"), ("payload/image.tar", b"image")])

    def test_rejects_limits_before_extraction(self) -> None:
        self.write_entries([("one", b"1"), ("two", b"2")])
        with self.assertRaises(secure_extract_zip.ArchiveError):
            self.extract(max_files=1)
        self.assertEqual(list(self.destination.iterdir()), [])

        self.archive.unlink()
        self.write_entries([("large", b"12345")])
        with self.assertRaises(secure_extract_zip.ArchiveError):
            self.extract(max_bytes=4)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_rejects_nonempty_destination(self) -> None:
        self.write_entries([("file", b"data")])
        (self.destination / "existing").write_text("data", encoding="utf-8")
        with self.assertRaises(secure_extract_zip.ArchiveError):
            self.extract()


if __name__ == "__main__":
    unittest.main()
