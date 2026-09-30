#!/usr/bin/env python3

"""Validate and extract a W distribution ZIP without trusting entry names."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath


class ArchiveError(RuntimeError):
    pass


def parse_positive_int(value: str) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise argparse.ArgumentTypeError("нужно целое число") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("значение должно быть больше нуля")
    return parsed


def entry_kind(info: zipfile.ZipInfo) -> str:
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if info.is_dir() or file_type == stat.S_IFDIR:
        return "directory"
    if file_type in (0, stat.S_IFREG):
        return "file"
    if file_type == stat.S_IFLNK:
        return "symlink"
    return "special"


def normalized_name(info: zipfile.ZipInfo) -> tuple[str, tuple[str, ...]]:
    name = info.orig_filename
    if not name:
        raise ArchiveError("ZIP содержит пустое имя")
    if name.startswith(("/", "\\")):
        raise ArchiveError(f"абсолютный путь запрещён: {name!r}")
    if "\\" in name:
        raise ArchiveError(f"обратный слеш запрещён: {name!r}")
    if any(ord(char) < 32 or ord(char) == 127 for char in name):
        raise ArchiveError(f"управляющий символ запрещён: {name!r}")
    if "//" in name:
        raise ArchiveError(f"пустой сегмент пути запрещён: {name!r}")

    trimmed = name[:-1] if name.endswith("/") else name
    path = PurePosixPath(trimmed)
    parts = path.parts
    if not trimmed or not parts or any(part in ("", ".", "..") for part in parts):
        raise ArchiveError(f"небезопасный относительный путь: {name!r}")
    return trimmed, parts


def validate_entries(
    entries: list[zipfile.ZipInfo],
    *,
    max_files: int,
    max_uncompressed_bytes: int,
) -> list[tuple[zipfile.ZipInfo, str, tuple[str, ...], str]]:
    if not entries:
        raise ArchiveError("ZIP пуст")
    if len(entries) > max_files:
        raise ArchiveError(
            f"слишком много записей: {len(entries)} > {max_files}",
        )

    validated: list[tuple[zipfile.ZipInfo, str, tuple[str, ...], str]] = []
    canonical_paths: dict[str, str] = {}
    path_kinds: dict[tuple[str, ...], str] = {}
    total_size = 0

    for info in entries:
        name, parts = normalized_name(info)
        kind = entry_kind(info)
        if kind == "symlink":
            raise ArchiveError(f"симлинк запрещён: {name!r}")
        if kind == "special":
            raise ArchiveError(f"специальный файл запрещён: {name!r}")
        if info.flag_bits & 0x1:
            raise ArchiveError(f"зашифрованная запись запрещена: {name!r}")

        canonical = unicodedata.normalize("NFC", name).casefold()
        previous = canonical_paths.get(canonical)
        if previous is not None:
            raise ArchiveError(
                f"дублирующий или неоднозначный путь: {previous!r} и {name!r}",
            )
        canonical_paths[canonical] = name

        tuple_parts = tuple(parts)
        path_kinds[tuple_parts] = kind
        total_size += info.file_size
        if total_size > max_uncompressed_bytes:
            raise ArchiveError(
                "суммарный распакованный размер превышает лимит "
                f"{max_uncompressed_bytes} байт",
            )
        validated.append((info, name, tuple_parts, kind))

    for _, name, parts, _ in validated:
        for depth in range(1, len(parts)):
            if path_kinds.get(parts[:depth]) == "file":
                parent = "/".join(parts[:depth])
                raise ArchiveError(
                    f"файл {parent!r} одновременно используется как каталог для {name!r}",
                )
    return validated


def extract(
    archive: Path,
    destination: Path,
    *,
    max_files: int,
    max_uncompressed_bytes: int,
) -> None:
    if archive.is_symlink() or not archive.is_file():
        raise ArchiveError(f"архив не является обычным файлом: {archive}")
    if destination.is_symlink() or not destination.is_dir():
        raise ArchiveError(f"каталог назначения недоступен: {destination}")
    if any(destination.iterdir()):
        raise ArchiveError(f"каталог назначения не пуст: {destination}")

    try:
        with zipfile.ZipFile(archive) as handle:
            validated = validate_entries(
                handle.infolist(),
                max_files=max_files,
                max_uncompressed_bytes=max_uncompressed_bytes,
            )
            for info, _, parts, kind in validated:
                target = destination.joinpath(*parts)
                if kind == "directory":
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                with handle.open(info, "r") as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                source_mode = (info.external_attr >> 16) & 0o777
                target.chmod(0o755 if source_mode & 0o111 else 0o644)
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise ArchiveError(str(error)) from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--max-files", required=True, type=parse_positive_int)
    parser.add_argument(
        "--max-uncompressed-bytes",
        required=True,
        type=parse_positive_int,
    )
    args = parser.parse_args()
    try:
        extract(
            args.archive,
            args.destination,
            max_files=args.max_files,
            max_uncompressed_bytes=args.max_uncompressed_bytes,
        )
    except ArchiveError as error:
        print(f"Небезопасный ZIP: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
