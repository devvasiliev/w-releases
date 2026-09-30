"""Готовит адаптеры и детерминированные ZIP произвольных командных поставок."""
from __future__ import annotations
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path
from release_runtime import NAME, SET, ROOT, ReleaseError, safe_path, digest, load_config, verify_payload
from validate_compatibility import validate_manifest


def regular_tree(root: Path) -> list[Path]:
    """Полностью проверяет source tree до копирования первого файла."""
    safe_path(root)
    if not root.is_dir():
        raise ReleaseError("SOURCE_MISSING", f"Нужен каталог: {root}")
    files = []
    for path in sorted(root.rglob("*")):
        safe_path(path)
        if path.is_file():
            if any(ord(character) < 32 for character in path.name) or "\\" in path.name:
                raise ReleaseError("INVALID_FILENAME", f"Некорректное имя: {path}")
            files.append(path)
        elif not path.is_dir():
            raise ReleaseError("SPECIAL_FILE", f"Нужен обычный файл: {path}")
    return files


def initialize(root: Path, name: str) -> Path:
    """Создаёт готовый directory adapter; существующее определение сохраняется."""
    safe_path(root)
    if not NAME.fullmatch(name):
        raise ReleaseError("INVALID_SERVICE", "Имя поставки должно быть kebab-case.")
    destination = safe_path(root / "distributions" / name)
    if destination.exists():
        raise ReleaseError("ADAPTER_EXISTS", f"Адаптер уже существует: {destination}")
    template = ROOT / "templates/directory"
    regular_tree(template)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    try:
        for source in template.iterdir():
            shutil.copy2(source, destination / source.name)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return destination


def pack_distribution(root: Path, name: str, source: Path, version: str, commit: str, set_id: str, *, hook_path: Path | None = None, compatibility_path: Path | None = None) -> Path:
    """Упаковывает payload и adapter; существующий ZIP и принятый set неизменяемы."""
    root, source = safe_path(root), safe_path(source)
    if not NAME.fullmatch(name) or not SET.fullmatch(set_id):
        raise ReleaseError("INVALID_SERVICE", "Проверь имя поставки и release set.")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-?[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*)?", version) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("INVALID_MANIFEST", "Нужны версия и полный commit SHA.")
    files = regular_tree(source)
    if not files:
        raise ReleaseError("EMPTY_PAYLOAD", "Каталог payload пуст.")
    config = load_config(root)
    output = safe_path(root / set_id / f"{name}.zip")
    record = safe_path(config["state"] / "sets" / f"{set_id}.json")
    if output.exists() or record.exists():
        raise ReleaseError("IMMUTABLE_SET_CHANGED", "Выбери новый release set; существующий ZIP или применённый набор сохраняется.")
    if output.is_relative_to(source):
        raise ReleaseError("OUTPUT_INSIDE_SOURCE", "ZIP должен находиться вне payload.")
    if hook_path:
        adapter_files = [safe_path(hook_path)]
        if not hook_path.is_file():
            raise ReleaseError("HOOK_MISSING", "Нужен обычный hook-файл.")
        adapter_root = hook_path.parent
    else:
        adapter_root = safe_path(root / "distributions" / name)
        adapter_files = regular_tree(adapter_root)
        if not (adapter_root / "deploy.sh").is_file():
            raise ReleaseError("HOOK_MISSING", f"Выполни ./release init {name} или задай --hook.")
    compatibility = {"schema_version": 1, "distribution": name, "supported_topology_revisions": [config["topologyRevision"]], "ownership_generation": 1, "contracts": {"provides": [], "requires": []}, "database_schema": None}
    if compatibility_path:
        compatibility = json.loads(safe_path(compatibility_path).read_text())
    validate_manifest(compatibility)
    if compatibility["distribution"] != name:
        raise ReleaseError("COMPATIBILITY_OWNER", "Compatibility относится к другой поставке.")
    with tempfile.TemporaryDirectory(prefix="distribution-") as temporary:
        staging = Path(temporary).resolve() / "staging"
        staging.mkdir()
        for path in files:
            target = staging / "payload" / path.relative_to(source)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        for path in adapter_files:
            relative = Path("deploy.sh") if hook_path else path.relative_to(adapter_root)
            if relative.parts[0] in {"payload", "release.env", "SHA256SUMS", "compatibility.json"}:
                raise ReleaseError("ADAPTER_RESERVED_PATH", f"Зарезервированный путь: {relative}")
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
        (staging / "release.env").write_text(f"W_DISTRIBUTION_NAME={name}\nW_DISTRIBUTION_VERSION={version}\nW_DISTRIBUTION_COMMIT={commit}\n")
        (staging / "compatibility.json").write_text(json.dumps(compatibility, indent=2) + "\n")
        (staging / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(staging).as_posix()}\n" for path in regular_tree(staging)))
        verify_payload(staging, name)
        output.parent.mkdir(parents=True, exist_ok=True)
        # Публикуем полный ZIP атомарно; link исключает перезапись параллельным pack.
        descriptor, temporary_archive = tempfile.mkstemp(prefix=f".{name}-", suffix=".zip", dir=output.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    for path in regular_tree(staging):
                        info = zipfile.ZipInfo(path.relative_to(staging).as_posix(), (1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.compress_type = zipfile.ZIP_DEFLATED
                        info.file_size = path.stat().st_size
                        info.external_attr = (stat.S_IFREG | (path.stat().st_mode & 0o777)) << 16
                        with path.open("rb") as source_stream, archive.open(info, "w", force_zip64=True) as target_stream:
                            shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary_archive, 0o644)
            try:
                os.link(temporary_archive, output)
            except FileExistsError as error:
                raise ReleaseError("IMMUTABLE_SET_CHANGED", f"ZIP уже опубликован: {output}") from error
        finally:
            Path(temporary_archive).unlink(missing_ok=True)
    return output
