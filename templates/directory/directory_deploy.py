"""Публикует immutable каталог и атомарно переключает current; хранит прежнюю ссылку."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import sys
import uuid
from pathlib import Path


def safe(path: Path) -> Path:
    """Защищает managed каталоги от подмены символическими ссылками."""
    for item in (path, *path.parents):
        if item.is_symlink():
            raise ValueError(f"Симлинк вне current: {item}")
    return path


def activate(current: Path, target: Path | None) -> None:
    """Переключает единственную управляемую ссылку без удаления версий и данных."""
    if target is None:
        current.unlink(missing_ok=True)
        return
    temporary = current.with_name(f".current-{uuid.uuid4().hex}")
    temporary.symlink_to(target, target_is_directory=True)
    temporary.replace(current)


def checksums(root: Path) -> dict[str, str]:
    """Подтверждает содержимое версии по каждому файлу payload."""
    result = {}
    for file in sorted(root.rglob("*")):
        safe(file)
        if file.is_file():
            with file.open("rb") as stream:
                result[file.relative_to(root).as_posix()] = hashlib.file_digest(stream, "sha256").hexdigest()
    return result


def main(phase: str) -> None:
    """Применяет одну фазу adapter contract; rollback использует состояние этого run."""
    name = os.environ["W_DISTRIBUTION_NAME"]
    base = safe(Path(os.environ["W_DEPLOY_ROOT"]) / name)
    versions = safe(base / "versions")
    current = base / "current"
    marker = safe(base / ".distribution")
    version = versions / f"{os.environ['W_DISTRIBUTION_VERSION']}-{os.environ['W_DISTRIBUTION_ARCHIVE_SHA256'][:16]}"
    previous_file = safe(Path(os.environ["W_RELEASE_RUN_STATE_DIR"]) / "previous.json")
    if phase == "rollback":
        if not previous_file.exists():
            return
        previous_value = json.loads(previous_file.read_text())["previous"]
        target = Path(previous_value) if previous_value else None
        if target and (target.parent != versions or not safe(target).is_dir()):
            raise ValueError("Предыдущая версия недоступна")
        if current.exists() and not current.is_symlink():
            raise ValueError("current принадлежит другому владельцу")
        activate(current, target)
        return
    if base.exists() and (not marker.is_file() or marker.read_text() != name):
        raise ValueError(f"Каталог принадлежит другому владельцу: {base}")
    if current.exists() or current.is_symlink():
        if not current.is_symlink():
            raise ValueError("current должен быть ссылкой этого adapter")
        previous = Path(os.readlink(current))
        if not previous.is_absolute() or previous.parent != versions or not safe(previous).is_dir():
            raise ValueError("current выходит из каталога versions")
    else:
        previous = None
    source = safe(Path(os.environ["W_DISTRIBUTION_DIR"]) / "payload")
    expected = checksums(source)
    if not expected:
        raise ValueError("Пустой payload")
    if phase == "preflight":
        return
    if phase == "deploy":
        previous_file.parent.mkdir(parents=True, exist_ok=True)
        with previous_file.open("x") as stream:
            json.dump({"previous": str(previous) if previous else None}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        base.mkdir(parents=True, exist_ok=True)
        marker.write_text(name)
        versions.mkdir(exist_ok=True)
        safe(version)
        if version.exists():
            if checksums(version) != expected:
                raise ValueError("Существующая версия изменилась")
        else:
            temporary = versions / f".copy-{uuid.uuid4().hex}"
            try:
                shutil.copytree(source, temporary)
                temporary.rename(version)
            finally:
                if temporary.exists():
                    shutil.rmtree(temporary)
        activate(current, version)
    elif phase == "verify":
        if not current.is_symlink() or Path(os.readlink(current)) != version or checksums(version) != expected:
            raise ValueError("Активная версия не совпадает с payload")
    else:
        raise ValueError(f"Неизвестная фаза: {phase}")


if __name__ == "__main__":
    main(sys.argv[1])
