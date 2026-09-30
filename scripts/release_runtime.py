#!/usr/bin/env python3
"""Применяет проверенный набор ZIP с общим lock и обратным кодовым откатом."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from secure_extract_zip import extract
from validate_compatibility import merge_compatibility_set

ROOT = Path(__file__).resolve().parents[1]
NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SET = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
RUN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")


class ReleaseError(Exception):
    """Связывает техническую причину с этапом и затронутым сервисом."""
    def __init__(self, code: str, message: str, stage: str = "validation", service: str = ""):
        super().__init__(message)
        self.code, self.stage, self.service = code, stage, service


def safe_path(path: Path) -> Path:
    """Отклоняет симлинки во всех компонентах до чтения и записи состояния."""
    path = path.absolute()
    if ".." in path.parts:
        raise ReleaseError("UNSAFE_PATH", f"Путь содержит ..: {path}")
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise ReleaseError("SYMLINK_PATH", f"Симлинк в пути: {entry}")
    return path


def digest(path: Path) -> str:
    """Считает SHA-256 обычного файла потоково, включая большие Docker images."""
    safe_path(path)
    if not path.is_file():
        raise ReleaseError("FILE_MISSING", f"Нет обычного файла: {path}")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path: Path, value: dict) -> None:
    """Атомарно сохраняет состояние запуска с owner-only доступом."""
    safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def load_config(root: Path) -> dict:
    """Разрешает пути окружения относительно checkout и проверяет лимиты."""
    file = safe_path(root / "config/project.json")
    config = json.loads(file.read_text())
    if config.get("schemaVersion") != 1 or not re.fullmatch(r"[A-Z][A-Z0-9]{0,15}", config.get("code", "")):
        raise ReleaseError("INVALID_CONFIG", "Некорректная версия конфигурации или код проекта.")
    for field in ("lockTimeout", "hookTimeout"):
        value = config.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86400:
            raise ReleaseError("INVALID_CONFIG", f"{field}: требуется целое число от 1 до 86400.")
    config["deploy"] = safe_path(root / config["deployRoot"])
    config["state"] = safe_path(root / config["stateRoot"])
    return config


def verify_payload(directory: Path, expected_name: str) -> dict:
    """Проверяет полный checksum-манифест перед выполнением hook."""
    sums = safe_path(directory / "SHA256SUMS")
    listed = {}
    for line in sums.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ReleaseError("INVALID_CHECKSUMS", "Некорректный SHA256SUMS.")
        expected, name = match.groups()
        path = Path(name)
        if path.is_absolute() or ".." in path.parts or name != path.as_posix() or "\\" in name or name == "SHA256SUMS" or name in listed:
            raise ReleaseError("UNSAFE_CHECKSUM_PATH", f"Недопустимый checksum path: {name}")
        if digest(directory / path) != expected:
            raise ReleaseError("CHECKSUM_MISMATCH", f"Не совпал SHA-256: {name}")
        listed[name] = expected
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob("*") if path.is_file() and path != sums}
    if set(listed) != actual or not {"release.env", "deploy.sh", "compatibility.json"} <= actual:
        raise ReleaseError("INCOMPLETE_CHECKSUMS", "Каждый файл ZIP должен присутствовать в SHA256SUMS.")
    manifest = {}
    for line in (directory / "release.env").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or key in manifest:
            raise ReleaseError("INVALID_MANIFEST", "Некорректный release.env.")
        manifest[key] = value
    fields = {f"W_DISTRIBUTION_{key}" for key in ("NAME", "VERSION", "COMMIT")}
    optional = {"W_DISTRIBUTION_ARCH", "W_DISTRIBUTION_IMAGE"}
    if not fields <= set(manifest) or set(manifest) - fields - optional or manifest["W_DISTRIBUTION_NAME"] != expected_name or bool(optional & set(manifest)) != optional.issubset(manifest):
        raise ReleaseError("INVALID_MANIFEST", "Имя ZIP или поля release.env не совпали.")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-?[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*)?", manifest["W_DISTRIBUTION_VERSION"]):
        raise ReleaseError("INVALID_VERSION", "Некорректная версия поставки.")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["W_DISTRIBUTION_COMMIT"]) or ("W_DISTRIBUTION_ARCH" in manifest and manifest["W_DISTRIBUTION_ARCH"] not in {"linux/amd64", "linux/arm64"}):
        raise ReleaseError("INVALID_MANIFEST", "Проверь commit SHA и архитектуру.")
    if "W_DISTRIBUTION_IMAGE" in manifest and not re.fullmatch(r"[a-z0-9][a-z0-9._/:\-]*:[A-Za-z0-9][A-Za-z0-9._-]*", manifest["W_DISTRIBUTION_IMAGE"]):
        raise ReleaseError("INVALID_IMAGE", "Некорректная ссылка на image.")
    subprocess.run(["bash", "-n", str(directory / "deploy.sh")], check=True, capture_output=True)
    return manifest


@contextmanager
def deploy_lock(path: Path, timeout: int):
    """Удерживает общий deploy-lock с ограниченным ожиданием."""
    safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("a") as stream:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ReleaseError("LOCK_TIMEOUT", "Другой релиз удерживает deploy-lock.", "lock")
                time.sleep(0.1)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def hook(item: dict, phase: str, config: dict, root: Path, run_id: str, set_id: str, run_dir: Path) -> None:
    """Передаёт контекст hook через environment и ограничивает время его работы."""
    environment = {**os.environ, **item["manifest"],
        "W_PROJECT_CODE": config["code"], "W_COMPOSE_PROJECT": config["code"].lower(),
        "W_DEPLOY_ROOT": str(config["deploy"]), "W_RELEASES_ROOT": str(root),
        "W_RELEASE_RUN_ID": run_id, "W_RELEASE_SET_ID": set_id,
        "W_DISTRIBUTION_DIR": str(item["directory"]),
        "W_DISTRIBUTION_ARCHIVE": str(item["archive"]),
        "W_DISTRIBUTION_ARCHIVE_SHA256": item["sha256"],
        "W_DISTRIBUTION_STATE_DIR": str(config["state"] / "distributions" / item["name"]),
        "W_RELEASE_RUN_STATE_DIR": str(run_dir / "services" / item["name"]),
        "W_TOPOLOGY_REVISION": config["topologyRevision"],
    }
    print(f"{item['name']}: {phase}", flush=True)
    process = subprocess.Popen(["bash", "./deploy.sh", phase], cwd=item["directory"], env=environment, start_new_session=True)
    try:
        code = process.wait(timeout=config["hookTimeout"])
    except BaseException:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    if code:
        raise ReleaseError("HOOK_FAILED", f"{item['name']}: {phase} завершился с кодом {code}.", phase, item["name"])


def execute(root: Path, set_id: str, *, preflight_only: bool, yes: bool) -> dict:
    """Проверяет snapshot набора и применяет только его сервисы под общим lock."""
    root = safe_path(root)
    if not SET.fullmatch(set_id):
        raise ReleaseError("INVALID_SET", "Недопустимое имя release set.")
    config = load_config(root)
    set_dir = safe_path(root / set_id)
    archives = sorted(set_dir.glob("*.zip"))
    if not archives:
        raise ReleaseError("EMPTY_SET", "В каталоге нет ZIP-поставок.")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    run_dir = safe_path(config["state"] / "runs" / run_id)
    for path in (config["state"] / "active.json", config["state"] / "sets" / f"{set_id}.json", config["deploy"] / ".deploy.lock"):
        safe_path(path)
    with tempfile.TemporaryDirectory(prefix="release-") as temp:
        temporary = Path(temp).resolve()
        items = []
        for archive in archives:
            safe_path(archive)
            if not NAME.fullmatch(archive.stem):
                raise ReleaseError("INVALID_SERVICE", "Имя ZIP должно быть kebab-case.")
            snapshot = temporary / archive.name
            shutil.copyfile(archive, snapshot)
            directory = temporary / archive.stem
            directory.mkdir()
            extract(snapshot, directory, max_files=20000, max_uncompressed_bytes=21474836480)
            manifest = verify_payload(directory, archive.stem)
            compatibility = json.loads((directory / "compatibility.json").read_text())
            if compatibility.get("distribution") != archive.stem:
                raise ReleaseError("COMPATIBILITY_OWNER", "Compatibility manifest принадлежит другому сервису.")
            items.append({"name": archive.stem, "archive": snapshot, "directory": directory, "sha256": digest(snapshot), "manifest": manifest, "compatibility": compatibility})
        immutable = {item["name"]: item["sha256"] for item in items}
        record = config["state"] / "sets" / f"{set_id}.json"
        active_path = config["state"] / "active.json"

        def validate_current() -> dict:
            safe_path(record); safe_path(active_path)
            if record.exists() and json.loads(record.read_text()) != immutable:
                raise ReleaseError("IMMUTABLE_SET_CHANGED", "Состав уже зарегистрированного release set изменился.")
            if {p.stem: digest(p) for p in sorted(set_dir.glob("*.zip"))} != immutable:
                raise ReleaseError("ARCHIVE_CHANGED", "Архивы изменились после snapshot.")
            for item in items:
                verify_payload(item["directory"], item["name"])
                if digest(item["archive"]) != item["sha256"]:
                    raise ReleaseError("ARCHIVE_CHANGED", "Snapshot архива изменился после проверки.")
            active = json.loads(active_path.read_text()).get("manifests", []) if active_path.exists() else []
            return merge_compatibility_set(active, [item["compatibility"] for item in items], topology_revision=config["topologyRevision"])

        validate_current()
        for item in items:
            hook(item, "preflight", config, root, run_id, set_id, run_dir)
        if preflight_only:
            return {"status": "preflight-passed", "set": set_id, "services": list(immutable)}
        if not yes and (not sys.stdin.isatty() or input(f"Применить {set_id}? [yes]: ") != "yes"):
            raise ReleaseError("CONFIRMATION_REQUIRED", "Для применения передай --yes.", "confirmation")
        with deploy_lock(config["deploy"] / ".deploy.lock", config["lockTimeout"]):
            candidate = validate_current()
            for item in items:
                hook(item, "preflight", config, root, run_id, set_id, run_dir)
            candidate = validate_current()
            for item in items:
                safe_path(config["state"] / "distributions" / item["name"])
            run_dir.mkdir(parents=True, mode=0o700)
            save(record, immutable)
            applied = []
            report = {"run": run_id, "set": set_id, "status": "deploying", "services": [], "rollback": [], "details": str(run_dir)}
            for item in items:
                target = run_dir / "artifacts" / item["name"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(item["directory"]), target)
                item["directory"] = target
                archive_target = run_dir / "artifacts" / item["archive"].name
                shutil.move(str(item["archive"]), archive_target)
                item["archive"] = archive_target
                (run_dir / "services" / item["name"]).mkdir(parents=True)
                (config["state"] / "distributions" / item["name"]).mkdir(parents=True, exist_ok=True)
            try:
                for item in items:
                    applied.append(item)
                    report["services"].append(item["name"])
                    save(run_dir / "result.json", report)
                    hook(item, "deploy", config, root, run_id, set_id, run_dir)
                for item in items:
                    hook(item, "verify", config, root, run_id, set_id, run_dir)
                save(active_path, candidate)
                report["status"] = "verified"
            except BaseException as error:
                report.update(status="failed", code=getattr(error, "code", "RELEASE_INTERRUPTED"), stage=getattr(error, "stage", "execution"), error=str(error))
                # Ошибочный deploy мог успеть изменить сервис, поэтому он уже в applied.
                for item in reversed(applied):
                    try:
                        hook(item, "rollback", config, root, run_id, set_id, run_dir)
                        report["rollback"].append({"service": item["name"], "status": "restored"})
                    except BaseException as rollback_error:
                        report["rollback"].append({"service": item["name"], "status": "failed", "error": str(rollback_error)})
                raise ReleaseError(report["code"], f"{error} Отчёт: {run_dir / 'report.txt'}", report["stage"]) from error
            finally:
                save(run_dir / "result.json", report)
                rollback = ", ".join(f"{x['service']}={x['status']}" for x in report["rollback"]) or "не требовался"
                (run_dir / "report.txt").write_text(f"Результат: {report['status']}\nЭтап: {report.get('stage', 'verify')}\nОжидалось: успешные deploy и verify всех поставок.\nФактически: {report.get('error', 'все hooks успешны')}\nRollback: {rollback}\nДанные: принадлежат hooks; runner не удаляет volumes.\nCleanup: временные ZIP удаляются; artifacts сохранены для диагностики.\nСледующий шаг: ./release inspect {run_id}\nПодробности: {run_dir / 'result.json'}\n")
            return report


def main() -> int:
    """Предоставляет один CLI для preflight, применения и чтения отчёта."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    release = commands.add_parser("release")
    release.add_argument("set")
    release.add_argument("--preflight-only", action="store_true")
    release.add_argument("--yes", action="store_true")
    inspect = commands.add_parser("inspect")
    inspect.add_argument("run")
    init = commands.add_parser("init", help="Создать адаптер файловой поставки")
    init.add_argument("name")
    pack = commands.add_parser("pack", help="Подготовить ZIP произвольного payload")
    pack.add_argument("name")
    pack.add_argument("--source", type=Path, required=True)
    pack.add_argument("--version", required=True)
    pack.add_argument("--commit", required=True)
    pack.add_argument("--set", required=True)
    pack.add_argument("--hook", type=Path)
    pack.add_argument("--compatibility", type=Path)
    args = parser.parse_args()
    def interrupted(number, frame):
        raise ReleaseError("SIGNAL_RECEIVED", f"Получен сигнал {number}.", "execution")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.command in {"init", "pack"}:
            from distribution import initialize, pack_distribution
            result = initialize(args.root, args.name) if args.command == "init" else pack_distribution(args.root, args.name, args.source, args.version, args.commit, args.set, hook_path=args.hook, compatibility_path=args.compatibility)
            print(result)
        elif args.command == "inspect":
            if not RUN.fullmatch(args.run):
                raise ReleaseError("INVALID_RUN", "Недопустимый run ID.")
            path = safe_path(load_config(args.root)["state"] / "runs" / args.run / "report.txt")
            print(path.read_text(), end="")
        else:
            print(json.dumps(execute(args.root, args.set, preflight_only=args.preflight_only, yes=args.yes), ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"{getattr(error, 'code', 'RELEASE_FAILED')}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
