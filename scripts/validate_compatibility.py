#!/usr/bin/env python3
"""Validate release compatibility before any service mutation."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

MAX_DOCUMENT_BYTES = 131_072
MAX_INT = 2_147_483_647
SAFE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
SAFE_DISTRIBUTION = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SAFE_CONTRACT = re.compile(r"^[a-z][a-z0-9.-]{0,127}$")
MANIFEST_KEYS = {
    "schema_version",
    "distribution",
    "supported_topology_revisions",
    "ownership_generation",
    "contracts",
    "database_schema",
}
CONTRACT_KEYS = {"provides", "requires"}
PROVIDE_KEYS = {"kind", "name", "major"}
REQUIREMENT_KEYS = {
    "provider",
    "kind",
    "name",
    "minimum_major",
    "maximum_major",
}
DATABASE_SCHEMA_KEYS = {"revision", "rollback_floor"}
SET_KEYS = {"schema_version", "manifests"}
CONTRACT_KINDS = {"api", "event"}


class CompatibilityError(ValueError):
    """A compatibility manifest or the resulting active set is unsafe."""


def _integer(value: object, field: str, *, minimum: int = 1) -> int:
    if type(value) is not int or not minimum <= value <= MAX_INT:
        raise CompatibilityError(f"{field} must be an integer from {minimum} to {MAX_INT}")
    return value


def _safe_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not SAFE_NAME.fullmatch(value):
        raise CompatibilityError(f"{field} is invalid")
    return value


def _distribution(value: object, field: str) -> str:
    if not isinstance(value, str) or not SAFE_DISTRIBUTION.fullmatch(value):
        raise CompatibilityError(f"{field} is invalid")
    return value


def _contract_name(value: object, field: str) -> str:
    if not isinstance(value, str) or not SAFE_CONTRACT.fullmatch(value):
        raise CompatibilityError(f"{field} is invalid")
    return value


def _kind(value: object, field: str) -> str:
    if value not in CONTRACT_KINDS:
        raise CompatibilityError(f"{field} must be api or event")
    return str(value)


def _validate_provides(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise CompatibilityError("contracts.provides must be an array")
    identities: list[tuple[str, str, int]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != PROVIDE_KEYS:
            raise CompatibilityError(f"contracts.provides[{index}] has unknown or missing fields")
        identities.append(
            (
                _kind(item["kind"], f"contracts.provides[{index}].kind"),
                _contract_name(item["name"], f"contracts.provides[{index}].name"),
                _integer(item["major"], f"contracts.provides[{index}].major"),
            )
        )
    if identities != sorted(set(identities)):
        raise CompatibilityError("contracts.provides must be unique and sorted")
    logical = [(kind, name) for kind, name, _ in identities]
    if len(logical) != len(set(logical)):
        raise CompatibilityError("a contract can provide only one active major")
    return value


def _validate_requirements(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise CompatibilityError("contracts.requires must be an array")
    identities: list[tuple[str, str, str, int, int]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != REQUIREMENT_KEYS:
            raise CompatibilityError(f"contracts.requires[{index}] has unknown or missing fields")
        minimum = _integer(
            item["minimum_major"],
            f"contracts.requires[{index}].minimum_major",
        )
        maximum = _integer(
            item["maximum_major"],
            f"contracts.requires[{index}].maximum_major",
        )
        if minimum > maximum:
            raise CompatibilityError("contract major range is inverted")
        identities.append(
            (
                _distribution(item["provider"], f"contracts.requires[{index}].provider"),
                _kind(item["kind"], f"contracts.requires[{index}].kind"),
                _contract_name(item["name"], f"contracts.requires[{index}].name"),
                minimum,
                maximum,
            )
        )
    if identities != sorted(set(identities)):
        raise CompatibilityError("contracts.requires must be unique and sorted")
    logical = [(provider, kind, name) for provider, kind, name, _, _ in identities]
    if len(logical) != len(set(logical)):
        raise CompatibilityError("a required contract can declare only one major range")
    return value


def _validate_database_schema(value: object) -> dict[str, int] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != DATABASE_SCHEMA_KEYS:
        raise CompatibilityError("database_schema has unknown or missing fields")
    revision = _integer(value["revision"], "database_schema.revision")
    rollback_floor = _integer(value["rollback_floor"], "database_schema.rollback_floor")
    if rollback_floor > revision:
        raise CompatibilityError("database schema rollback floor exceeds its revision")
    return value


def validate_manifest(document: object) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
        raise CompatibilityError("compatibility manifest has unknown or missing fields")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise CompatibilityError("compatibility manifest schema is unsupported")
    _distribution(document["distribution"], "distribution")
    revisions = document["supported_topology_revisions"]
    if (
        not isinstance(revisions, list)
        or not revisions
        or not all(isinstance(item, str) and SAFE_NAME.fullmatch(item) for item in revisions)
        or revisions != sorted(set(revisions))
    ):
        raise CompatibilityError("supported topology revisions must be unique and sorted")
    _integer(document["ownership_generation"], "ownership_generation")
    contracts = document["contracts"]
    if not isinstance(contracts, dict) or set(contracts) != CONTRACT_KEYS:
        raise CompatibilityError("contracts has unknown or missing fields")
    _validate_provides(contracts["provides"])
    _validate_requirements(contracts["requires"])
    _validate_database_schema(document["database_schema"])
    return document


def _manifest_map(manifests: list[dict[str, Any]], *, require_sorted: bool) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    distributions: list[str] = []
    for document in manifests:
        validated = validate_manifest(document)
        distribution = str(validated["distribution"])
        if distribution in result:
            raise CompatibilityError(f"duplicate compatibility manifest for {distribution}")
        result[distribution] = validated
        distributions.append(distribution)
    if require_sorted and distributions != sorted(distributions):
        raise CompatibilityError("compatibility manifests must be sorted by distribution")
    return result


def validate_compatibility_set(
    manifests: object,
    *,
    topology_revision: str,
) -> dict[str, Any]:
    _safe_name(topology_revision, "topology revision")
    if not isinstance(manifests, list) or not manifests:
        raise CompatibilityError("compatibility set must contain manifests")
    manifest_map = _manifest_map(manifests, require_sorted=True)
    provided: dict[tuple[str, str, str], int] = {}
    for distribution, document in manifest_map.items():
        if topology_revision not in document["supported_topology_revisions"]:
            raise CompatibilityError(
                f"{distribution} does not support topology revision {topology_revision}"
            )
        for contract in document["contracts"]["provides"]:
            provided[(distribution, contract["kind"], contract["name"])] = contract["major"]
    for distribution, document in manifest_map.items():
        for requirement in document["contracts"]["requires"]:
            identity = (
                requirement["provider"],
                requirement["kind"],
                requirement["name"],
            )
            actual = provided.get(identity)
            if actual is None:
                raise CompatibilityError(
                    f"{distribution} requires missing {identity[0]} {identity[1]} {identity[2]}"
                )
            if not requirement["minimum_major"] <= actual <= requirement["maximum_major"]:
                raise CompatibilityError(
                    f"{distribution} rejects {identity[0]} {identity[1]} {identity[2]} major {actual}"
                )
    return {"schema_version": 1, "manifests": list(manifest_map.values())}


def validate_set_document(document: object, *, topology_revision: str) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != SET_KEYS:
        raise CompatibilityError("active compatibility set has unknown or missing fields")
    if document["schema_version"] != 1 or isinstance(document["schema_version"], bool):
        raise CompatibilityError("active compatibility set schema is unsupported")
    return validate_compatibility_set(
        document["manifests"],
        topology_revision=topology_revision,
    )


def _validate_upgrade(
    active: dict[str, Any],
    candidate: dict[str, Any],
) -> None:
    distribution = str(candidate["distribution"])
    if candidate["ownership_generation"] < active["ownership_generation"]:
        raise CompatibilityError(f"{distribution} ownership generation cannot move backwards")
    active_schema = active["database_schema"]
    candidate_schema = candidate["database_schema"]
    if (active_schema is None) != (candidate_schema is None):
        raise CompatibilityError(f"{distribution} database schema contract changed kind")
    if active_schema is None:
        return
    if candidate_schema["revision"] < active_schema["rollback_floor"]:
        raise CompatibilityError(f"{distribution} candidate cannot read the active schema floor")
    if active_schema["revision"] < candidate_schema["rollback_floor"]:
        raise CompatibilityError(f"{distribution} candidate removes the compatible rollback version")


def merge_compatibility_set(
    active_manifests: list[dict[str, Any]],
    candidate_manifests: list[dict[str, Any]],
    *,
    topology_revision: str,
) -> dict[str, Any]:
    active = _manifest_map(active_manifests, require_sorted=True) if active_manifests else {}
    candidates = _manifest_map(candidate_manifests, require_sorted=False)
    if not candidates:
        raise CompatibilityError("candidate compatibility set is empty")
    for distribution, candidate in candidates.items():
        previous = active.get(distribution)
        if previous is not None:
            _validate_upgrade(previous, candidate)
    combined = {**active, **candidates}
    return validate_compatibility_set(
        [combined[name] for name in sorted(combined)],
        topology_revision=topology_revision,
    )


def compatibility_checksum(document: dict[str, Any]) -> str:
    canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_json(path: Path, *, owner_only: bool) -> object:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise CompatibilityError("compatibility path must not be a symlink") from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise CompatibilityError("compatibility path must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise CompatibilityError("compatibility file must be owned by the current user")
        if owner_only and stat.S_IMODE(metadata.st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
            raise CompatibilityError("active compatibility state must be owner-only")
        if not 0 < metadata.st_size <= MAX_DOCUMENT_BYTES:
            raise CompatibilityError("compatibility document size is invalid")
        with os.fdopen(descriptor, encoding="utf-8") as stream:
            descriptor = -1
            try:
                return json.load(stream)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise CompatibilityError("compatibility document must be valid UTF-8 JSON") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    temporary_name: str | None = None
    descriptor = -1
    try:
        for _ in range(16):
            candidate = f".{path.name}.{secrets.token_hex(16)}.tmp"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_name is None:
            raise CompatibilityError("could not allocate a compatibility temporary file")
        os.fchmod(descriptor, 0o600)
        content = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(descriptor)
        os.replace(temporary_name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary_name = None
        os.fsync(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory)
            except FileNotFoundError:
                pass
        os.close(directory)


def _active_manifests(path: Path | None, *, topology_revision: str) -> list[dict[str, Any]]:
    if path is None:
        return []
    if not path.exists():
        if path.is_symlink():
            raise CompatibilityError("active compatibility path must not be a symlink")
        return []
    document = validate_set_document(
        _read_json(path, owner_only=True),
        topology_revision=topology_revision,
    )
    return document["manifests"]


def _candidate_manifests(paths: list[Path]) -> list[dict[str, Any]]:
    if not paths:
        raise CompatibilityError("at least one candidate compatibility manifest is required")
    return [validate_manifest(_read_json(path, owner_only=False)) for path in paths]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate-manifest")
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--topology-revision", required=True)
    for name in ("validate-set", "merge-set"):
        command = commands.add_parser(name)
        command.add_argument("--topology-revision", required=True)
        command.add_argument("--active", type=Path)
        command.add_argument("--candidate", action="append", type=Path, default=[])
        if name == "merge-set":
            command.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-manifest":
            manifest = validate_manifest(_read_json(arguments.manifest, owner_only=False))
            if arguments.topology_revision not in manifest["supported_topology_revisions"]:
                raise CompatibilityError("manifest does not support the selected topology revision")
            document = {"schema_version": 1, "manifests": [manifest]}
        else:
            document = merge_compatibility_set(
                _active_manifests(
                    arguments.active,
                    topology_revision=arguments.topology_revision,
                ),
                _candidate_manifests(arguments.candidate),
                topology_revision=arguments.topology_revision,
            )
            if arguments.command == "merge-set":
                _atomic_write(arguments.output, document)
        print(compatibility_checksum(document))
        return 0
    except (CompatibilityError, OSError) as error:
        print(f"compatibility rejected: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
