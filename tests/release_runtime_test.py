"""Проверяет общий CLI на изолированных файловых hooks."""
import fcntl
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from release_runtime import execute, ReleaseError


class ReleaseRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release workspace ")
        self.root = Path(self.temp.name).resolve()
        (self.root / "config").mkdir()
        (self.root / "config/project.json").write_text(json.dumps({
            "schemaVersion": 1, "code": "ATLAS", "name": "Atlas", "deployRoot": ".runtime",
            "stateRoot": ".state", "topologyRevision": "1", "lockTimeout": 1, "hookTimeout": 3,
        }))
        self.events = self.root / "events"
        self.old_events = os.environ.get("RELEASE_TEST_EVENTS")
        os.environ["RELEASE_TEST_EVENTS"] = str(self.events)

    def tearDown(self):
        if self.old_events is None:
            os.environ.pop("RELEASE_TEST_EVENTS", None)
        else:
            os.environ["RELEASE_TEST_EVENTS"] = self.old_events
        self.temp.cleanup()

    def archive(self, name, *, fail="", extra="", corrupt=False, set_id="set-1"):
        directory = self.root / set_id
        directory.mkdir(exist_ok=True)
        hook = f'''#!/usr/bin/env bash
set -euo pipefail
printf '%s:%s\\n' "$W_DISTRIBUTION_NAME" "$1" >> "$RELEASE_TEST_EVENTS"
{extra}
[[ "$1" != "{fail}" ]]
'''
        files = {
            "deploy.sh": hook.encode(),
            "release.env": (f"W_DISTRIBUTION_NAME={name}\nW_DISTRIBUTION_VERSION=1.0.0\nW_DISTRIBUTION_COMMIT={'a'*40}\nW_DISTRIBUTION_ARCH=linux/amd64\nW_DISTRIBUTION_IMAGE={name}:1.0.0\n").encode(),
            "compatibility.json": json.dumps({"schema_version": 1, "distribution": name, "supported_topology_revisions": ["1"], "ownership_generation": 1, "contracts": {"provides": [], "requires": []}, "database_schema": None}).encode(),
        }
        files["SHA256SUMS"] = "".join(f"{hashlib.sha256(content).hexdigest()}  {path}\n" for path, content in sorted(files.items())).encode()
        if corrupt:
            files["deploy.sh"] += b"# changed\n"
        with zipfile.ZipFile(directory / f"{name}.zip", "w") as archive:
            for path, content in files.items():
                archive.writestr(path, content)

    def events_read(self):
        return self.events.read_text().splitlines() if self.events.exists() else []

    def run_release(self, **kwargs):
        return execute(self.root, "set-1", preflight_only=False, yes=True, **kwargs)

    def test_cli_and_partial_set_keep_omitted_service(self):
        self.archive("orders-api")
        result = subprocess.run([str(ROOT / "release"), "--root", str(self.root), "release", "set-1", "--yes"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events_read(), ["orders-api:preflight"] * 2 + ["orders-api:deploy", "orders-api:verify"])
        original = json.loads((self.root / ".state/active.json").read_text())
        self.archive("warehouse-worker", set_id="set-2")
        execute(self.root, "set-2", preflight_only=False, yes=True)
        active = json.loads((self.root / ".state/active.json").read_text())
        self.assertIn(original["manifests"][0], active["manifests"])
        self.assertEqual(self.events_read().count("orders-api:deploy"), 1)

    def test_checksum_failure_prevents_every_hook(self):
        self.archive("alpha")
        self.archive("zeta", corrupt=True)
        with self.assertRaises(ReleaseError) as caught:
            self.run_release()
        self.assertEqual(caught.exception.code, "CHECKSUM_MISMATCH")
        self.assertEqual(self.events_read(), [])

    def test_preflight_failure_prevents_every_deploy(self):
        self.archive("alpha")
        self.archive("zeta", fail="preflight")
        with self.assertRaises(ReleaseError) as caught:
            self.run_release()
        self.assertEqual(caught.exception.stage, "preflight")
        self.assertFalse(any(":deploy" in event for event in self.events_read()))

    def test_second_preflight_is_required_under_lock(self):
        extra = '''if [[ "$1" == preflight ]]; then
count="$(grep -c ':preflight' "$RELEASE_TEST_EVENTS")"
[[ "$count" -eq 1 ]] || exit 8
fi'''
        self.archive("orders", extra=extra)
        with self.assertRaises(ReleaseError) as caught:
            self.run_release()
        self.assertEqual(caught.exception.stage, "preflight")
        self.assertEqual(self.events_read(), ["orders:preflight", "orders:preflight"])

    def test_failed_deploy_is_included_in_reverse_rollback(self):
        self.archive("alpha")
        self.archive("zeta", fail="deploy")
        with self.assertRaises(ReleaseError) as caught:
            self.run_release()
        self.assertEqual(caught.exception.code, "HOOK_FAILED")
        self.assertEqual(self.events_read()[-2:], ["zeta:rollback", "alpha:rollback"])
        self.assertFalse((self.root / ".state/active.json").exists())

    def test_verify_failure_rolls_back_all(self):
        self.archive("alpha", fail="verify")
        self.archive("zeta")
        with self.assertRaises(ReleaseError):
            self.run_release()
        self.assertEqual(self.events_read()[-2:], ["zeta:rollback", "alpha:rollback"])

    def test_immutable_set_rejects_changed_bytes(self):
        self.archive("alpha")
        self.run_release()
        self.events.unlink()
        self.archive("alpha", extra=": changed")
        with self.assertRaises(ReleaseError) as caught:
            self.run_release()
        self.assertEqual(caught.exception.code, "IMMUTABLE_SET_CHANGED")
        self.assertEqual(self.events_read(), [])

    def test_lock_is_bounded_and_has_no_deploy(self):
        self.archive("alpha")
        deploy = self.root / ".runtime"
        deploy.mkdir()
        with (deploy / ".deploy.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = subprocess.run([str(ROOT / "release"), "--root", str(self.root), "release", "set-1", "--yes"], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events_read(), ["alpha:preflight"])

    def test_symlink_state_cannot_write_external_files(self):
        self.archive("alpha")
        outside = self.root / "outside"
        outside.mkdir()
        (outside / "sentinel").write_text("unchanged")
        (self.root / ".state").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ReleaseError) as caught:
            self.run_release()
        self.assertEqual(caught.exception.code, "SYMLINK_PATH")
        self.assertEqual(list(outside.iterdir()), [outside / "sentinel"])

    def command(self, *arguments, success=True):
        result = subprocess.run([str(ROOT / "release"), "--root", str(self.root), *map(str, arguments)], capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_inspect_reads_generated_run_report(self):
        self.archive("orders-api")
        self.command("release", "set-1", "--yes")
        run = next((self.root / ".state/runs").iterdir())
        events = self.events_read()
        report = self.command("inspect", run.name)
        self.assertEqual(report.stdout, (run / "report.txt").read_text())
        for invalid in ("../outside", "", run.name + "/../outside", run.name.lower()):
            with self.subTest(run=invalid):
                result = self.command("inspect", invalid, success=False)
                self.assertEqual(result.stderr.partition(":")[0], "INVALID_RUN")
        self.assertEqual(self.events_read(), events)

    def test_init_pack_directory_publication_and_rollback_via_cli(self):
        payload = self.root / "compiled assets"
        payload.mkdir()
        (payload / "index.html").write_text("version one")
        self.command("init", "team-portal")
        original = (self.root / "distributions/team-portal/deploy.sh").read_bytes()
        self.command("init", "team-portal", success=False)
        self.assertEqual((self.root / "distributions/team-portal/deploy.sh").read_bytes(), original)
        self.command("pack", "team-portal", "--source", payload, "--version", "1.0.0", "--commit", "a" * 40, "--set", "initial")
        self.command("release", "initial", "--yes")
        current = self.root / ".runtime/team-portal/current"
        previous = os.readlink(current)
        (self.root / ".runtime/team-portal/data").mkdir()
        sentinel = self.root / ".runtime/team-portal/data/user-file"
        sentinel.write_text("keep")
        (payload / "index.html").write_text("version two")
        self.command("pack", "team-portal", "--source", payload, "--version", "1.1.0", "--commit", "b" * 40, "--set", "next")
        self.archive("zeta", fail="verify", set_id="next")
        self.command("release", "next", "--yes", success=False)
        self.assertEqual(os.readlink(current), previous)
        self.assertEqual((current / "index.html").read_text(), "version one")
        self.assertEqual(sentinel.read_text(), "keep")
        self.command("pack", "team-portal", "--source", payload, "--version", "1.2.0", "--commit", "c" * 40, "--set", "initial", success=False)

    def test_pack_rejects_source_link_before_creating_zip(self):
        self.command("init", "agent-binary")
        payload = self.root / "payload"
        payload.mkdir()
        (payload / "first").write_text("ordinary")
        (payload / "last").symlink_to(self.root / "config/project.json")
        self.command("pack", "agent-binary", "--source", payload, "--version", "1.0.0", "--commit", "a" * 40, "--set", "unsafe", success=False)
        self.assertFalse((self.root / "unsafe").exists())

    def test_distribution_names_are_independent_of_internal_run_directories(self):
        payload = self.root / "payload"
        payload.mkdir()
        (payload / "binary").write_text("payload")
        for name in ("artifacts", "services"):
            self.command("init", name)
            self.command("pack", name, "--source", payload, "--version", "1.0.0", "--commit", "a" * 40, "--set", "named")
        self.command("release", "named", "--yes")
        run = next((self.root / ".state/runs").iterdir())
        for name in ("artifacts", "services"):
            self.assertEqual((self.root / ".runtime" / name / "current/binary").read_text(), "payload")
            self.assertTrue((run / "services" / name / "previous.json").is_file())
        self.assertEqual(json.loads((run / "result.json").read_text())["status"], "verified")


if __name__ == "__main__":
    unittest.main()
