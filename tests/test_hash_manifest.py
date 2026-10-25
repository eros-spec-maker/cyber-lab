import hashlib
import json
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_ROOT / "tools" / "forensics" / "hash_manifest.py"
SPEC = importlib.util.spec_from_file_location("hash_manifest", SCRIPT)
HASH_MANIFEST = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(HASH_MANIFEST)


class HashManifestTests(unittest.TestCase):
    def run_tool(self, source: Path, output: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), str(source), "--output", str(output)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_hashes_nested_and_empty_files_in_sorted_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            evidence = base / "evidence"
            (evidence / "z-dir").mkdir(parents=True)
            (evidence / "a.txt").write_bytes(b"hello\n")
            (evidence / "z-dir" / "empty.bin").write_bytes(b"")
            (evidence / "z-dir" / "data.bin").write_bytes(b"synthetic evidence\x00")
            output = base / "manifest.json"

            result = self.run_tool(evidence, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            manifest = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                [item["path"] for item in manifest["files"]],
                ["a.txt", "z-dir/data.bin", "z-dir/empty.bin"],
            )
            expected = {
                "a.txt": b"hello\n",
                "z-dir/data.bin": b"synthetic evidence\x00",
                "z-dir/empty.bin": b"",
            }
            for item in manifest["files"]:
                contents = expected[item["path"]]
                self.assertEqual(item["size_bytes"], len(contents))
                self.assertEqual(item["sha256"], hashlib.sha256(contents).hexdigest())
                self.assertNotIn("content", item)
            self.assertTrue(manifest["generated_at_utc"].endswith("Z"))

    def test_does_not_modify_evidence_and_skips_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            evidence = base / "evidence"
            evidence.mkdir()
            evidence_file = evidence / "sample.txt"
            evidence_file.write_text("synthetic", encoding="utf-8")
            outside = base / "outside.txt"
            outside.write_text("outside scope", encoding="utf-8")
            try:
                (evidence / "external-link").symlink_to(outside)
                (evidence / "directory-link").symlink_to(base, target_is_directory=True)
            except (NotImplementedError, OSError):
                self.skipTest("symbolic links are unavailable in this environment")
            before = (evidence_file.read_bytes(), evidence_file.stat().st_mtime_ns)
            output = base / "manifest.json"

            result = self.run_tool(evidence, output)

            self.assertEqual(result.returncode, 0, result.stderr)
            records = json.loads(output.read_text(encoding="utf-8"))["files"]
            self.assertEqual([item["path"] for item in records], ["sample.txt"])
            self.assertEqual((evidence_file.read_bytes(), evidence_file.stat().st_mtime_ns), before)
            self.assertIn("Skipped 2 symbolic link", result.stderr)

    def test_rejects_missing_input_and_non_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            missing = self.run_tool(base / "missing", base / "manifest.json")
            file_path = base / "not-a-directory"
            file_path.write_text("synthetic", encoding="utf-8")
            not_directory = self.run_tool(file_path, base / "other.json")

            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("cannot resolve input directory", missing.stderr)
            self.assertNotEqual(not_directory.returncode, 0)
            self.assertIn("not a directory", not_directory.stderr)

    def test_refuses_existing_or_in_scope_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            evidence = base / "evidence"
            evidence.mkdir()
            existing = base / "existing.json"
            existing.write_text("keep me", encoding="utf-8")

            result_existing = self.run_tool(evidence, existing)
            result_inside = self.run_tool(evidence, evidence / "manifest.json")

            self.assertNotEqual(result_existing.returncode, 0)
            self.assertIn("refusing to overwrite", result_existing.stderr)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep me")
            self.assertNotEqual(result_inside.returncode, 0)
            self.assertIn("outside the input directory", result_inside.stderr)
            self.assertFalse((evidence / "manifest.json").exists())

    def test_rejects_unavailable_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            evidence = base / "evidence"
            evidence.mkdir()
            result = self.run_tool(evidence, base / "missing" / "manifest.json")

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("output directory is unavailable", result.stderr)

    def test_reports_directory_permission_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(HASH_MANIFEST.os, "scandir", side_effect=PermissionError("denied")):
                with self.assertRaisesRegex(HASH_MANIFEST.ManifestError, "cannot read directory.*denied"):
                    HASH_MANIFEST._walk_files(root)

    def test_reports_file_read_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sample.bin").write_bytes(b"synthetic")

            class FailingReader:
                def __init__(self, descriptor: int, _mode: str) -> None:
                    self.descriptor = descriptor

                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    HASH_MANIFEST.os.close(self.descriptor)

                def fileno(self) -> int:
                    return self.descriptor

                def read(self, _size: int) -> bytes:
                    raise OSError("synthetic read failure")

            with mock.patch.object(HASH_MANIFEST.os, "fdopen", side_effect=FailingReader):
                with self.assertRaisesRegex(HASH_MANIFEST.ManifestError, "cannot read.*synthetic read failure"):
                    HASH_MANIFEST._walk_files(root)


if __name__ == "__main__":
    unittest.main()
