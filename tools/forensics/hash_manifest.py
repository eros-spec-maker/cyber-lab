#!/usr/bin/env python3
"""Create a read-only SHA-256 inventory of regular files in a directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CHUNK_SIZE = 1024 * 1024


class ManifestError(Exception):
    """An expected input, traversal, or output error suitable for CLI display."""


def _error_detail(exc: OSError) -> str:
    return exc.strerror or str(exc) or type(exc).__name__


def _walk_files(root: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    skipped_symlinks = 0

    def visit(directory: Path) -> None:
        nonlocal skipped_symlinks
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            raise ManifestError(f"cannot read directory '{directory}': {_error_detail(exc)}") from exc

        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    skipped_symlinks += 1
                    continue
                if entry.is_dir(follow_symlinks=False):
                    visit(path)
                    continue
                info = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise ManifestError(f"cannot inspect '{path}': {_error_detail(exc)}") from exc

            if not stat.S_ISREG(info.st_mode):
                continue

            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(path, flags)
            except OSError as exc:
                raise ManifestError(f"cannot open '{path}': {_error_detail(exc)}") from exc

            digest = hashlib.sha256()
            byte_count = 0
            try:
                with os.fdopen(descriptor, "rb") as stream:
                    opened_info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened_info.st_mode):
                        raise ManifestError(f"not a regular file: '{path}'")
                    # Bind the bytes read to the object observed by scandir. This
                    # detects replacement between lstat and open (including a
                    # symlink swap where O_NOFOLLOW is unavailable).
                    observed_identity = (
                        info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns,
                    )
                    opened_identity = (
                        opened_info.st_dev, opened_info.st_ino, opened_info.st_size,
                        opened_info.st_mtime_ns, opened_info.st_ctime_ns,
                    )
                    if opened_identity != observed_identity:
                        raise ManifestError(f"file changed before hashing: '{path}'")
                    while True:
                        block = stream.read(CHUNK_SIZE)
                        if not block:
                            break
                        digest.update(block)
                        byte_count += len(block)
                    final_info = os.fstat(stream.fileno())
            except OSError as exc:
                raise ManifestError(f"cannot read '{path}': {_error_detail(exc)}") from exc

            identity_before = (
                opened_info.st_dev, opened_info.st_ino, opened_info.st_size,
                opened_info.st_mtime_ns, opened_info.st_ctime_ns,
            )
            identity_after = (
                final_info.st_dev, final_info.st_ino, final_info.st_size,
                final_info.st_mtime_ns, final_info.st_ctime_ns,
            )
            if byte_count != opened_info.st_size or identity_before != identity_after:
                raise ManifestError(f"file changed while being hashed: '{path}'")

            records.append({
                "path": path.relative_to(root).as_posix(),
                "size_bytes": byte_count,
                "sha256": digest.hexdigest(),
            })

    visit(root)
    records.sort(key=lambda item: item["path"])
    return records, skipped_symlinks


def _write_manifest(output: Path, payload: dict[str, Any]) -> None:
    """Write atomically without replacing an existing path."""
    parent = output.parent
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=parent)
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # link() is atomic and fails if output already exists, unlike replace().
        os.link(temporary_path, output)
    except FileExistsError as exc:
        raise ManifestError(f"output already exists; refusing to overwrite: '{output}'") from exc
    except OSError as exc:
        raise ManifestError(f"cannot write output '{output}': {_error_detail(exc)}") from exc
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a SHA-256 JSON manifest for regular files under a directory."
    )
    parser.add_argument("directory", help="directory to inventory (symbolic links are skipped)")
    parser.add_argument("--output", default="manifest.json", help="new JSON output file (default: manifest.json)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    supplied_root = Path(args.directory)
    if supplied_root.is_symlink():
        print("error: input directory must not be a symbolic link", file=sys.stderr)
        return 2
    try:
        root = supplied_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        detail = _error_detail(exc) if isinstance(exc, OSError) else str(exc)
        print(f"error: cannot resolve input directory '{supplied_root}': {detail}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"error: input is not a directory: '{root}'", file=sys.stderr)
        return 2

    raw_output = Path(args.output)
    if not raw_output.name:
        print(f"error: output must be a file path: '{raw_output}'", file=sys.stderr)
        return 2
    try:
        output_parent = raw_output.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        detail = _error_detail(exc) if isinstance(exc, OSError) else str(exc)
        print(f"error: output directory is unavailable '{raw_output.parent}': {detail}", file=sys.stderr)
        return 2
    if not output_parent.is_dir():
        print(f"error: output parent is not a directory: '{output_parent}'", file=sys.stderr)
        return 2
    output = output_parent / raw_output.name
    if output == root or root in output.parents:
        print("error: output must be stored outside the input directory", file=sys.stderr)
        return 2
    if os.path.lexists(output):
        print(f"error: output already exists; refusing to overwrite: '{output}'", file=sys.stderr)
        return 2

    try:
        records, skipped_symlinks = _walk_files(root)
        payload = {
            "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "files": records,
        }
        _write_manifest(output, payload)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if skipped_symlinks:
        print(f"Skipped {skipped_symlinks} symbolic link(s).", file=sys.stderr)
    print(f"Wrote {len(records)} file record(s) to '{output}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
