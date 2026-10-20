"""Task 2, Variant 2: a file integrity monitor."""

import argparse
import hashlib
import json
import logging
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from shared.student import STUDENT_NAME, VARIANT_NUMBER

LOGGER = logging.getLogger("lab02.fim")


@dataclass
class FileMetadata:
    """Integrity metadata for one monitored file."""

    path: str
    sha256: str
    size: int
    modified: str


def configure_logging(log_file: Path | None) -> None:
    """Configure FIM logging without duplicate handlers."""
    LOGGER.handlers.clear()
    LOGGER.setLevel(logging.INFO)
    LOGGER.propagate = False
    formatter = logging.Formatter("[%(levelname)s] %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    LOGGER.addHandler(console_handler)
    if log_file is not None:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        LOGGER.addHandler(file_handler)


def sha256_file(path: Path) -> str:
    """Calculate the SHA-256 digest of a file in chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_directory(
    directory: Path, excluded_paths: set[Path]
) -> dict[str, FileMetadata]:
    """Recursively scan regular files and return portable relative metadata."""
    files: dict[str, FileMetadata] = {}
    for path in directory.rglob("*"):
        if path in excluded_paths or not path.is_file():
            continue
        try:
            stat = path.stat()
            relative_path = path.relative_to(directory).as_posix()
            files[relative_path] = FileMetadata(
                path=relative_path,
                sha256=sha256_file(path),
                size=stat.st_size,
                modified=datetime.fromtimestamp(
                    stat.st_mtime, timezone.utc
                ).isoformat(),
            )
        except OSError as error:
            LOGGER.warning("Cannot read %s: %s", path, error)
    return files


def write_baseline(path: Path, files: dict[str, FileMetadata]) -> None:
    """Write a readable UTF-8 baseline JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    records = [asdict(files[name]) for name in sorted(files)]
    with path.open("w", encoding="utf-8") as target:
        json.dump(records, target, ensure_ascii=False, indent=2)
        target.write("\n")


def load_baseline(path: Path) -> dict[str, FileMetadata]:
    """Load and validate a baseline JSON file."""
    try:
        with path.open(encoding="utf-8") as source:
            records = json.load(source)
        if not isinstance(records, list):
            raise TypeError("baseline must contain a list")
        files = {}
        for record in records:
            if not isinstance(record, dict) or set(record) != {
                "path",
                "sha256",
                "size",
                "modified",
            }:
                raise ValueError("baseline contains invalid file metadata")
            metadata = FileMetadata(**record)
            if not isinstance(metadata.path, str) or not isinstance(
                metadata.sha256, str
            ):
                raise TypeError("baseline contains invalid field types")
            if not isinstance(metadata.size, int) or not isinstance(
                metadata.modified, str
            ):
                raise TypeError("baseline contains invalid field types")
            files[metadata.path] = metadata
        return files
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
        raise ValueError(f"Cannot read baseline '{path}': {error}") from error


def inspect_integrity(
    baseline: dict[str, FileMetadata], current: dict[str, FileMetadata]
) -> tuple[list[FileMetadata], list[FileMetadata], list[FileMetadata], int]:
    """Return created, deleted, modified metadata and unchanged file count."""
    created = [current[name] for name in sorted(current.keys() - baseline.keys())]
    deleted = [baseline[name] for name in sorted(baseline.keys() - current.keys())]
    modified = [
        current[name]
        for name in sorted(current.keys() & baseline.keys())
        if current[name].sha256 != baseline[name].sha256
    ]
    unchanged = len(current.keys() & baseline.keys()) - len(modified)
    return created, deleted, modified, unchanged


def print_check_result(
    baseline: dict[str, FileMetadata],
    current: dict[str, FileMetadata],
) -> bool:
    """Print the inspection summary and details; return whether alerts exist."""
    created, deleted, modified, unchanged = inspect_integrity(baseline, current)
    print("\n=== File Integrity Inspection Summary ===")
    print(f"Total monitored files : {len(current)}")
    print(f"Unchanged files       : {unchanged}")
    print(f"Modified files        : {len(modified)}")
    print(f"Created files         : {len(created)}")
    print(f"Deleted files         : {len(deleted)}")
    print("\n=== Detected Anomalies ===")

    for file in modified:
        print(f"\n[MODIFIED] {file.path}")
        print(f"Expected SHA-256: {baseline[file.path].sha256}")
        print(f"Actual SHA-256:   {file.sha256}")
        LOGGER.warning("MODIFIED: %s", file.path)
    for file in created:
        print(f"\n[CREATED] {file.path} (Size: {file.size} B)")
        LOGGER.warning("CREATED: %s", file.path)
    for file in deleted:
        print(f"\n[DELETED] {file.path}")
        LOGGER.warning("DELETED: %s", file.path)
    return bool(created or deleted or modified)


def build_parser() -> argparse.ArgumentParser:
    """Create the FIM command-line argument parser."""
    parser = argparse.ArgumentParser(description="File Integrity Monitor (Variant 2)")
    parser.add_argument("--dir", required=True, type=Path, help="Directory to scan")
    parser.add_argument(
        "--baseline", required=True, type=Path, help="Baseline JSON path"
    )
    parser.add_argument("--mode", required=True, choices=("generate", "check"))
    parser.add_argument("--log-file", type=Path, help="Optional audit log path")
    return parser


def run_analysis(args: argparse.Namespace) -> int:
    """Execute baseline generation or integrity checking."""
    directory = args.dir.resolve()
    baseline_path = args.baseline.resolve()
    log_path = args.log_file.resolve() if args.log_file else None
    if not directory.exists():
        print(f"Error: directory does not exist: {directory}", file=sys.stderr)
        return 2
    if not directory.is_dir():
        print(f"Error: path is not a directory: {directory}", file=sys.stderr)
        return 2
    if args.mode == "check" and not baseline_path.is_file():
        print(f"Error: baseline does not exist: {baseline_path}", file=sys.stderr)
        return 2

    print("=== Laboratory Work #2: File Integrity Monitor ===")
    print(f"Student: {STUDENT_NAME}")
    print(f"Variant: {VARIANT_NUMBER}")

    try:
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
        configure_logging(log_path)
    except OSError as error:
        print(f"Error: cannot open log file: {error}", file=sys.stderr)
        return 2

    excluded = {path for path in (baseline_path, log_path) if path is not None}
    if args.mode == "generate":
        LOGGER.info("Scanning directory: %s", directory)
        current = scan_directory(directory, excluded)
        try:
            write_baseline(baseline_path, current)
        except OSError as error:
            print(f"Error: cannot write baseline: {error}", file=sys.stderr)
            return 2
        LOGGER.info("Baseline created: %s", baseline_path)
        print(f"Baseline created for {len(current)} files: {baseline_path}")
        return 0

    LOGGER.info("Loading baseline file: %s", baseline_path)
    try:
        baseline = load_baseline(baseline_path)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    LOGGER.info("Scanning directory: %s", directory)
    current = scan_directory(directory, excluded)
    alerts = print_check_result(baseline, current)
    if alerts:
        LOGGER.warning(
            "Security alerts detected! Check audit log at %s", log_path or "console"
        )
        print(
            f"\n[WARNING] Security alerts detected! Check audit log at {log_path or 'console'}"
        )
    else:
        LOGGER.info("No integrity anomalies detected")
        print("\n[INFO] No integrity anomalies detected.")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run Task 2 from command-line arguments."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return run_analysis(args)


if __name__ == "__main__":
    raise SystemExit(main())
