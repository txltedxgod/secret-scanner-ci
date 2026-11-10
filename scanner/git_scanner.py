"""
Git Diff and File System Scanner for CI and Pre-commit Hooks.
"""

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from scanner.engine import SecretScanner


DEFAULT_IGNORE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
}

DEFAULT_IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
    ".zip", ".tar", ".gz", ".7z",
    ".pdf", ".lock",
}


@dataclass
class DiffFinding:
    file_path: str
    line_number: int
    rule: str
    severity: str
    matched: str
    entropy: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule": self.rule,
            "severity": self.severity,
            "matched": self.matched,
            "entropy": self.entropy,
        }


def scan_unified_diff(
    diff_text: str, scanner: Optional[SecretScanner] = None
) -> List[Dict[str, Any]]:
    """
    Scan added lines within a unified Git diff.
    """
    sc = scanner or SecretScanner()
    findings: List[Dict[str, Any]] = []

    current_file = "unknown"
    current_line = 0

    hunk_regex = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            continue
        elif raw_line.startswith("--- "):
            continue

        hunk_match = hunk_regex.match(raw_line)
        if hunk_match:
            current_line = int(hunk_match.group(2))
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            added_content = raw_line[1:]
            line_findings = sc.scan_content(added_content)
            for f in line_findings:
                findings.append({
                    "file_path": current_file,
                    "line_number": current_line,
                    "rule": f["rule"],
                    "rule_id": f["rule_id"],
                    "severity": f["severity"],
                    "matched": f["matched"],
                    "entropy": f["entropy"],
                })
            current_line += 1
        elif not raw_line.startswith("-"):
            current_line += 1

    return findings


def scan_directory(
    root_path: str,
    scanner: Optional[SecretScanner] = None,
    max_file_size_bytes: int = 2 * 1024 * 1024,
) -> List[Dict[str, Any]]:
    """
    Recursively scans files in root_path skipping ignored dirs and binaries.
    """
    sc = scanner or SecretScanner()
    all_findings: List[Dict[str, Any]] = []
    root = Path(root_path)

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in DEFAULT_IGNORE_DIRS]

        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext in DEFAULT_IGNORE_EXTENSIONS:
                continue

            file_abs = Path(dirpath) / fname
            try:
                if file_abs.stat().st_size > max_file_size_bytes:
                    continue

                rel_path = str(file_abs.relative_to(root))
                content = file_abs.read_text(encoding="utf-8", errors="ignore")
                file_findings = sc.scan_content(content)

                for f in file_findings:
                    all_findings.append({
                        "file_path": rel_path,
                        "line_number": f["line"],
                        "column": f["column"],
                        "rule": f["rule"],
                        "rule_id": f["rule_id"],
                        "severity": f["severity"],
                        "matched": f["matched"],
                        "entropy": f["entropy"],
                    })
            except Exception:
                continue

    return all_findings
