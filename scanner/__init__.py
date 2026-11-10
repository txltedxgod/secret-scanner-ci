"""
Secret Scanner CI & Pre-commit Engine.
"""

from scanner.engine import SecretScanner, mask_secret
from scanner.git_scanner import scan_unified_diff, scan_directory
from scanner.rules import RULES, SecretRule, Severity

__all__ = [
    "SecretScanner",
    "mask_secret",
    "scan_unified_diff",
    "scan_directory",
    "RULES",
    "SecretRule",
    "Severity",
]
