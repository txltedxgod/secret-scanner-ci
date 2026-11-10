"""
SecretScanner Detection Engine.
Combines regex signature matching, Shannon entropy analysis, line mapping,
and false-positive filtering.
"""

from dataclasses import dataclass
import math
import re
from typing import Any, Dict, List, Optional, Set
from scanner.rules import RULES, SecretRule, Severity


KEYWORD_PROXIMITY_REGEX = re.compile(
    r"(?i)\b[a-zA-Z0-9_-]*(?:password|passwd|secret|token|api[_-]?key|auth|bearer|credentials|private[_-]?key)\s*[:=]\s*(?:['\"]([^\s'\"]{16,})['\"]|([A-Za-z0-9+/=_-]{16,}))"
)

FALSE_POSITIVE_SUBSTRINGS: Set[str] = {
    "YOUR_KEY",
    "CHANGEME",
    "PLACEHOLDER",
    "0000000000000000",
}


def mask_secret(raw: str) -> str:
    """Mask secret retaining safe prefix for debugging."""
    if len(raw) <= 8:
        return raw[:2] + "..."
    return raw[:6] + "..."


class SecretScanner:
    """Enterprise-grade secrets scanner for source code, configuration, and Git diffs."""

    def __init__(
        self,
        entropy_threshold: float = 4.5,
        enable_entropy_detection: bool = True,
    ):
        self.entropy_threshold = entropy_threshold
        self.enable_entropy_detection = enable_entropy_detection
        self.rule_catalog = RULES

        # Backward compatibility with self.rules tuple list
        self.rules = [(r.name, r.pattern) for r in self.rule_catalog]

    def _entropy(self, s: str) -> float:
        """Calculate base-2 Shannon entropy of a string."""
        if not s:
            return 0.0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def _calculate_line_col(self, text: str, index: int) -> tuple[int, int]:
        """Convert character offset into 1-based line and column numbers."""
        line = text.count("\n", 0, index) + 1
        last_nl = text.rfind("\n", 0, index)
        col = index + 1 if last_nl == -1 else (index - last_nl)
        return line, col

    def _is_false_positive(self, matched_text: str) -> bool:
        """Check if matched secret matches known documentation/test placeholder patterns."""
        upper = matched_text.upper()
        return any(fp in upper for fp in FALSE_POSITIVE_SUBSTRINGS)

    def scan_content(self, text: str) -> List[Dict[str, Any]]:
        """
        Scan text content for hardcoded secrets.
        Returns a list of detected findings with backward-compatible fields.
        """
        findings: List[Dict[str, Any]] = []
        seen_spans: Set[tuple[int, int]] = set()

        # 1. Signature Rule Scanning
        for rule in self.rule_catalog:
            for match in rule.pattern.finditer(text):
                start, end = match.span()
                matched_str = match.group(0)

                # Skip false-positive placeholders
                if self._is_false_positive(matched_str):
                    continue

                line_num, col_num = self._calculate_line_col(text, start)
                entropy_val = round(self._entropy(matched_str), 2)

                findings.append({
                    "rule": rule.name,
                    "rule_id": rule.id,
                    "severity": rule.severity.value,
                    "matched": mask_secret(matched_str),
                    "start": start,
                    "end": end,
                    "line": line_num,
                    "column": col_num,
                    "entropy": entropy_val,
                })
                seen_spans.add((start, end))

        # 2. Shannon Entropy Proximity Scanning
        if self.enable_entropy_detection:
            for match in KEYWORD_PROXIMITY_REGEX.finditer(text):
                token = match.group(1) or match.group(2)
                token_start = match.start(1) if match.group(1) else match.start(2)
                token_end = match.end(1) if match.group(1) else match.end(2)

                if any(start <= token_start and token_end <= end for start, end in seen_spans):
                    continue
                if self._is_false_positive(token):
                    continue

                entropy_val = self._entropy(token)
                if entropy_val >= self.entropy_threshold:
                    line_num, col_num = self._calculate_line_col(text, token_start)
                    findings.append({
                        "rule": "High Entropy Credential",
                        "rule_id": "SEC099",
                        "severity": Severity.HIGH.value,
                        "matched": mask_secret(token),
                        "start": token_start,
                        "end": token_end,
                        "line": line_num,
                        "column": col_num,
                        "entropy": round(entropy_val, 2),
                    })
                    seen_spans.add((token_start, token_end))

        # Sort findings deterministically by character start position
        findings.sort(key=lambda x: x["start"])
        return findings
