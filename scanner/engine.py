import re
import math
from typing import List, Dict, Any

class SecretScanner:
    def __init__(self):
        self.rules = [
            ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("GitHub Token", re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}")),
            ("Generic Private Key", re.compile(r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----"))
        ]

    def _entropy(self, s: str) -> float:
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    def scan_content(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        for name, pattern in self.rules:
            for match in pattern.finditer(text):
                findings.append({
                    "rule": name,
                    "matched": match.group(0)[:6] + "...",
                    "start": match.start()
                })
        return findings
