"""
Secret detection rules and signature patterns.
"""

from dataclasses import dataclass
from enum import Enum
import re
from typing import List


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str


RULES: List[SecretRule] = [
    SecretRule(
        id="SEC001",
        name="AWS Access Key",
        pattern=re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        severity=Severity.CRITICAL,
        description="Amazon Web Services 20-character Access Key ID",
    ),
    SecretRule(
        id="SEC002",
        name="AWS Secret Access Key",
        pattern=re.compile(r"(?i)\b(?:aws_secret_access_key|aws_sec_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        severity=Severity.CRITICAL,
        description="Amazon Web Services 40-character Secret Access Key",
    ),
    SecretRule(
        id="SEC003",
        name="GitHub Token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{36,})\b"),
        severity=Severity.CRITICAL,
        description="GitHub personal, oauth, user, or server access token",
    ),
    SecretRule(
        id="SEC004",
        name="GitLab Personal Access Token",
        pattern=re.compile(r"\b(glpat-[0-9a-zA-Z_-]{20,})\b"),
        severity=Severity.HIGH,
        description="GitLab Personal Access Token",
    ),
    SecretRule(
        id="SEC005",
        name="Slack Token",
        pattern=re.compile(r"\b(xox[baprs]-[0-9A-Za-z]{10,48})\b"),
        severity=Severity.HIGH,
        description="Slack bot, user, or app authorization token",
    ),
    SecretRule(
        id="SEC006",
        name="Stripe Secret Key",
        pattern=re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b"),
        severity=Severity.CRITICAL,
        description="Stripe live secret or restricted API key",
    ),
    SecretRule(
        id="SEC007",
        name="OpenAI API Key",
        pattern=re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,})\b"),
        severity=Severity.HIGH,
        description="OpenAI API project or secret key",
    ),
    SecretRule(
        id="SEC008",
        name="Anthropic API Key",
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"),
        severity=Severity.HIGH,
        description="Anthropic Claude API authorization token",
    ),
    SecretRule(
        id="SEC009",
        name="Generic Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        description="Unencrypted cryptographic private key header",
    ),
    SecretRule(
        id="SEC010",
        name="JSON Web Token",
        pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)\b"),
        severity=Severity.MEDIUM,
        description="Signed JSON Web Token (JWT) bearing authentication payload",
    ),
]
