import pytest
from scanner.engine import SecretScanner, mask_secret
from scanner.rules import Severity


def test_secret_detection():
    """Verify backward compatibility of test_secret_detection."""
    s = SecretScanner()
    res = s.scan_content("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert len(res) == 1
    assert res[0]["rule"] == "AWS Access Key"


def test_github_token_detection():
    s = SecretScanner()
    content = "git_token = '" + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'"
    findings = s.scan_content(content)
    assert len(findings) == 1
    assert findings[0]["rule"] == "GitHub Token"
    assert findings[0]["severity"] == "CRITICAL"
    assert findings[0]["matched"].startswith("ghp_")


def test_stripe_and_slack_detection():
    s = SecretScanner()
    stripe_token = "sk_" + "live_" + "012345678901234567890123"
    slack_token = "xoxb-" + "1234567890-" + "1234567890123-" + "abcdefghijklmnop"
    content = f"""
    STRIPE_SECRET={stripe_token}
    SLACK_BOT={slack_token}
    """
    findings = s.scan_content(content)
    assert len(findings) == 2
    rule_names = {f["rule"] for f in findings}
    assert "Stripe Secret Key" in rule_names
    assert "Slack Token" in rule_names


def test_private_key_header():
    s = SecretScanner()
    content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    findings = s.scan_content(content)
    assert len(findings) == 1
    assert findings[0]["rule"] == "Generic Private Key"


def test_jwt_detection():
    s = SecretScanner()
    # Sample formatted JWT string
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    findings = s.scan_content(f"Authorization: Bearer {jwt}")
    assert any(f["rule"] == "JSON Web Token" for f in findings)


def test_shannon_entropy_calculation():
    s = SecretScanner()
    # Repetitive string has low entropy
    low_entropy = s._entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High randomness string has high entropy
    high_entropy = s._entropy("9fA&2!kL#8xP@1zQ$7wM")
    assert high_entropy > 4.0


def test_shannon_entropy_detection_with_keywords():
    s = SecretScanner(entropy_threshold=4.2)
    content = "database_password = '8xP#9fA&2!kL@1zQ$7wM%4vN^0bC'"
    findings = s.scan_content(content)
    assert len(findings) >= 1
    assert any("Entropy" in f["rule"] for f in findings)


def test_false_positive_suppression():
    s = SecretScanner()
    # Documentation dummy examples
    content = """
    token = ghp_YOUR_KEY_HERE_1234567890abcdef
    secret = CHANGEME_PLACEHOLDER
    """
    findings = s.scan_content(content)
    assert len(findings) == 0


def test_mask_secret_helper():
    assert mask_secret("AKIAIOSFODNN7ABCD123") == "AKIAIO..."
    assert mask_secret("short") == "sh..."
