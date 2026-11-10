import pytest
from scanner.git_scanner import scan_unified_diff, scan_directory
from scanner.engine import SecretScanner


def test_scan_unified_diff_detects_added_secret():
    token_str = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    diff_text = f"""
diff --git a/config.py b/config.py
index 1234567..89abcdef 100644
--- a/config.py
+++ b/config.py
@@ -10,3 +10,4 @@ def get_client():
     url = "https://api.github.com"
+    token = "{token_str}"
     return client
"""
    findings = scan_unified_diff(diff_text)
    assert len(findings) == 1
    assert findings[0]["file_path"] == "config.py"
    assert findings[0]["line_number"] == 11
    assert findings[0]["rule"] == "GitHub Token"


def test_scan_unified_diff_ignores_removed_secret():
    token_str = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    diff_text = f"""
diff --git a/old_config.py b/old_config.py
index 89abcdef..1234567 100644
--- a/old_config.py
+++ b/old_config.py
@@ -10,4 +10,3 @@ def cleanup():
-    token = "{token_str}"
     pass
"""
    findings = scan_unified_diff(diff_text)
    assert len(findings) == 0


def test_scan_directory(tmp_path):
    # Setup test file tree
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    clean_file = src_dir / "clean.py"
    clean_file.write_text("print('clean code')", encoding="utf-8")

    leaky_file = src_dir / "keys.env"
    leaky_file.write_text("export AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")

    # Ignored directory
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    git_file = git_dir / "config"
    token_str = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    git_file.write_text(f"token = {token_str}", encoding="utf-8")

    findings = scan_directory(str(tmp_path))
    assert len(findings) == 1
    assert findings[0]["rule"] == "AWS Access Key"
    assert "keys.env" in findings[0]["file_path"]
