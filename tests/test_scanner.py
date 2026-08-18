from scanner.engine import SecretScanner

def test_secret_detection():
    s = SecretScanner()
    res = s.scan_content("export AWS_KEY=AKIAIOSFODNN7EXAMPLE")
    assert len(res) == 1
    assert res[0]["rule"] == "AWS Access Key"
