from fastapi import FastAPI
from pydantic import BaseModel
from scanner.engine import SecretScanner

app = FastAPI(title="Secret Scanner CI", version="0.1.0")
scanner = SecretScanner()

class ScanReq(BaseModel):
    content: str

@app.post("/api/v1/scan")
def scan(req: ScanReq):
    findings = scanner.scan_content(req.content)
    return {"has_secrets": len(findings) > 0, "findings": findings}
