from typing import Any, Dict, List
from fastapi import FastAPI
from pydantic import BaseModel, Field

from scanner.engine import SecretScanner
from scanner.git_scanner import scan_unified_diff
from scanner.rules import RULES

app = FastAPI(
    title="Secret Scanner CI",
    version="0.2.0",
    description="High-Speed Pre-Commit & CI/CD Secret Scanner with Shannon Entropy Analysis",
)
scanner = SecretScanner()


class ScanReq(BaseModel):
    content: str = Field(..., description="Raw text, configuration, or code block to scan")


class DiffScanReq(BaseModel):
    diff: str = Field(..., description="Unified Git diff string (e.g. git diff HEAD~1)")


@app.get("/healthz", tags=["Health"])
def health_check() -> Dict[str, str]:
    """Liveness probe endpoint."""
    return {"status": "healthy", "version": "0.2.0"}


@app.post("/api/v1/scan", tags=["Scanner"])
def scan(req: ScanReq) -> Dict[str, Any]:
    """Scan raw content string for credentials and tokens."""
    findings = scanner.scan_content(req.content)
    return {
        "has_secrets": len(findings) > 0,
        "total_findings": len(findings),
        "findings": findings,
    }


@app.post("/api/v1/scan/diff", tags=["Scanner"])
def scan_diff(req: DiffScanReq) -> Dict[str, Any]:
    """Scan unified Git diff added lines for staged credentials."""
    findings = scan_unified_diff(req.diff, scanner=scanner)
    return {
        "has_secrets": len(findings) > 0,
        "total_findings": len(findings),
        "findings": findings,
    }


@app.get("/api/v1/rules", tags=["Rules"])
def get_rules() -> Dict[str, Any]:
    """List all supported signature rules and severities."""
    return {
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "description": r.description,
            }
            for r in RULES
        ],
        "count": len(RULES),
    }
