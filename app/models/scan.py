from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
import uuid

class VulnType(str, Enum):
    SQL_INJECTION = "SQL Injection"
    XSS = "Cross-Site Scripting"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    SSRF = "Server-Side Request Forgery (SSRF)"
    PATH_TRAVERSAL = "Path Traversal"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    vuln_type: VulnType
    severity: Severity
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: str
    remediation: str
    cvss_score: float = 0.0
    cvss_vector: str = ""

class ScanRequest(BaseModel):
    target_url: str
    scan_types: List[VulnType] = Field(default_factory=lambda: list(VulnType))
    depth: int = 2
    timeout: int = 10
    user_agent: str = "VulnHunter/1.0"

class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    pages_crawled: int = 0
    requests_sent: int = 0
    vulnerabilities: List[Vulnerability] = []
    error: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    @property
    def severity_counts(self) -> dict:
        counts = {sev.value: 0 for sev in Severity}
        for v in self.vulnerabilities:
            counts[v.severity.value] += 1
        return counts
