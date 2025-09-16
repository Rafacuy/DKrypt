# modules/xss/models.py
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any

class XSSContext(Enum):
    """XSS injection context types"""
    HTML_TAG = "html_tag"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    JSON = "json"
    EVENT_HANDLER = "event_handler"
    COMMENT = "comment"
    CDATA = "cdata"

class VulnerabilitySeverity(Enum):
    """CVSS-based severity levels"""
    CRITICAL = (9.0, 10.0, "critical")
    HIGH = (7.0, 8.9, "high")
    MEDIUM = (4.0, 6.9, "medium")
    LOW = (0.1, 3.9, "low")
    INFO = (0.0, 0.0, "info")

@dataclass
class XSSVulnerability:
    """Represents a discovered XSS vulnerability"""
    url: str
    method: str
    parameter: str
    payload: str
    context: XSSContext
    severity: VulnerabilitySeverity
    evidence: str
    response_time: float
    status_code: int
    headers: Dict[str, str]
    request_data: Dict[str, Any]
    cvss_score: float = 0.0
    remediation: str = ""
    false_positive_score: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        """Converts the vulnerability object to a dictionary."""
        return {
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'payload': self.payload,
            'context': self.context.value,
            'severity': self.severity.value[2],
            'cvss_score': self.cvss_score,
            'evidence': self.evidence[:500],
            'response_time': self.response_time,
            'status_code': self.status_code,
            'remediation': self.remediation,
            'timestamp': self.timestamp.isoformat()
        }
