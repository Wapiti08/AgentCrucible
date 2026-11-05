from dataclasses import dataclass

from detectors.engine import DetectionStatus
from mcp_servers.filesystem_server.models import (
    ExecutionStatus,
    PolicyDecision,
)


@dataclass(frozen=True)
class FileReadExpectation:
    policy_decision: PolicyDecision
    execution_status: ExecutionStatus
    rule_id: str
    detection_status: DetectionStatus
