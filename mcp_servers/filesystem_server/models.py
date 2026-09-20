"""
Configuration, requests, and results for the file service
"""

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256

# succeed str, and Enum, 
class PolicyDecision(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"


class ExecutionStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NOT_STARTED = "not_started"

@dataclass(frozen=True)
class FileServiceConfig:
    workspace_root: str
    authorized_roots: tuple[str, ...]
    max_read_bytes: int

    def __post_init__(self) -> None:
        """
        process and check before going to following steps
        """
        if (
            
            not isinstance(self.workspace_root, str)
            or not self.workspace_root.strip()
        ):
            raise ValueError("workspace_root must be a non-empty string.")
        
        if not isinstance(self.authorized_roots, tuple):
            raise TypeError("authorized_roots must be a tuple.")


        if not all(
            isinstance(root, str) and root.strip()
            for root in self.authorized_roots
        ):
            raise ValueError("Each authorized root must be a non-empty string.")


        if type(self.max_read_bytes) is not int:
            raise TypeError("max_read_bytes must be an integer.")

        if self.max_read_bytes <= 0:
            raise ValueError("max_read_bytes must be positive.")


@dataclass(frozen=True)
class ReadRequest:
    request_id: str
    original_path: str

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ValueError("request_id must be a non-empty string.")

        if not isinstance(self.original_path, str):
            raise TypeError("original_path must be a string.")


@dataclass(frozen=True)
class ReadResult:
    request_id: str
    original_path: str
    resolved_path: str | None
    policy_decision: PolicyDecision
    execution_status: ExecutionStatus
    reason: str
    content: bytes | None = field(default=None, repr=False)
    truncated: bool | None = None
    # automatically generated instead of manually transferred
    content_sha256: str | None = field(init=False, default=None)

    def __post_init__(self) -> None:
        if not isinstance(self.request_id, str) or not self.request_id.strip():
            raise ValueError("request_id must be a non-empty string.")

        if not isinstance(self.original_path, str):
            raise TypeError("original_path must be a string.")

        if self.resolved_path is not None:
            if (
                not isinstance(self.resolved_path, str)
                or not self.resolved_path
            ):
                raise ValueError("resolved_path must be a non-empty string or None.")

        if not isinstance(self.policy_decision, PolicyDecision):
            raise TypeError("policy_decision must be PolicyDecision.")

        if not isinstance(self.execution_status, ExecutionStatus):
            raise TypeError("execution_status must be ExecutionStatus.")

        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string.")

        if (
            self.policy_decision is not PolicyDecision.ALLOWED
            and self.execution_status is not ExecutionStatus.NOT_STARTED
        ):
            raise ValueError("Execution requires an allowed policy decision.")

        if self.execution_status is ExecutionStatus.SUCCEEDED:
            if not isinstance(self.content, bytes):
                raise TypeError("Successful reads must contain bytes.")

            if type(self.truncated) is not bool:
                raise TypeError("Successful reads require a boolean truncated flag.")

            object.__setattr__(
                self,
                "content_sha256",
                sha256(self.content).hexdigest(),
            )
        else:
            if self.content is not None or self.truncated is not None:
                raise ValueError(
                    "Failed or unstarted reads must not contain content "
                    "or a truncation flag."
                )
    @property
    def returned_bytes(self) -> int:
        return 0 if self.content is None else len(self.content)