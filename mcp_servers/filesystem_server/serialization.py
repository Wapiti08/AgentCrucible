'''
convert data to base64 format
'''


import base64
from typing import TypedDict

from .models import ReadResult


# define response format
class ReadFileResponse(TypedDict):
    request_id: str
    policy_decision: str
    execution_status: str
    reason: str
    content_base64: str | None
    returned_bytes: int
    truncated: bool | None
    content_sha256: str | None


def serialize_read_result(result: ReadResult) -> ReadFileResponse:
    content_base64 = (
        base64.b64encode(result.content).decode("ascii")
        if result.content is not None
        else None
    )

    return {
        "request_id": result.request_id,
        "policy_decision": result.policy_decision.value,
        "execution_status": result.execution_status.value,
        "reason": result.reason,
        "content_base64": content_base64,
        "returned_bytes": result.returned_bytes,
        "truncated": result.truncated,
        "content_sha256": result.content_sha256,
    }