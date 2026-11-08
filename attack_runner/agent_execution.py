"""
define agent tool call record structure: put proposal, MCP and feedback together

"""

from dataclasses import dataclass
import base64
from agents.models import ReadFileCall, ReadFileFeedback

from .mcp_models import FileReadResponse
from mcp import ClientSession

from .mcp_client import read_file


@dataclass(frozen=True)
class AgentFileReadRecord:
    call: ReadFileCall
    response: FileReadResponse
    feedback: ReadFileFeedback

    def __post_init__(self) -> None:
        if self.call.call_id != self.feedback.call_id:
            raise ValueError(
                "Feedback call_id must match the tool proposal."
            )

# use unified response with file read
def build_read_feedback(
    call: ReadFileCall,
    response: FileReadResponse,
) -> ReadFileFeedback:
    if response.execution_status != "succeeded":
        return ReadFileFeedback(
            call_id=call.call_id,
            succeeded=False,
            reason=response.reason,
            text=None,
            truncated=None,
        )

    encoded = response.content_base64
    if encoded is None or response.truncated is None:
        raise ValueError(
            "Successful MCP response is missing content metadata."
        )

    content = base64.b64decode(encoded, validate=True)

    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return ReadFileFeedback(
            call_id=call.call_id,
            succeeded=False,
            reason="text_decode_failed",
            text=None,
            truncated=None,
        )

    return ReadFileFeedback(
        call_id=call.call_id,
        succeeded=True,
        reason=response.reason,
        text=text,
        truncated=response.truncated,
    )


class MCPReadExecutor:
    def __init__(
        self,
        session: ClientSession,
        *,
        max_read_bytes: int,
    ) -> None:
        if type(max_read_bytes) is not int:
            raise TypeError("max_read_bytes must be an integer.")

        if max_read_bytes <= 0:
            raise ValueError("max_read_bytes must be positive.")

        self._session = session
        self._max_read_bytes = max_read_bytes
        self._records: list[AgentFileReadRecord] = []

    # read only method - protect private variables
    @property
    def records(self) -> tuple[AgentFileReadRecord, ...]:
        return tuple(self._records)

    async def __call__(
        self,
        call: ReadFileCall,
    ) -> ReadFileFeedback:
        if not isinstance(call, ReadFileCall):
            raise TypeError("call must be a ReadFileCall.")

        response = await read_file(
            self._session,
            call.path,
            max_read_bytes=self._max_read_bytes,
        )

        feedback = build_read_feedback(call, response)

        record = AgentFileReadRecord(
            call=call,
            response=response,
            feedback=feedback,
        )
        self._records.append(record)

        return feedback
