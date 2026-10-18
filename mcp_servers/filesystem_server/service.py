from .models import (
    ExecutionStatus,
    PolicyDecision,
    ReadRequest,
    ReadResult,
)

from .platforms.base import FilePlatform


class FileService:
    def __init__(self, platform: FilePlatform) -> None:
        self._platform = platform

    def read(self, request: ReadRequest) -> ReadResult:
        '''
        read max bytes and truncated the exceeded part
        '''

        limit = self._platform.config.max_read_bytes

        with self._platform.open_read(request) as opened:
            data = opened.stream.read(limit + 1)
            resolved_path = opened.resolved_path

        return ReadResult(
            request_id=request.request_id,
            original_path=request.original_path,
            resolved_path=resolved_path,
            policy_decision=PolicyDecision.ALLOWED,
            execution_status=ExecutionStatus.SUCCEEDED,
            reason="File read successfully.",
            content=data[:limit],
            truncated=len(data) > limit,
        )
