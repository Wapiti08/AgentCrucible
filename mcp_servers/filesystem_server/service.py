from .models import (
    ExecutionStatus,
    PolicyDecision,
    ReadRequest,
    ReadResult,
)

from .platforms.base import (
    FilePlatform,
    PlatformErrorCode,
    PlatformRequestError,
)

class FileService:
    def __init__(self, platform: FilePlatform) -> None:
        self._platform = platform

    def read(self, request: ReadRequest) -> ReadResult:
        '''
        read max bytes and truncated the exceeded part
        '''

        limit = self._platform.config.max_read_bytes

        try:
            with self._platform.open_read(request) as opened:
                resolved_path = opened.resolved_path
                try:
                    data = opened.stream.read(limit + 1)
                except OSError as exc:
                    raise PlatformRequestError(
                        PlatformErrorCode.IO_ERROR,
                        resolved_path=resolved_path,
                        policy_decision=PolicyDecision.ALLOWED,
                    ) from exc

        except PlatformRequestError as exc:
            execution_status = (
                ExecutionStatus.FAILED
                if exc.policy_decision is PolicyDecision.ALLOWED
                else ExecutionStatus.NOT_STARTED
            )

            return ReadResult(
                request_id=request.request_id,
                original_path=request.original_path,
                resolved_path=exc.resolved_path,
                policy_decision=exc.policy_decision,
                execution_status=execution_status,
                reason=exc.code.value,
                content=None,
                truncated=None,
            )

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
