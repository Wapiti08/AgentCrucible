"""Platform contracts for safe file opening."""

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from types import TracebackType
from typing import BinaryIO, Self

from ..models import FileServiceConfig, ReadRequest


class PlatformErrorCode(str, Enum):
    INVALID_PATH = "invalid_path"
    NO_AUTHORIZED_ROOTS = "no_authorized_roots"
    OUTSIDE_WORKSPACE = "outside_workspace"
    OUTSIDE_AUTHORIZED_ROOTS = "outside_authorized_roots"
    NOT_REGULAR_FILE = "not_regular_file"
    FILE_NOT_FOUND = "file_not_found"
    PERMISSION_DENIED = "permission_denied"
    SYMLINK_LOOP = "symlink_loop"
    IO_ERROR = "io_error"


# runtimeerror is a built-in exception
class PlatformInitializationError(RuntimeError):
    """The platform cannot start safely."""


class PlatformRequestError(Exception):
    """An expected request failure, translated by the service."""

    def __init__(
        self,
        code: PlatformErrorCode,
        *,
        resolved_path: str | None = None,
    ) -> None:
        # what is required by RuntimeError
        super().__init__(code.value)
        self.code = code
        self.resolved_path = resolved_path


@dataclass(frozen=True)
class FileIdentity:
    """Identity of the opened object, not a content snapshot."""

    # unique identifier for the file
    device: int
    # index of node
    inode: int


@dataclass(frozen=True)
class OpenedFile:
    """Borrowed file stream valid only inside the opening context."""

    # The identity of the file
    identity: FileIdentity
    stream: BinaryIO
    resolved_path: str | None


class FilePlatform(ABC):
    def __init__(self, config: FileServiceConfig) -> None:
        self._config = config
        self._closed = False

    @property # readonly
    def config(self) -> FileServiceConfig:
        return self._config
    
    @property # readonly
    def closed(self) -> bool:
        return self._closed
    
    @abstractmethod
    def open_read(
        self,
        request: ReadRequest,
    ) -> AbstractContextManager[OpenedFile]:
        """Safely open an authorized regular file for binary reading.

        Implementations must:
        - Reject use after the platform is closed.
        - Enforce workspace and authorization constraints during opening.
        - Verify the type of the actual opened file.
        - Yield an OpenedFile whose stream is positioned at the beginning.
        - Close the stream when the context exits, including on exceptions.
        - Release any temporary handles if opening fails.

        Expected request failures raise PlatformRequestError.
        """
        raise NotImplementedError
    
    def close(self) -> None:
        """
        release platform resources; repeated calls are harmless
        """
        if self._closed:
            return 
        
        self._closed = True
        self._close_resources()

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("File platform is closed.")

    @abstractmethod
    def _close_resources(self) -> None:
        """ Attempt to release every owned long-lived handle
        
        This method must tolerate partially initialized state.
        One cleanup failure must not prevent attempts to release others.
        """
        raise NotImplementedError
    
    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()