from contextlib import AbstractContextManager
from .base import FilePlatform, OpenedFile, PlatformInitializationError
from ..models import FileServiceConfig, ReadRequest
import os
import sys
from pathlib import PurePosixPath

class LinuxFilePlatform(FilePlatform):
    def __init__(self, config: FileServiceConfig) -> None:
        super().__init__(config)
        # None means not opened yet, otherwise it will be a valid file descriptor
        self._workspace_fd: int | None = None
        # define multiply authorized roots 
        self._authorized_root_fds: dict[str, int] = {}
        
        try:
            self._check_environment()
            # check safe open capability and capture workspace fd
        
        except BaseException as init_error:
            try:
                self.close()
            except BaseException as cleanup_error:
                raise BaseExceptionGroup(
                    "Initialization failed and cleanup also failed.",
                    [init_error, cleanup_error],
                ) from None
            raise
        

    def open_read(self, 
                  request: ReadRequest) -> AbstractContextManager[OpenedFile]:
        """ open function sepcifically for linux platform

        """
        self._ensure_open()

        raise NotImplementedError("Safe opening is not implemented yet.")

    def _close_resources(self) -> None:
        # get all owned fd
        owned_fds = set(self._authorized_root_fds.values())
        
        if self._workspace_fd is not None:
            owned_fds.add(self._workspace_fd)
        
        # clear ownership records, avoid double closing
        self._authorized_root_fds.clear()
        self._workspace_fd = None

        errors: list[OSError] = []

        for fd in owned_fds:
            try:
                os.close(fd)
            except OSError as exc:
                errors.append(exc)

        if errors:
            raise ExceptionGroup(
                "Failed to close some directory file descriptors.",
                errors,
            )
        
    def _check_environment(self) -> None:
        if sys.platform != "linux":
            raise PlatformInitializationError(
                "LinuxFilePlatform requires Linux."
            )
        
        workspace = self.config.workspace_root

        if "\x00" in workspace:
            raise PlatformInitializationError(
                "Workspace path must not contain NUL characters."
            )

        path = PurePosixPath(workspace)

        if not path.is_absolute():
            raise PlatformInitializationError(
                "Workspace path must be absolute."
            )

        if ".." in path.parts:
            raise PlatformInitializationError(
                "Workspace configuration must not contain '..'."
            )