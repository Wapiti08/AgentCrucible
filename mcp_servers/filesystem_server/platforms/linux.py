from contextlib import AbstractContextManager
import stat
from .base import FilePlatform, OpenedFile, PlatformInitializationError, FileIdentity, PlatformErrorCode, PlatformRequestError
from ..models import FileServiceConfig, ReadRequest
import os
import sys
from pathlib import PurePosixPath
from .linux_syscalls import UnsupportedPlatformError, LinuxSyscalls
from .path_utils import authorized_root_relative_path, request_relative_path
from collections.abc import Iterator
from contextlib import contextmanager


class LinuxFilePlatform(FilePlatform):
    def __init__(self, config: FileServiceConfig) -> None:
        super().__init__(config)
        # None means not opened yet, otherwise it will be a valid file descriptor
        self._workspace_fd: int | None = None
        # define multiply authorized roots 
        self._authorized_root_fds: dict[str, int] = {}
        self._authorized_root_identities: dict[str, FileIdentity] = {}
        self._authorization_invalidated = False
        
        try:
            self._check_environment()
            # check safe open capability and capture workspace fd
            self._syscalls = LinuxSyscalls()
            self._open_workspace()
            self._probe_openat2()
            self._open_authorized_roots()
        
        except BaseException as init_error:
            try:
                self.close()
            except BaseException as cleanup_error:
                raise BaseExceptionGroup(
                    "Initialization failed and cleanup also failed.",
                    [init_error, cleanup_error],
                ) from None
            
            if isinstance(init_error, PlatformInitializationError):
                raise

            if isinstance(init_error, (OSError, UnsupportedPlatformError)):
                raise PlatformInitializationError(
                    "Unable to initialize the Linux file platform."
                ) from init_error

            raise

    @contextmanager
    def _open_regular_target(
        self,
        relative_path: str,
    ) -> Iterator[int]:
        """Yield a reference to a regular file, then close it."""
        


        
    @contextmanager
    def open_read(self, 
                  request: ReadRequest) -> Iterator[OpenedFile]:
        """ Validate a read request before attempting to open its target.

        """
        self._ensure_open()

        if not isinstance(request, ReadRequest):
            raise TypeError("request must be a ReadRequest instance.")
        
        original_path = request.original_path

        if not original_path or "\x00" in original_path:
            raise PlatformRequestError(
                PlatformErrorCode.INVALID_PATH,
            )
        
        if not self._authorized_root_fds:
            raise PlatformRequestError(
                PlatformErrorCode.NO_AUTHORIZED_ROOTS,
            )
        
        relative_path = request_relative_path(
            self.config.workspace_root,
            original_path
        )

        self._check_authorized_roots()

        raise NotImplementedError("Safe opening is not implemented yet.")
    
        yield


    def _close_resources(self) -> None:
        # get all owned fd
        owned_fds = set(self._authorized_root_fds.values())
        
        if self._workspace_fd is not None:
            owned_fds.add(self._workspace_fd)
        
        # clear ownership records, avoid double closing
        self._authorized_root_fds.clear()
        self._authorized_root_identities.clear()
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
        
    def _open_workspace(self) -> None:
        """Acquire the trusted workspace directory."""

        # for linux, keep one starting /
        workspace = "/" + self.config.workspace_root.lstrip("/")

        self._workspace_fd = os.open(
            workspace,
            os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC,
        )

    def _probe_openat2(self) -> None:
        """capability check: Check that the required constrained opening operation works."""

        workspace_fd = self._workspace_fd

        if workspace_fd is None:
            raise RuntimeError("Workspace directory is not open.")

        probe_fd = self._syscalls.open_beneath(
            directory_fd=workspace_fd,
            relative_path=".",
            flags=os.O_PATH | os.O_DIRECTORY,
        )

        os.close(probe_fd)

     
    def _open_authorized_roots(self) -> None:
        """Open configured roots and record their initial identities."""

        workspace_fd = self._workspace_fd

        if workspace_fd is None:
            raise RuntimeError("Workspace directory is not open.")
        
        for configured_root in self.config.authorized_roots:
            relative_path = authorized_root_relative_path(
                self.config.workspace_root,
                configured_root,
            )

            # open path only once
            if relative_path in self._authorized_root_fds:
                continue

            root_fd = self._syscalls.open_beneath(
                directory_fd=workspace_fd,
                relative_path=relative_path,
                flags=os.O_PATH | os.O_DIRECTORY,
            )

            # Record fd ownership so initialization cleanup can release it.
            try:
                self._authorized_root_fds[relative_path] = root_fd
            except BaseException:
                os.close(root_fd)
                raise
            # Query metadata for the already-opened directory.
            metadata = os.fstat(root_fd)

            if not stat.S_ISDIR(metadata.st_mode):
                raise PlatformInitializationError(
                    "An authorized root is not a directory."
                )

            self._authorized_root_identities[relative_path] = FileIdentity(
                device=metadata.st_dev,
                inode=metadata.st_ino,
        )
            

    def _check_authorized_roots(self) -> None:
        """Reject requests if the configured directory state is no longer valid."""
        
        self._ensure_open()

        if self._authorization_invalidated:
            raise PlatformRequestError(
                PlatformErrorCode.AUTHORIZATION_STATE_UNVERIFIABLE,
        )

        workspace_fd = self._workspace_fd

        if workspace_fd is None:
            raise RuntimeError("Workspace directory is not open.")

        for relative_path, expected_identity in (
            self._authorized_root_identities.items()
        ):
            try:
                check_fd = self._syscalls.open_beneath(
                    directory_fd=workspace_fd,
                    relative_path=relative_path,
                    flags = os.O_PATH | os.O_DIRECTORY,
                )

                try:
                    metadata = os.fstat(check_fd)
                    current_identity = FileIdentity(
                        device = metadata.st_dev,
                        inode = metadata.st_ino,
                    )
                finally:
                    os.close(check_fd)

            except OSError as exc:
                self._authorization_invalidated = True
                raise PlatformRequestError(
                    PlatformErrorCode.AUTHORIZATION_STATE_UNVERIFIABLE,
                ) from exc

            if current_identity != expected_identity:
                self._authorization_invalidated = True
                raise PlatformRequestError(
                    PlatformErrorCode.AUTHORIZATION_STATE_CHANGED,
                )