"""Pure configuration path conversion; no filesystem access or authorization."""

from pathlib import PurePosixPath
from .base import PlatformInitializationError, PlatformErrorCode, PlatformRequestError


def authorized_root_relative_path(
    workspace_root: str,
    configured_root: str,
) -> str:
    """Express an authorized root relative to the configured workspace."""
    for name, value in (
        ("workspace_root", workspace_root),
        ("authorized_root", configured_root),
    ):
        if not isinstance(value, str) or not value:
            raise PlatformInitializationError(
                f"{name} must be a non-empty string."
            )

        if "\x00" in value:
            raise PlatformInitializationError(
                f"{name} must not contain NUL characters."
            )

    # Normalize separators without resolving symlinks or removing '..'.
    if not workspace_root.startswith("/"):
        raise PlatformInitializationError(
            "Workspace path must be absolute."
        )

    workspace = PurePosixPath(
        "/" + workspace_root.lstrip("/")
    )

    if ".." in workspace.parts:
        raise PlatformInitializationError(
            "Workspace configuration must not contain '..'."
        )

    # Preserve relative paths for constrained kernel resolution.
    if not configured_root.startswith("/"):
        return configured_root

    absolute_root = PurePosixPath(
        "/" + configured_root.lstrip("/")
    )

    try:
        relative_root = absolute_root.relative_to(workspace)
    except ValueError as exc:
        raise PlatformInitializationError(
            "Absolute authorized root must use the workspace path prefix."
        ) from exc

    return str(relative_root)


def request_relative_path(
    workspace_root: str,
    original_path: str,
) -> str:
    """Convert a request path without resolving filesystem objects.

    workspace_root must already have passed initialization validation.
    """
    if (
        not isinstance(original_path, str)
        or not original_path
        or "\x00" in original_path
    ):
        raise PlatformRequestError(
            PlatformErrorCode.INVALID_PATH,
        )
    
    if not original_path.startswith("/"):
        return original_path

    workspace = PurePosixPath(
        "/" + workspace_root.lstrip("/")
    )
    target = PurePosixPath(
        "/" + original_path.lstrip("/")
    )

    try:
        relative = target.relative_to(workspace)
    except ValueError as exc:
        raise PlatformRequestError(
            PlatformErrorCode.OUTSIDE_WORKSPACE,
        ) from exc

    return str(relative)

