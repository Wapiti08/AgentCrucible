"""Low-level Linux openat2 definitions. --- kernal-level boundary check"""
import platform
import sys
import ctypes
from enum import IntFlag
import os
from pydantic import BaseModel, ConfigDict, Field, field_validator


class UnsupportedPlatformError(RuntimeError):
    """The current platform or ABI is not supported."""

def _get_supported_architecture() -> str:
    if sys.platform != "linux":
        raise UnsupportedPlatformError("openat2 requires Linux.")
    
    machine = platform.machine().lower()

    aliases = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "aarch64",
        "arm64": "aarch64",
    }

    architecture = aliases.get(machine)

    if architecture is None:
        raise UnsupportedPlatformError(
            f"Unsupported CPU architecture: {machine}"
        )
    
    if (
            ctypes.sizeof(ctypes.c_void_p) != 8
            or ctypes.sizeof(ctypes.c_long) != 8
            or ctypes.sizeof(ctypes.c_int) != 4
        ):
            raise UnsupportedPlatformError(
                "A supported 64-bit Linux ABI is required."
            )

    return architecture


# define strict type check
class OpenBeneathArguments(BaseModel):
    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    directory_fd: int = Field(ge=0, le=2**31 - 1)
    relative_path: str = Field(min_length=1)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("Path must not contain NUL characters.")

        if value.startswith("/"):
            raise ValueError("Expected a relative path.")

        return value


class ResolveFlags(IntFlag):
    # prohibit /proc/.../fd/... like link
    NO_MAGICLINKS = 0x02
    # prohibit path from escaping the starting directory
    BENEATH = 0x08


class OpenHow(ctypes.Structure):
    # flags: how to open
    # mode: file mode (permissions) if creating a new file
    # resolve: limitation when resolving the path (e.g., prohibit symlinks)
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


def build_open_how(flags: int) -> OpenHow:
    return OpenHow(
        flags=flags,
        mode=0,
        # or manipulation of flags to set the resolve field
        resolve=int(
            ResolveFlags.BENEATH
            | ResolveFlags.NO_MAGICLINKS
        ),
    )


def _encode_relative_path(
    directory_fd: int,
    relative_path: str,
) -> bytes:
    """ validate the directory fd and encode a relative path.
    
    """
    arguments = OpenBeneathArguments(
        directory_fd=directory_fd,
        relative_path=relative_path,
    )
    # convert to bytes for passing to the syscall
    return os.fsencode(arguments.relative_path)


class LinuxSyscalls:
    def __init__(self) -> None:
        raise NotImplementedError("Linux syscall binding is not implemented yet.")
