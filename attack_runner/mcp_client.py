import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from .mcp_models import FileReadResponse
from mcp_servers.filesystem_server.models import FileServiceConfig

'''
responsible for connected lifecycle

asyncio is called in other functions which call the function defined in this file

low-level asyncio is achieved by mcp library
'''


@asynccontextmanager
async def connect_filesystem_server(
    config: FileServiceConfig,
    *,
    audit_path: Path,
) -> AsyncIterator[ClientSession]:
    """Start one filesystem server and reuse its session for a batch."""
    # project root
    if not audit_path.is_absolute():
        raise ValueError("audit_path must be absolute.")

    project_root = Path(__file__).resolve().parents[1]

    # cmd sent to python subprocess
    args = [
        # no .pyc cache file
        "-B",
        # execute as python module
        "-m",
        # Run the server module and its main() entry point.
        "mcp_servers.filesystem_server.server",
        "--workspace",
        config.workspace_root,
        "--max-read-bytes",
        str(config.max_read_bytes),
        "--audit-file",
        str(audit_path),
    ]

    for root in config.authorized_roots:
        args.append(f"--allowed-root={root}")

    parameters = StdioServerParameters(
        command=sys.executable,
        args=args,
        cwd=project_root,
    )
    # launch subprocess and build standard input/output pipeline
    # The SDK context manager handles transport and subprocess cleanup.
    async with stdio_client(parameters) as (read_stream, write_stream):
        # build mcp protocol session on pipeline
        async with ClientSession(
            read_stream,
            write_stream,
            read_timeout_seconds=15,
        ) as session:
            # handshake initialization between client and server
            await session.initialize()
            # hand over session control
            yield session


def validate_read_response(
    raw_data: object,
    *,
    max_read_bytes: int,
) -> FileReadResponse:
    """
    restrict content decoding budget

    params:
        max_read_bytes: from configuration while not user provided value

    """
    if type(max_read_bytes) is not int:
        raise TypeError("max_read_bytes must be an integer.")

    if max_read_bytes <= 0:
        raise ValueError("max_read_bytes must be positive.")

    if not isinstance(raw_data, dict):
        raise ValueError("Expected a structured response object.")

    encoded = raw_data.get("content_base64")
    # make sure it is integer
    max_encoded_length = 4 * ((max_read_bytes + 2) // 3)

    if isinstance(encoded, str) and len(encoded) > max_encoded_length:
        raise ValueError("Encoded content exceeds the configured limit.")

    returned_bytes = raw_data.get("returned_bytes")
    if type(returned_bytes) is int and returned_bytes > max_read_bytes:
        raise ValueError("Returned bytes exceed the configured limit.")

    response = FileReadResponse.model_validate(raw_data)

    if response.truncated is True:
        if response.returned_bytes != max_read_bytes:
            raise ValueError(
                "Truncated content must fill the configured read limit."
            )

    return response


class MCPToolCallError(RuntimeError):
    """The MCP server reported a tool execution error."""


async def read_file(
    session: ClientSession,
    path: str,
    *,
    max_read_bytes: int,
) -> FileReadResponse:

    if not isinstance(path, str):
        raise TypeError("path must be a string.")

    if type(max_read_bytes) is not int:
        raise TypeError("max_read_bytes must be an integer.")

    if max_read_bytes <= 0:
        raise ValueError("max_read_bytes must be positive.")

    result = await session.call_tool(
        "read_file",
        {"path": path},
    )

    if result.is_error:
        raise MCPToolCallError(
            "The filesystem MCP tool reported an error."
        )

    return validate_read_response(
        result.structured_content,
        max_read_bytes=max_read_bytes,
    )