import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_servers.filesystem_server.models import FileServiceConfig

'''
responsible for connected lifecycle

asyncio is called in other functions which call the function defined in this file

low-level asyncio is achieved by mcp library
'''


@asynccontextmanager
async def connect_filesystem_server(
    config: FileServiceConfig,
) -> AsyncIterator[ClientSession]:
    """Start one filesystem server and reuse its session for a batch."""
    # project root
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