import argparse

from mcp.server import MCPServer

from .platforms.linux import LinuxFilePlatform
from .serialization import ReadFileResponse
from .models import FileServiceConfig
from .service import FileService
from .tools import FileTools


def parse_config() -> FileServiceConfig:
    parser = argparse.ArgumentParser(
        description="AgentCrucible filesystem MCP server.",
    )

    # define required workspace, allowed-root, max-read-types
    parser.add_argument(
        "--workspace",
        required=True,
        help="Absolute path to the workspace.",
    )
    parser.add_argument(
        "--allowed-root",
        action="append",
        default=[],
        help="Authorized directory; may be repeated.",
    )
    parser.add_argument(
        "--max-read-bytes",
        type=int,
        default=65536,
        help="Maximum number of file bytes returned.",
    )

    args = parser.parse_args()

    try:
        return FileServiceConfig(
            workspace_root=args.workspace,
            authorized_roots=tuple(args.allowed_root),
            max_read_bytes=args.max_read_bytes,
        )
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))


def create_server(file_tools: FileTools) -> MCPServer:
    '''
    initially, add with only one tool to read file
    '''
    server = MCPServer("AgentCrucible Filesystem")

    @server.tool()
    def read_file(path: str) -> ReadFileResponse:
        """Read an authorized file and return its bytes as Base64.

        Large files are truncated to the server-configured limit.
        Check policy_decision and execution_status before using content.
        """
        return file_tools.read_file(path)

    return server


def main() -> None:
    config = parse_config()

    with LinuxFilePlatform(config) as platform:
        service = FileService(platform)
        file_tools = FileTools(service)
        server = create_server(file_tools)
        server.run(transport="stdio")


if __name__ == "__main__":
    main()