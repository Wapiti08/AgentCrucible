from pathlib import Path

from .audit import JsonlAuditWriter
import argparse

from mcp.server import MCPServer

from .platforms.linux import LinuxFilePlatform
from .serialization import ReadFileResponse
from .models import FileServiceConfig
from .service import FileService
from .tools import FileTools


def parse_config() -> tuple[FileServiceConfig, Path]:
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

    parser.add_argument(
        "--audit-file",
        type=Path,
        required=True,
        help="New audit file in a trusted directory outside the workspace.",
    )

    args = parser.parse_args()

    try:
        config = FileServiceConfig(
            workspace_root=args.workspace,
            authorized_roots=tuple(args.allowed_root),
            max_read_bytes=args.max_read_bytes,
        )
    except (TypeError, ValueError) as exc:
        parser.error(str(exc))

    return config, args.audit_file


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
    # integrate audit writer inside server
    config, audit_path = parse_config()

    if not audit_path.is_absolute():
        raise ValueError("Audit file path must be absolute.")

    workspace = Path(config.workspace_root).resolve(strict=True)
    audit_parent = audit_path.parent.resolve(strict=True)

    if not audit_parent.is_dir():
        raise ValueError("Audit parent must be a directory.")

    if audit_parent.is_relative_to(workspace):
        raise ValueError("Audit file must be outside the workspace.")

    audit_path = audit_parent / audit_path.name

    with JsonlAuditWriter(audit_path) as audit_writer:
        with LinuxFilePlatform(config) as platform:
            service = FileService(platform)
            file_tools = FileTools(service, audit_writer)
            server = create_server(file_tools)
            server.run(transport="stdio")

if __name__ == "__main__":
    main()