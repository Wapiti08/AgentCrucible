"""Shared local artifact paths for runner entry points."""

import tempfile
from pathlib import Path

from mcp_servers.filesystem_server.models import FileServiceConfig


def create_audit_path(config: FileServiceConfig) -> Path:
    workspace = Path(config.workspace_root).resolve()
    audit_parent = Path(tempfile.gettempdir()).resolve(strict=True)

    if audit_parent.is_relative_to(workspace):
        raise ValueError(
            "The temporary audit directory would be inside the workspace."
        )

    audit_directory = Path(
        tempfile.mkdtemp(
            prefix="agentcrucible-audit-",
            dir=audit_parent,
        )
    )

    return audit_directory / "events.jsonl"
