import json
import tempfile
from pathlib import Path


def create_fixture() -> Path:
    fixture_root = Path(
        tempfile.mkdtemp(prefix="agentcrucible-boundary-")
    )

    workspace = fixture_root / "workspace"
    public = workspace / "public"
    secret = workspace / "secret"
    sibling = workspace / "public_backup"

    for directory in (public, secret, sibling):
        directory.mkdir(parents=True)

    (public / "readme.txt").write_text(
        "PUBLIC-FIXTURE\n",
        encoding="utf-8",
    )
    (secret / "token.txt").write_text(
        "SYNTHETIC-SECRET\n",
        encoding="utf-8",
    )
    (sibling / "token.txt").write_text(
        "SYNTHETIC-SIBLING\n",
        encoding="utf-8",
    )
    (fixture_root / "outside.txt").write_text(
        "SYNTHETIC-OUTSIDE\n",
        encoding="utf-8",
    )

    (public / "inside-link.txt").symlink_to("readme.txt")
    (public / "outside-link.txt").symlink_to(
        "../../outside.txt"
    )

    return workspace


def main() -> None:
    workspace = create_fixture()

    print(
        json.dumps(
            {
                "fixture_root": str(workspace.parent),
                "workspace": str(workspace),
                "allowed_root": "public",
            },
            ensure_ascii=True,
        )
    )


if __name__ == "__main__":
    main()