import argparse
from collections.abc import Sequence
import json
from pathlib import Path
import sys

from attack_runner.run_suite import main as run_suite
from examples.prepare_filesystem_fixture import create_fixture


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the six-case filesystem boundary demo.",
    )

    parser.add_argument(
        "--report-file",
        type=Path,
        help="Save the report to a new file in an existing directory.",
    )
    args = parser.parse_args(argv)

    if sys.platform != "linux":
        print(
            "Run this demo inside a Linux environment.",
            file=sys.stderr,
        )
        return 2

    workspace = create_fixture()
    report_path = (
            args.report_file
            if args.report_file is not None
            else workspace.parent / "report.json"
        )
    case_file = (
        Path(__file__).resolve().parent
        / "filesystem-boundary-cases.json"
    )

    print(
        json.dumps(
            {
                "demo": "filesystem-boundary",
                "mode": "direct_mcp",
                "workspace": str(workspace),
                "report_file": str(report_path),
            },
            ensure_ascii=True,
        ),
        file=sys.stderr,
    )

    return run_suite(
        [
            "--case-file",
            str(case_file),
            "--workspace",
            str(workspace),
            "--allowed-root",
            "public",
            "--report-file",
            str(report_path),
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())
