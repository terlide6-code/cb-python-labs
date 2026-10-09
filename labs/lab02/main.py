"""Command-line entry point for laboratory work #2."""

import argparse

from labs.lab02 import task2
from labs.lab02.task1 import run_demo


def main() -> int:
    """Run the selected Lab 02 task."""
    parser = argparse.ArgumentParser(description="Laboratory Work #2")
    parser.add_argument("command", choices=("demo", "analyze"))
    args, remaining = parser.parse_known_args()

    if args.command == "demo":
        if remaining:
            parser.error("demo does not accept additional arguments")
        run_demo()
        return 0
    return task2.main(remaining)


if __name__ == "__main__":
    raise SystemExit(main())
