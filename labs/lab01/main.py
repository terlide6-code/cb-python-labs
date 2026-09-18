"""Run all tasks from laboratory work #1."""

import os
import sys

sys.path.append (os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import main as task3_main


def main():
    """Run Task 1, Task 2, and Task 3 sequentially."""
    print("=== TASK 1 ===")
    run_task1()
    print()

    print("=== TASK 2 ===")
    run_task2()
    print()

    print("=== TASK 3 ===")
    task3_main()


if __name__ == "__main__":
    main()
