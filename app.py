import threading

from modules.premint import Premint
from utils import get_tasks


def main():
    tasks = get_tasks("./tasks.csv")

    tasks_count = len(tasks)
    i = 1

    for task in tasks:
        threading.Thread(
            target=Premint(
                task=task,
                task_num=i,
                tasks_count=tasks_count,
                proxy=task["account_proxy"]
            ).start_task
        ).start()
        i += 1


if __name__ == "__main__":
    main()
