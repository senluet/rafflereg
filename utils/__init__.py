import csv
from itertools import cycle

from eth_account import Account


def get_accounts(path: str) -> dict:
    accounts = {}

    with open(path, "r", encoding="utf8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            try:
                accounts[row["account_name"]] = {
                    "email": row["email"],
                    "private_key": row["private_key"],
                    "twitter_username": row["twitter_username"],
                    "twitter_pass": row["twitter_pass"],
                    "twitter_email": row["twitter_email"],
                    "account_proxy": row["account_proxy"],
                }
            except Exception as err:
                print(f"Error getting profile: {err}")

    return accounts


def get_tasks(path: str) -> list:
    tasks = []

    profiles = get_accounts("./accounts.csv")

    with open(path, "r", encoding="utf8") as input_file:
        reader = csv.DictReader(input_file)
        for row in reader:
            try:
                tasks.append({
                    "raffle_url": row["raffle_url"],
                    "email": profiles[row["account_name"]]["email"],
                    "twitter_username": profiles[row["account_name"]]["twitter_username"],
                    "twitter_pass": profiles[row["account_name"]]["twitter_pass"],
                    "twitter_email": profiles[row["account_name"]]["twitter_email"],
                    "account_proxy": profiles[row["account_name"]]["account_proxy"],
                    "account_name": row["account_name"],
                    "account": Account.from_key(profiles[row["account_name"]]["private_key"]),
                })
            except Exception as err:
                print(f"Error getting task: {err}")

    return tasks
