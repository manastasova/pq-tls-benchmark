from itertools import groupby
from functools import cmp_to_key
from statistics import *
from tabulate import tabulate

import os
import csv

DATA_DIR = "./kex/data"


def format_row(row):
    return [
        row[0],  # KEX
        f"{round(row[1], 2)}ms",  # delay
        f"{str(row[2])}%",  # loss %
        round(row[3], 2),  # mean
        round(row[4], 2),  # variance
        round(row[5], 2),  # p0
        round(row[6], 2),  # p50
        round(row[7], 2),  # p90
        round(row[8], 2),  # p99
    ]


def print_stats(data_dir=DATA_DIR):
    headers = [
        ["KEX", "delay", "loss %", "mean", "variance", "p0", "p50", "p90", "p99"]
    ]
    stats = []
    for fname in os.listdir(data_dir):
        with open(f"{data_dir}/{fname}") as f:
            for row in csv.reader(f, delimiter=","):
                row = list(map(float, row))
                loss = row.pop(0)
                kex = fname.split("_")[0].split("-")[-1]
                delay = fname.split("_")[1]
                delay = float(delay.split("p")[0]) + float(
                    "0." + delay.split("p")[1][:-6]
                )
                percentiles = quantiles(row, n=100)
                processed = [
                    kex,
                    delay,
                    loss,
                    mean(row),
                    variance(row),
                    min(row),
                    percentiles[50 - 1],
                    percentiles[90 - 1],
                    percentiles[99 - 1],
                ]
                stats.append(processed)

    key_fn = lambda row: row[1]  # group by delay
    stats = sorted(stats, key=key_fn)
    for delay, group in groupby(stats, key_fn):
        print(f"DELAY: {delay}")

        # below is a garbage special-case hack to make sure KYBER1024 is considered "larger"
        # than KYBER768
        def _compare_row_kex(row1, row2):
            k1, k2 = row1[0], row2[0]
            if k1 == k2:
                return 0
            if k1 == "KYBER768" and k2 == "KYBER1024":
                return -1
            if k1 == "KYBER1024" and k2 == "KYBER768":
                return 1
            return 1 if k1 > k2 else -1

        group = sorted(group, key=cmp_to_key(_compare_row_kex))  # sort by KEX name
        formatted = list(format_row(row) for row in group)
        print(tabulate(headers + formatted, headers="firstrow"))
        print()


if __name__ == "__main__":
    print_stats()
