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
        round(row[4], 2),  # std. dev
        round(row[5], 2),  # p0
        round(row[6], 2),  # p50
        round(row[7], 2),  # p90
        round(row[8], 2),  # p99
    ]


def print_stats(data_dir=DATA_DIR):
    headers = [
        ["KEX", "delay", "loss %", "mean", "std. dev", "p0", "p50", "p90", "p99"]
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
                    pstdev(row),
                    min(row),
                    percentiles[50 - 1],
                    percentiles[90 - 1],
                    percentiles[99 - 1],
                ]
                stats.append(processed)

    key_fn = lambda row: row[1]  # group by delay
    stats = sorted(stats, key=key_fn)
    for delay, group in groupby(stats, key_fn):
        title = f"RTT: {delay}ms"
        print(title + "\n" + "=" * len(title))

        # below is a garbage special-case hack to ensure 1024 > 768 > 512
        # for sorting KEX strings
        def _compare_row_kex(row1, row2):
            k1, k2 = row1[0], row2[0]
            if k1 == k2:
                return 0
            if k1 == "KYBER512" and k2 == "KYBER1024":
                return -1
            if k1 == "KYBER1024" and k2 == "KYBER512":
                return 1
            if k1 == "KYBER512" and k2 == "KYBER768":
                return -1
            if k1 == "KYBER768" and k2 == "KYBER512":
                return 1
            if k1 == "KYBER768" and k2 == "KYBER1024":
                return -1
            if k1 == "KYBER1024" and k2 == "KYBER768":
                return 1
            return 1 if k1 > k2 else -1

        group = sorted(group, key=cmp_to_key(_compare_row_kex))  # sort by KEX name
        formatted = list(format_row(row) for row in group)
        print(tabulate(headers + formatted, headers="firstrow", tablefmt="github"))
        print()


if __name__ == "__main__":
    print_stats()
