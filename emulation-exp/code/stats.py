from itertools import groupby
from functools import cmp_to_key
from statistics import *
from tabulate import tabulate

import os
import csv

DATA_DIR = "./kex/data"


def format_row(row):
    return [
        row[0],  # policy
        round(row[1], 2),  # delay
        round(row[2], 2),  # loss %
        row[3],  # xfer
        row[4],  # MTU
        round(row[5], 2),  # mean
        round(row[6], 2),  # std. dev
        round(row[7], 2),  # p0
        round(row[8], 2),  # p50
        round(row[9], 2),  # p90
        round(row[10], 2),  # p99
    ]


def print_stats(data_dir=DATA_DIR):
    headers = [
        ["policy", "delay (ms)", "loss (%)", "xfer (B)", "mtu (B)", "mean", "std. dev", "p0", "p50", "p90", "p99"]
    ]
    stats = []
    with open(f"{data_dir}/data.csv") as f:
        reader = csv.reader(f, delimiter=",")
        next(reader)    # skip csv headers
        for key, group in groupby(list(reader), lambda r: tuple(r[:5])):
            print(key)
            policy, delay, loss, xfer, mtu = key
            latencies = [float(row[5]) for row in group]
            percentiles = quantiles(latencies, n=100)
            processed = [
                policy,
                float(delay),
                float(loss),
                int(xfer),
                int(mtu),
                mean(latencies),
                pstdev(latencies),
                min(latencies),
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
        formatted = list(format_row(row) for row in group)
        print(tabulate(headers + formatted, headers="firstrow", tablefmt="github"))
        print()


if __name__ == "__main__":
    print_stats()
