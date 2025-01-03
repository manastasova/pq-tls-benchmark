import csv
import datetime
from multiprocessing import Pool
import os
import re
import subprocess

# only measure on single parallel client until we figure out why s2nd hangs
# after a while on >1 parallel connections
TIMERS = 1
MEASUREMENTS_PER_TIMER = 1000

def get_mtu(ns: str) -> int:
    mtu_re = re.compile(r".+ mtu ([0-9]+) .+")
    cmd = []
    dev = 'eth0'
    if ns:
        cmd += ['sudo', 'ip', 'netns', 'exec', f"{ns}_ns"]
        dev = f"{ns}_ve"
    cmd += ['ip', 'link', 'show', 'dev', dev]
    try:
        out = run_subprocess(cmd)
        return int(out.match(r.decode()).group(1))
    except:
        return 9001

def set_mtu(ns: str, mtu: int):
    cmd = [
        'sudo', 'ip', 'netns', 'exec', f"{ns}_ns",
        'ip', 'link', 'set', 'mtu', str(mtu), f"{ns}_ve",
    ]
    run_subprocess(cmd)

def run_subprocess(command, working_dir='.', expected_returncode=0):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=working_dir
    )
    if(result.stderr):
        print(result.stderr)
    assert result.returncode == expected_returncode
    return result.stdout.decode('utf-8')

def change_qdisc(ns, dev, pkt_loss, rtt_millis):
    command = [
        'sudo', 'ip', 'netns', 'exec', ns,
        'tc', 'qdisc', 'change',
        'dev', dev, 'root', 'netem',
        'limit', '1000',
        'delay', f"{rtt_millis/2.0}ms",
        'rate', '1000mbit'
    ]
    if pkt_loss > 0:
        command.extend(["loss", f"{pkt_loss}%"])
    print(str(datetime.datetime.now()) + " > " + " ".join(command))
    run_subprocess(command)

def time_handshake(security_policy, measurements, xfer_size):
    assert xfer_size >= 0
    command = [
        'sudo', 'ip', 'netns', 'exec', 'cli_ns',
        './s_timer.o', security_policy, str(measurements), str(xfer_size),
    ]
    rows = [row.split(',') for row in run_subprocess(command).strip().split('\n')]
    return [list(map(float, row)) for row in rows]

def run_timers(security_policy, timer_pool, xfer_size):
    results_nested = timer_pool.starmap(time_handshake, [(security_policy,
        MEASUREMENTS_PER_TIMER, xfer_size)] * TIMERS)
    return [item for sublist in results_nested for item in sublist]

def get_rtt_ms() -> float:
    command = [
        'sudo', 'ip', 'netns', 'exec', 'cli_ns',
        'ping', '10.0.0.1', '-c', '30'
    ]
    result = run_subprocess(command)
    result_fmt = result.splitlines()[-1].split("/")
    return float(result_fmt[4])

# Main
timer_pool = Pool(processes=TIMERS)

if not os.path.exists('data'):
    os.makedirs('data')

security_policies = [
    'PQ-TLS-1-3-P256',
    'PQ-TLS-1-3-P384',
    'PQ-TLS-1-3-P521',
    'PQ-TLS-1-3-KYBER512',
    'PQ-TLS-1-3-KYBER768',
    'PQ-TLS-1-3-KYBER1024',
]

rtt_latencies = [
    0.08,   # localhost
    0.69,   # PDX => PDX
    21.0,   # PDX => SFO
    133.0,  # PDX => LHR
    230.0,  # PDX => BOM
]

loss_rates = [0, 0.1, 0.5, 1, 1.5, 2, 2.5, 3, 10]

xfer_sizes = [
    0,              # handshake-only, close immediately
]

DEFAULT_MTU = get_mtu(None)
assert get_mtu('cli') == get_mtu('srv')
mtus = [
    DEFAULT_MTU,
]
if DEFAULT_MTU < 9000:
    mtus += [9000]
if DEFAULT_MTU != 1500:
    mtus += [1500]

# TODO: delete below for full measurements...
rtt_latencies = [0]
loss_rates = [0]
mtus = [DEFAULT_MTU]
security_policies = [
    'PQ-TLS-1-3-P384',
    'PQ-TLS-1-3-KYBER768-x25519',
]

with open("data/data.csv", 'w') as out:
    csv_out=csv.writer(out)
    csv_out.writerow([
        "policy", "rtt", "pkt_loss", "xfer_bytes", "mtu", "latency",
        "tcpi_retransmits", "tcpi_retrans", "tcpi_total_retrans",
        "tcpi_lost",
    ])
    for rtt in rtt_latencies:
        if rtt > 0:
            change_qdisc('cli_ns', 'cli_ve', 0, rtt)
            change_qdisc('srv_ns', 'srv_ve', 0, rtt)
        measured_rtt = get_rtt_ms() if rtt > 0 else 0
        for pkt_loss in loss_rates:
            change_qdisc('cli_ns', 'cli_ve', pkt_loss, measured_rtt)
            change_qdisc('srv_ns', 'srv_ve', pkt_loss, measured_rtt)
            for security_policy in security_policies:
                for xfer_size in map(int, xfer_sizes):
                    for mtu in mtus:
                        set_mtu('cli', mtu)
                        set_mtu('srv', mtu)
                        for in_row in run_timers(security_policy, timer_pool, xfer_size):
                            row = [
                                security_policy,
                                str(measured_rtt),
                                str(pkt_loss/100),
                                str(xfer_size),
                                str(mtu),
                                *in_row,
                            ]
                            csv_out.writerow(row)
