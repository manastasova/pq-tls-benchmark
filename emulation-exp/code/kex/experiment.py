import csv
import datetime
from multiprocessing import Pool
import os
import subprocess

# only measure on single parallel client until we figure out why s2nd hangs
# after a while on >1 parallel connections
TIMERS = 1
MEASUREMENTS_PER_TIMER = 10

def run_subprocess(command, working_dir='.', expected_returncode=0):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=working_dir
    )
    if(result.stderr):
        print(result.stderr.decode('utf-8'), flush=True)
    assert result.returncode == expected_returncode
    return result.stdout.decode('utf-8')

def change_qdisc(ns, dev, pkt_loss, rtt_millis, speed_mbps):
    command = [
        'sudo', 'ip', 'netns', 'exec', ns,
        'tc', 'qdisc', 'change',
        'dev', dev, 'root', 'netem',
        'limit', '1000',
        'delay', f"{rtt_millis/2.0}ms", f"{rtt_millis/50.0}ms", 'distribution', 'normal',
        'rate', f"{speed_mbps}mbit"
    ]
    if pkt_loss > 0:
        command.extend(["loss", f"{pkt_loss}%"])
    print(str(datetime.datetime.now()) + " > " + " ".join(command))
    run_subprocess(command)

rtt_latencies = [
    #35,    #, f"{rtt_millis/90.0}ms", 'distribution', 'normal', 
    50,     # for 1mbps speed (fast connections)
    #75,
    #150,    # for 100mbps speed (slow connections)
]


speed = [
    #1000,       # superFast
    100,        # fast
    # 1,          # slow
]

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
    # Fallback: Try a policy that supports both traditional and ML-DSA
    '20250512',
    # This is 20241001 with ML-DSA support added - supports both PQ signatures and PQ key exchange
]

loss_rates = [0]

xfer_sizes = [
    0,             # handshake-only, close immediately
    #2**10*50,      # 50     KiB
    #2**10*150,     # 150     KiB
]

with open("data/112525/50KB_S24C10.csv", 'w') as out:
    csv_out=csv.writer(out)
    csv_out.writerow(
        ["policy", "rtt", "speed", "xfer_bytes", "latency"]
        )
    for speed_mbps in speed:
        for rtt in rtt_latencies:
            change_qdisc('cli_ns', 'cli_ve', 0, rtt, speed_mbps)
            change_qdisc('srv_ns', 'srv_ve', 0, rtt, speed_mbps)
            measured_rtt = get_rtt_ms()
            change_qdisc('cli_ns', 'cli_ve', 0, measured_rtt, speed_mbps)
            change_qdisc('srv_ns', 'srv_ve', 0, measured_rtt, speed_mbps)
            for security_policy in security_policies:
                for xfer_size in map(int, xfer_sizes):
                    for in_row in run_timers(security_policy, timer_pool, xfer_size):
                        row = [
                            security_policy,
                            str(measured_rtt),
                            str(speed_mbps),
                            str(xfer_size),
                            *in_row,
                        ]
                        csv_out.writerow(row)
