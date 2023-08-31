import csv
from multiprocessing import Pool
import os
import subprocess

# only measure on single parallel client until we figure out why s2nd hangs
# after a while on >1 parallel connections
TIMERS = 1
MEASUREMENTS_PER_TIMER = 500

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
    print(" > " + " ".join(command))
    run_subprocess(command)

def time_handshake(security_policy, measurements):
    command = [
        'sudo', 'ip', 'netns', 'exec', 'cli_ns',
        './s_timer.o', security_policy, str(measurements)
    ]
    result = run_subprocess(command)
    return [float(i) for i in result.strip().split(',')]

def run_timers(security_policy, timer_pool):
    results_nested = timer_pool.starmap(time_handshake, [(security_policy, MEASUREMENTS_PER_TIMER)] * TIMERS)
    return [item for sublist in results_nested for item in sublist]

def get_rtt_ms():
    command = [
        'sudo', 'ip', 'netns', 'exec', 'cli_ns',
        'ping', '10.0.0.1', '-c', '30'
    ]

    print(" > " + " ".join(command))
    result = run_subprocess(command)

    result_fmt = result.splitlines()[-1].split("/")
    return result_fmt[4].replace(".", "p")

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

for rtt in rtt_latencies:
    # get emulated RTT
    change_qdisc('cli_ns', 'cli_ve', 0, rtt)
    change_qdisc('srv_ns', 'srv_ve', 0, rtt)
    rtt_str = get_rtt_ms()
    for security_policy in security_policies:
        with open('data/{}_{}ms.csv'.format(security_policy, rtt_str),'w') as out:
            # each line contains: pkt_loss, observations
            csv_out=csv.writer(out)
            for pkt_loss in loss_rates:
                change_qdisc('cli_ns', 'cli_ve', pkt_loss, rtt)
                change_qdisc('srv_ns', 'srv_ve', pkt_loss, rtt)
                result = run_timers(security_policy, timer_pool)
                result.insert(0, pkt_loss)
                csv_out.writerow(result)
