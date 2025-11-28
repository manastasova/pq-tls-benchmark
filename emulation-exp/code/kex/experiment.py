import csv
import datetime
from multiprocessing import Pool
import os
import subprocess
import sys
import argparse

# only measure on single parallel client until we figure out why s2nd hangs
# after a while on >1 parallel connections
TIMERS = 1
MEASUREMENTS_PER_TIMER = 1000

def run_subprocess(command, working_dir='.', expected_returncode=0):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=working_dir
    )
    stdout = result.stdout.decode('utf-8')
    stderr = result.stderr.decode('utf-8')
    
    if stderr:
        print(stderr, flush=True)
    
    if result.returncode != expected_returncode:
        error_msg = f"Command failed with return code {result.returncode}: {' '.join(command)}\n"
        if stdout:
            error_msg += f"stdout: {stdout}\n"
        if stderr:
            error_msg += f"stderr: {stderr}\n"
        raise RuntimeError(error_msg)
    
    return stdout

def change_qdisc(ns, dev, pkt_loss, rtt_millis, speed_mbps):
    command = [
        'sudo', 'ip', 'netns', 'exec', ns,
        'tc', 'qdisc', 'change',
        'dev', dev, 'root', 'netem',
        'limit', '1000',
        'delay', f"{rtt_millis/2.0}ms", f"{rtt_millis/90.0}ms", 'distribution', 'normal',
        'rate', f"{speed_mbps}mbit"
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

def set_initcwnd(ns, src_ip, initcwnd):
    """Set the initial congestion window for a network namespace."""
    dev = 'srv_ve' if ns == 'srv_ns' else 'cli_ve'
    command = [
        'sudo', 'ip', 'netns', 'exec', ns,
        'ip', 'route', 'change', '10.0.0.0/24',
        'dev', dev,
        'proto', 'kernel',
        'scope', 'link',
        'src', src_ip,
        'initcwnd', str(initcwnd)
    ]
    print(f"{datetime.datetime.now()} > Setting initcwnd={initcwnd} for {ns}: {' '.join(command)}")
    run_subprocess(command)

# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run TLS benchmarks with configurable parameters')
    parser.add_argument('--server-icwnd', type=int, required=True, help='Server initial congestion window')
    parser.add_argument('--client-icwnd', type=int, required=True, help='Client initial congestion window')
    parser.add_argument('--rtt', type=int, required=True, help='RTT in milliseconds')
    parser.add_argument('--bytes', type=int, required=True, help='Transfer size in KB')
    parser.add_argument('--speed', type=int, required=True, help='Network speed in Mbps')
    parser.add_argument('--output', type=str, required=True, help='Output CSV filename')
    
    args = parser.parse_args()
    
    # Configuration from arguments
    server_icwnd = args.server_icwnd
    client_icwnd = args.client_icwnd
    rtt_ms = args.rtt
    xfer_kb = args.bytes
    xfer_bytes = xfer_kb * 1024
    speed_mbps = args.speed
    output_filename = args.output
    
    timer_pool = Pool(processes=TIMERS)

    # Ensure the output directory exists
    output_dir = os.path.dirname(output_filename)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    security_policies = [
        '20250512',  # Policy that supports both traditional and ML-DSA
    ]
    
    print(f"\n{'='*60}")
    print(f"Starting measurements with configuration:")
    print(f"  Server initcwnd: {server_icwnd}")
    print(f"  Client initcwnd: {client_icwnd}")
    print(f"  RTT: {rtt_ms}ms")
    print(f"  Transfer size: {xfer_kb}KB ({xfer_bytes} bytes)")
    print(f"  Speed: {speed_mbps}Mbps")
    print(f"  Output file: {output_filename}")
    print(f"{'='*60}\n")

    with open(output_filename, 'w') as out:
        csv_out = csv.writer(out)
        csv_out.writerow(
            ["policy", "rtt", "speed", "xfer_bytes", "handshake_time_ms", "tcpi_retransmits", "tcpi_retrans", "tcpi_total_retrans"]
        )
        
        # Configure network with specified RTT
        change_qdisc('cli_ns', 'cli_ve', 0, rtt_ms, speed_mbps)
        change_qdisc('srv_ns', 'srv_ve', 0, rtt_ms, speed_mbps)
        
        # Set initial congestion windows
        set_initcwnd('srv_ns', '10.0.0.1', server_icwnd)
        set_initcwnd('cli_ns', '10.0.0.2', client_icwnd)
        
        # Measure actual RTT
        measured_rtt = get_rtt_ms()
        print(f"Measured RTT: {measured_rtt}ms (target was {rtt_ms}ms)")
        
        # Adjust to measured RTT
        change_qdisc('cli_ns', 'cli_ve', 0, measured_rtt, speed_mbps)
        change_qdisc('srv_ns', 'srv_ve', 0, measured_rtt, speed_mbps)
        
        # Run measurements for each security policy
        for security_policy in security_policies:
            print(f"\nTesting security policy: {security_policy}")
            for in_row in run_timers(security_policy, timer_pool, xfer_bytes):
                row = [
                    security_policy,
                    str(measured_rtt),
                    str(speed_mbps),
                    str(xfer_bytes),
                    *in_row,
                ]
                csv_out.writerow(row)
                print(f"  Measurement: latency={in_row[0]:.2f}ms")
    
    print(f"\n{'='*60}")
    print(f"Measurements complete!")
    print(f"Results saved to: {output_filename}")
    print(f"{'='*60}\n")
