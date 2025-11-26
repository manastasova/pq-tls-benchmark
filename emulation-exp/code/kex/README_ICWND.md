# Initial Congestion Window (ICW) Experiment

## Overview

This documentation describes how to run TLS benchmark experiments with configurable initial congestion window (ICW) settings for both server and client.

## Files Modified/Created

### 1. `experiment.py` (Modified)
The main experiment script has been updated to accept command-line arguments for:
- `--server-icwnd`: Server initial congestion window (number of segments)
- `--client-icwnd`: Client initial congestion window (number of segments)
- `--rtt`: Round-trip time in milliseconds
- `--bytes`: Transfer size in kilobytes
- `--speed`: Network speed in Mbps
- `--output`: Output CSV filename (including path)

### 2. `run_icwnd_experiment.sh` (New)
A wrapper script that calls `experiment.py` with the following parameters:
- Server ICW (X): 24 segments (fixed)
- Client ICW (Y): Loops through 10 and 24 MSS
- RTT (Z): Loops through 35ms, 50ms, 75ms, 100ms, and 150ms
- Transfer bytes (V): Loops through 0KB, 50KB, and 150KB
- Speed (N): Loops through 1Mbps, 100Mbps, and 1000Mbps

The script runs a total of **70 experiments**:
- **30 experiments** with 0KB transfers (handshake-only): 2 client ICW × 5 RTT × 3 speeds (1, 100, 1000 Mbps)
- **40 experiments** with data transfers (50KB & 150KB): 2 client ICW × 5 RTT × 2 sizes × 2 speeds (100, 1000 Mbps only)

**Note**: 1Mbps speed is only tested with 0KB (handshake-only) transfers, as it's too slow for 50KB and 150KB data transfers and causes timeouts.

## Usage

### Option 1: Using the Wrapper Script

Simply run the pre-configured wrapper script:

```bash
cd /home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex
./run_icwnd_experiment.sh
```

This will run **70 experiments** with the server ICW fixed at 24, looping through:
- 2 client ICW values: 10 MSS and 24 MSS
- 5 RTT values: 35ms, 50ms, 75ms, 100ms, and 150ms
- 3 transfer sizes: 0KB, 50KB, and 150KB
- Speed values:
  - **0KB transfers**: 1Mbps, 100Mbps, and 1000Mbps (all speeds)
  - **50KB & 150KB transfers**: 100Mbps and 1000Mbps only (1Mbps is too slow)

### Option 2: Using experiment.py Directly

For custom configurations, call `experiment.py` directly with your desired parameters:

```bash
cd /home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex
python3 experiment.py \
    --server-icwnd 24 \
    --client-icwnd 10 \
    --rtt 50 \
    --bytes 0 \
    --speed 100 \
    --output "data/icwnd_server24_client10_RTT50_bytes0_speed100.csv"
```

You can change any of these parameters as needed.

## Output

Results are saved to:
```
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server{X}_client{Y}_RTT{Z}_bytes{V}_speed{N}.csv
```

When using the wrapper script, **70 CSV files** are generated (one for each valid client ICW/RTT/transfer size/speed combination):
```
# Examples (showing subset of 90 files):

## Client ICW=10, RTT=50ms, Speed=100Mbps
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server24_client10_RTT50_bytes0_speed100.csv
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server24_client10_RTT50_bytes50_speed100.csv
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server24_client10_RTT50_bytes150_speed100.csv

## Client ICW=24, RTT=100ms, Speed=1000Mbps
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server24_client24_RTT100_bytes0_speed1000.csv
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server24_client24_RTT100_bytes50_speed1000.csv
/home/ubuntu/pq-tls-benchmark/emulation-exp/code/kex/data/icwnd_server24_client24_RTT100_bytes150_speed1000.csv

(... 84 more files covering all combinations)
```

### Output Format

The CSV file contains the following columns:
- `policy`: Security policy used (e.g., 20250512)
- `rtt`: Measured round-trip time in milliseconds
- `speed`: Network speed in Mbps
- `xfer_bytes`: Transfer size in bytes
- `handshake_time_ms`: TLS handshake completion time in milliseconds
- `tcpi_retransmits`: TCP retransmit count
- `tcpi_retrans`: TCP retransmission count
- `tcpi_total_retrans`: Total TCP retransmissions

## How It Works

1. **Network Setup**: The script configures the network namespaces (`srv_ns` and `cli_ns`) with the specified RTT using `tc qdisc`.

2. **ICW Configuration**: Sets the initial congestion window for both server and client using:
   ```bash
   sudo ip netns exec srv_ns ip route change 10.0.0.0/24 dev srv_ve \
       proto kernel scope link src 10.0.0.1 initcwnd 24
   
   sudo ip netns exec cli_ns ip route change 10.0.0.0/24 dev cli_ve \
       proto kernel scope link src 10.0.0.2 initcwnd 10
   ```

3. **RTT Measurement**: Performs a ping test to measure the actual RTT and adjusts the network configuration accordingly.

4. **Benchmarking**: Runs multiple TLS handshake measurements and records the latency.

5. **Data Storage**: Saves all measurements to a CSV file with a descriptive filename.

## Prerequisites

Before running the experiment:

1. Ensure network namespaces are set up (usually done by `setup.sh`)
2. Ensure the TLS server is running (s2nd)
3. Ensure `s_timer.o` is compiled and available

## Example Commands

### Run with default settings (loops through all combinations)
```bash
./run_icwnd_experiment.sh
```
This will automatically run **70 experiments** covering:
- Client ICW values: 10 MSS, 24 MSS
- RTT values: 35ms, 50ms, 75ms, 100ms, 150ms
- Transfer sizes: 0KB (all speeds), 50KB (fast speeds), 150KB (fast speeds)
- Speed values: 
  - 1Mbps, 100Mbps, 1000Mbps for 0KB transfers
  - 100Mbps, 1000Mbps for 50KB and 150KB transfers

### Run with custom parameters
```bash
python3 experiment.py \
    --server-icwnd 30 \
    --client-icwnd 15 \
    --rtt 50 \
    --bytes 0 \
    --speed 100 \
    --output "data/icwnd_server30_client15_RTT50_bytes0_speed100.csv"
```

### Run with specific configuration
```bash
python3 experiment.py \
    --server-icwnd 24 \
    --client-icwnd 10 \
    --rtt 150 \
    --bytes 50 \
    --speed 1000 \
    --output "data/icwnd_server24_client10_RTT150_bytes50_speed1000.csv"
```

### Modify the loops in the wrapper script
To change which values are tested, edit the arrays in `run_icwnd_experiment.sh`:
```bash
CLIENT_ICWND_ARRAY=(10 24)      # Change client ICW values as needed
RTT_ARRAY=(35 50 75 100 150)    # Change RTT values as needed
BYTES_ARRAY=(0 50 150)          # Change transfer sizes as needed
SPEED_ARRAY=(1 100 1000)        # Change speed values as needed
```

## Notes

- The script uses a single parallel client (TIMERS=1) to avoid server hanging issues
- Each configuration runs 10 measurements per timer (MEASUREMENTS_PER_TIMER=10)
- Speed values of 1, 100, and 1000 Mbps represent slow, fast, and superfast connections respectively
- **1Mbps speed is only tested with 0KB (handshake-only) transfers** to avoid timeouts
- 50KB and 150KB transfers use only 100Mbps and 1000Mbps speeds
