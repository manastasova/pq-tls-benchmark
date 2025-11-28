#!/bin/bash
# Script to run TLS benchmark with specified congestion window parameters
# 
# Configuration:
# - Server initial congestion window (X): 24 (fixed)
# - Client initial congestion window (Y): Loop through 10 and 24 MSS
# - RTT (Z): Loop through 35ms, 50ms, 75ms, 100ms, and 150ms
# - Transfer bytes (V): Loop through 0KB, 50KB, and 150KB
# - Speed (N): Loop through 1Mbps, 100Mbps, and 1000Mbps

# Don't exit on error - we want to continue even if one experiment fails
set +e

# Change to the kex directory
cd "$(dirname "$0")"

# Fixed parameters
SERVER_ICWND=24

# Client initial congestion window values to test (in MSS)
CLIENT_ICWND_ARRAY=(10 24)

# RTT values to test (in ms)
RTT_ARRAY=(35 50 150)

# Data transfer sizes to test (in KB)
BYTES_ARRAY=(0 50 150 400)

# Network speed values to test (in Mbps)
SPEED_ARRAY=(1 100 1000)

# Calculate actual number of experiments
# 2 client ICW values × 3 RTT values × 4 transfer sizes × 3 speeds = 72 experiments
TOTAL_EXPERIMENTS=72

echo "=================================================="
echo "Running TLS Benchmark with ICW Configuration"
echo "=================================================="
echo "Server initcwnd: ${SERVER_ICWND} (fixed)"
echo "Client initcwnd values: ${CLIENT_ICWND_ARRAY[@]} MSS"
echo "RTT values: ${RTT_ARRAY[@]}ms"
echo "Transfer sizes: ${BYTES_ARRAY[@]}KB"
echo "Speed values: ${SPEED_ARRAY[@]}Mbps"
echo "Total experiments: ${TOTAL_EXPERIMENTS}"
echo "=================================================="
echo ""

# Counter for tracking progress
CURRENT_EXPERIMENT=0

# Loop through each client ICW value
for CLIENT_ICWND in "${CLIENT_ICWND_ARRAY[@]}"; do
    echo ""
    echo "=================================================="
    echo "Testing with Client ICW=${CLIENT_ICWND} MSS"
    echo "=================================================="
    
    # Loop through each RTT value
    for RTT in "${RTT_ARRAY[@]}"; do
        echo ""
        echo "  Testing with RTT=${RTT}ms"
        
        # Loop through each transfer size
        for BYTES in "${BYTES_ARRAY[@]}"; do
            # Loop through each speed value
            for SPEED in "${SPEED_ARRAY[@]}"; do
                CURRENT_EXPERIMENT=$((CURRENT_EXPERIMENT + 1))
                
                echo ""
                echo "=================================================="
                echo "Experiment ${CURRENT_EXPERIMENT}/${TOTAL_EXPERIMENTS}"
                echo "Server ICW: ${SERVER_ICWND}, Client ICW: ${CLIENT_ICWND}"
                echo "RTT: ${RTT}ms, Data transfer: ${BYTES}KB, Speed: ${SPEED}Mbps"
                echo "=================================================="
                
                # Construct output filename with desired format
                OUTPUT_FILE="data/test_pq_icwnd_server${SERVER_ICWND}_client${CLIENT_ICWND}_RTT${RTT}_bytes${BYTES}_speed${SPEED}.csv"
                
                # Run the experiment with the specified parameters
                if python3 experiment.py \
                    --server-icwnd ${SERVER_ICWND} \
                    --client-icwnd ${CLIENT_ICWND} \
                    --rtt ${RTT} \
                    --bytes ${BYTES} \
                    --speed ${SPEED} \
                    --output "${OUTPUT_FILE}"; then
                    echo ""
                    echo "✓ Completed experiment ${CURRENT_EXPERIMENT}/${TOTAL_EXPERIMENTS}"
                    echo "Results saved to: ${OUTPUT_FILE}"
                    echo ""
                else
                    echo ""
                    echo "✗ FAILED experiment ${CURRENT_EXPERIMENT}/${TOTAL_EXPERIMENTS}"
                    echo "Configuration: Server ICW=${SERVER_ICWND}, Client ICW=${CLIENT_ICWND}, RTT=${RTT}ms, Bytes=${BYTES}KB, Speed=${SPEED}Mbps"
                    echo "Continuing with next experiment..."
                    echo ""
                fi
            done
        done
    done
done

echo ""
echo "=================================================="
echo "All ${TOTAL_EXPERIMENTS} experiments completed!"
echo "=================================================="
echo "Generated files:"
for CLIENT_ICWND in "${CLIENT_ICWND_ARRAY[@]}"; do
    echo ""
    echo "Client ICW=${CLIENT_ICWND}:"
    for RTT in "${RTT_ARRAY[@]}"; do
        for BYTES in "${BYTES_ARRAY[@]}"; do
            for SPEED in "${SPEED_ARRAY[@]}"; do
                echo "  - data/icwnd_server${SERVER_ICWND}_client${CLIENT_ICWND}_RTT${RTT}_bytes${BYTES}_speed${SPEED}.csv"
            done
        done
    done
done
echo "=================================================="
