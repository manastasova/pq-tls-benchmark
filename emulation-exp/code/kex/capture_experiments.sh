#!/bin/bash
# Automated script to capture network traffic while running TLS experiments
# This script handles:
#   1. Starting the TLS server (setup.sh)
#   2. Capturing packets on both client and server namespaces
#   3. Running client experiments (run_icwnd_experiment.sh)
#   4. Proper cleanup of all processes

set -e

# Change to script directory
cd "$(dirname "$0")"

# Configuration
PCAP_DIR="pcaps"
CLIENT_PCAP="${PCAP_DIR}/client_capture.pcap"
SERVER_PCAP="${PCAP_DIR}/server_capture.pcap"
SERVER_LOG="server.log"
CLIENT_NS="cli_ns"
SERVER_NS="srv_ns"
CLIENT_IFACE="cli_ve"
SERVER_IFACE="srv_ve"

# PIDs for cleanup
SERVER_PID=""
CLIENT_TCPDUMP_PID=""
SERVER_TCPDUMP_PID=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo ""
    echo -e "${YELLOW}=================================================="
    echo "Cleaning up..."
    echo -e "==================================================${NC}"
    
    # Stop client experiments (if running)
    echo "Stopping any running experiments..."
    
    # Stop tcpdump processes
    if [ -n "$CLIENT_TCPDUMP_PID" ]; then
        echo "Stopping client tcpdump (PID: $CLIENT_TCPDUMP_PID)..."
        sudo kill -INT $CLIENT_TCPDUMP_PID 2>/dev/null || true
        sleep 0.5
    fi
    
    if [ -n "$SERVER_TCPDUMP_PID" ]; then
        echo "Stopping server tcpdump (PID: $SERVER_TCPDUMP_PID)..."
        sudo kill -INT $SERVER_TCPDUMP_PID 2>/dev/null || true
        sleep 0.5
    fi
    
    # Stop server
    if [ -n "$SERVER_PID" ]; then
        echo "Stopping server (PID: $SERVER_PID)..."
        sudo kill -INT $SERVER_PID 2>/dev/null || true
        sleep 0.5
    fi
    
    echo ""
    echo -e "${GREEN}=================================================="
    echo "Cleanup complete!"
    echo ""
    echo "Captured files:"
    if [ -f "$CLIENT_PCAP" ]; then
        echo "  Client PCAP: $CLIENT_PCAP ($(du -h "$CLIENT_PCAP" | cut -f1))"
    fi
    if [ -f "$SERVER_PCAP" ]; then
        echo "  Server PCAP: $SERVER_PCAP ($(du -h "$SERVER_PCAP" | cut -f1))"
    fi
    if [ -f "$SERVER_LOG" ]; then
        echo "  Server log: $SERVER_LOG"
    fi
    echo -e "==================================================${NC}"
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

echo -e "${GREEN}=================================================="
echo "TLS Experiment Packet Capture Script"
echo -e "==================================================${NC}"
echo "This script will:"
echo "  1. Start TLS server (setup.sh)"
echo "  2. Start packet capture on both namespaces"
echo "  3. Run client experiments (run_icwnd_experiment.sh)"
echo "  4. Save captures to ${PCAP_DIR}/"
echo ""

# Create pcaps directory
echo "Creating ${PCAP_DIR} directory..."
mkdir -p "${PCAP_DIR}"

# Check and compile s_timer.o if needed
echo ""
echo -e "${YELLOW}=================================================="
echo "Checking prerequisites..."
echo -e "==================================================${NC}"

if [ ! -f "s_timer.o" ]; then
    echo "s_timer.o not found - compiling..."
    if ! make s_timer.o; then
        echo -e "${RED}✗ Failed to compile s_timer.o${NC}"
        echo "Please check that all dependencies are installed"
        exit 1
    fi
    echo -e "${GREEN}✓ s_timer.o compiled successfully${NC}"
else
    echo -e "${GREEN}✓ s_timer.o exists${NC}"
fi

if [ ! -f "s2nd" ]; then
    echo "s2nd not found - compiling..."
    if ! make s2nd; then
        echo -e "${RED}✗ Failed to compile s2nd${NC}"
        echo "Please check that all dependencies are installed"
        exit 1
    fi
    echo -e "${GREEN}✓ s2nd compiled successfully${NC}"
else
    echo -e "${GREEN}✓ s2nd exists${NC}"
fi

# Step 1: Start the server
echo ""
echo -e "${YELLOW}=================================================="
echo "Step 1: Starting TLS server..."
echo -e "==================================================${NC}"
./setup.sh > "${SERVER_LOG}" 2>&1 &
SERVER_PID=$!
echo "Server started with PID: ${SERVER_PID}"
echo "Server logs: ${SERVER_LOG}"

# Wait for network namespaces to be created
echo "Waiting for network namespaces to be ready..."
MAX_WAIT=10
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if sudo ip netns list | grep -q "$CLIENT_NS" && sudo ip netns list | grep -q "$SERVER_NS"; then
        echo -e "${GREEN}✓ Network namespaces ready${NC}"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    echo "  Waiting... (${WAITED}/${MAX_WAIT}s)"
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo -e "${RED}✗ Failed to detect network namespaces after ${MAX_WAIT}s${NC}"
    echo "Please check ${SERVER_LOG} for errors"
    exit 1
fi

# Give server a bit more time to fully initialize
sleep 2

# Step 2: Start tcpdump on client namespace
echo ""
echo -e "${YELLOW}=================================================="
echo "Step 2: Starting packet capture..."
echo -e "==================================================${NC}"
echo "Starting client-side capture on ${CLIENT_IFACE}..."
sudo ip netns exec ${CLIENT_NS} tcpdump -U -i ${CLIENT_IFACE} -w "${CLIENT_PCAP}" > /dev/null 2>&1 &
CLIENT_TCPDUMP_PID=$!
echo -e "${GREEN}✓ Client tcpdump started (PID: ${CLIENT_TCPDUMP_PID})${NC}"

# Step 3: Start tcpdump on server namespace
echo "Starting server-side capture on ${SERVER_IFACE}..."
sudo ip netns exec ${SERVER_NS} tcpdump -U -i ${SERVER_IFACE} -w "${SERVER_PCAP}" > /dev/null 2>&1 &
SERVER_TCPDUMP_PID=$!
echo -e "${GREEN}✓ Server tcpdump started (PID: ${SERVER_TCPDUMP_PID})${NC}"

# Give tcpdump a moment to initialize
sleep 1

# Verify tcpdump processes are running
if ! ps -p $CLIENT_TCPDUMP_PID > /dev/null 2>&1; then
    echo -e "${RED}✗ Client tcpdump failed to start${NC}"
    exit 1
fi

if ! ps -p $SERVER_TCPDUMP_PID > /dev/null 2>&1; then
    echo -e "${RED}✗ Server tcpdump failed to start${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Packet capture active on both interfaces${NC}"

# Step 4: Run client experiments
echo ""
echo -e "${YELLOW}=================================================="
echo "Step 3: Running client experiments..."
echo -e "==================================================${NC}"
echo ""
./run_icwnd_experiment.sh

# Experiments complete
echo ""
echo -e "${GREEN}=================================================="
echo "All experiments completed!"
echo -e "==================================================${NC}"

# Give tcpdump a moment to flush buffers
sleep 2
