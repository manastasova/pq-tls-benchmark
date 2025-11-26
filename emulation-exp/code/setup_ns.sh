#!/bin/bash
set -x

##########################
# Setup network namespaces
##########################

SERVER_VETH_LL_ADDR=00:00:00:00:00:02
SERVER_NS=srv_ns
SERVER_VETH=srv_ve

CLIENT_NS=cli_ns
CLIENT_VETH_LL_ADDR=00:00:00:00:00:01
CLIENT_VETH=cli_ve

# Cleanup existing namespaces if they exist
echo "Cleaning up existing network namespaces..."
sudo ip netns del ${SERVER_NS} 2>/dev/null || true
sudo ip netns del ${CLIENT_NS} 2>/dev/null || true

# Create new namespaces
sudo ip netns add ${SERVER_NS}
sudo ip netns add ${CLIENT_NS}
sudo ip link add \
   name ${SERVER_VETH} \
   address ${SERVER_VETH_LL_ADDR} \
   netns ${SERVER_NS} type veth \
   peer name ${CLIENT_VETH} \
   address ${CLIENT_VETH_LL_ADDR} \
   netns ${CLIENT_NS}

sudo ip netns exec ${SERVER_NS} \
   ip link set dev ${SERVER_VETH} up
sudo ip netns exec ${SERVER_NS} \
   ip link set dev lo up
sudo ip netns exec ${SERVER_NS} \
   ip addr add 10.0.0.1/24 dev ${SERVER_VETH}

sudo ip netns exec ${CLIENT_NS} \
   ip addr add 10.0.0.2/24 dev ${CLIENT_VETH}
sudo ip netns exec ${CLIENT_NS} \
   ip link set dev lo up
sudo ip netns exec ${CLIENT_NS} \
   ip link set dev ${CLIENT_VETH} up
sudo ip netns exec ${CLIENT_NS} \
   ip link set dev lo up

sudo ip netns exec ${SERVER_NS} \
   ip neigh add 10.0.0.2 \
      lladdr ${CLIENT_VETH_LL_ADDR} \
      dev ${SERVER_VETH}
sudo ip netns exec ${CLIENT_NS} \
   ip neigh add 10.0.0.1 \
      lladdr ${SERVER_VETH_LL_ADDR} \
      dev ${CLIENT_VETH}

# Turn off optimizations
# that dent realism.
sudo ip netns exec ${CLIENT_NS} \
   ethtool -K ${CLIENT_VETH} gso off gro off tso off

sudo ip netns exec ${SERVER_NS} \
   ethtool -K ${SERVER_VETH} gso off gro off tso off

sudo ip netns exec ${CLIENT_NS} \
   tc qdisc add \
      dev ${CLIENT_VETH} \
      root netem limit 10000
sudo ip netns exec ${SERVER_NS} \
   tc qdisc add \
      dev ${SERVER_VETH} \
      root netem limit 10000
