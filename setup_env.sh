#!/usr/bin/env bash
set -euo pipefail

NS1=sec
NS2=insec
IF1=veth_sec
IF2=veth_insec

IP1=10.0.0.1/24
IP2=10.0.0.2/24

usage() {
  echo "Usage: $0 {up|down|status|ping}"
  exit 1
}

have_ns() { ip netns list | awk '{print $1}' | grep -qx "$1"; }


disable_offloads() {
  local ns="$1"
  # Best-effort: ethtool may not be installed
  ip netns exec "$ns" sh -lc 'command -v ethtool >/dev/null 2>&1 && ethtool -K eth0 tso off gso off gro off lro off rx off tx off' || true
}

up() {
  # Create namespaces if missing
  have_ns "$NS1" || ip netns add "$NS1"
  have_ns "$NS2" || ip netns add "$NS2"

  # If a stale veth exists in the root ns, delete it
  ip link show "$IF1" >/dev/null 2>&1 && ip link del "$IF1" || true
  ip link show "$IF2" >/dev/null 2>&1 && ip link del "$IF2" || true

  # Create veth pair in root and move each end to its ns
  ip link add "$IF1" type veth peer name "$IF2"
  ip link set "$IF1" netns "$NS1"
  ip link set "$IF2" netns "$NS2"

  # Inside namespaces: rename to eth0, bring up
  ip -n "$NS1" link set "$IF1" name eth0
  ip -n "$NS2" link set "$IF2" name eth0

  ip -n "$NS1" link set lo up
  ip -n "$NS2" link set lo up

  ip -n "$NS1" addr flush dev eth0 || true
  ip -n "$NS2" addr flush dev eth0 || true

  ip -n "$NS1" addr add "$IP1" dev eth0
  ip -n "$NS2" addr add "$IP2" dev eth0

  ip -n "$NS1" link set eth0 up
  ip -n "$NS2" link set eth0 up
  # Optional: disable offloads for cleaner captures / BPF work
  disable_offloads "$NS1"
  disable_offloads "$NS2"

  echo "Namespaces ${NS1} (${IP1}) and ${NS2} (${IP2}) are up."
}

down() {
  # Cleanly delete namespaces (removes veths inside)
  have_ns "$NS1" && ip netns del "$NS1" || true
  have_ns "$NS2" && ip netns del "$NS2" || true

  # Remove any leftover veths in root ns
  ip link show "$IF1" >/dev/null 2>&1 && ip link del "$IF1" || true
  ip link show "$IF2" >/dev/null 2>&1 && ip link del "$IF2" || true

  echo "Namespaces removed."
}

status() {
  ip netns list
  echo "--- ${NS1} ---"
  have_ns "$NS1" && ip -n "$NS1" addr show || echo "missing"
  echo "--- ${NS2} ---"
  have_ns "$NS2" && ip -n "$NS2" addr show || echo "missing"
}

ping_test() {
  ip netns exec "$NS1" ping -c1 -W1 10.0.0.2 && echo "sec → insec OK" || echo "sec → insec FAIL"
  ip netns exec "$NS2" ping -c1 -W1 10.0.0.1 && echo "insec → sec OK" || echo "insec → sec FAIL"
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  ping) ping_test ;;
  *) usage ;;
esac

