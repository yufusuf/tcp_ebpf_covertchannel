#!/usr/bin/env bash
# Show run_cnt, run_time_ns and avg ns per run for the first program
# whose name contains "tcp_processor".

set -euo pipefail
TARGET="tcp_processor"

# 1. Find the program ID safely.
PROG_ID=$(bpftool -j prog show \
          | jq -r --arg t "$TARGET" '
              .[]
              | select(.name? and (.name|type=="string") and (.name|test($t)))
              | .id' | head -n1)

if [[ -z "$PROG_ID" ]]; then
    echo "No BPF program matching \"$TARGET\" found."
    exit 1
fi

# 2. Read its stats (run_cnt & run_time_ns). Stats must be enabled via
#    sysctl kernel.bpf_stats_enabled=1 or 2.
STATS=$(bpftool -j prog show id "$PROG_ID")

RUN_CNT=$(  echo "$STATS" | jq '.run_cnt      // 0')
RUN_TIME=$( echo "$STATS" | jq '.run_time_ns // 0')

if (( RUN_CNT == 0 )); then
    echo "id=$PROG_ID  run_cnt=0  run_time_ns=$RUN_TIME  avg_ns=N/A"
    exit 0
fi

AVG=$(awk -v t="$RUN_TIME" -v c="$RUN_CNT" 'BEGIN {printf "%.2f", t/c}')

echo "id=$PROG_ID  run_cnt=$RUN_CNT  run_time_ns=$RUN_TIME  avg_ns_per_run=$AVG"

