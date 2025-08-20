from scapy.all import sniff, TCP
import subprocess
import os
import json
from time import sleep
from scapy.config import conf
conf.sniff_promisc = False


CAPTURE_COUNT = 20000
REPETITION = 30
RESULT_DIR = "./results/"
LOSS_RANGE = range(0, 21, 5)
DELAY_RANGE = range(1, 70, 10)
# CHANNEL_CAP = [(1 << i) * 10 for i in range(12)]  # goes through 10kbits to 21kbits
CHANNEL_CAP = range(2, 21, 2)
# CHANNEL_CAP = range(1, 4)
REORDER = range(0, 11, 5)
RUN_TYPE = ["covert", "normal"]

TC_NETEM_COMMAND = "tc qdisc replace dev eth0 root handle 1: netem loss {}% delay {}ms {}ms rate {}mbit reorder {}%"
TC_FQ_COMMAND = "tc qdisc add dev eth0 parent 1:1 handle 2: fq"
TC_DEL_COMMAND = "tc qdisc del dev eth0 root"
# listen to eth0 and capture the packets

CLONE_NEWNET = 0x40000000
ROOT_NS_FD = os.open("/proc/self/ns/net", os.O_RDONLY)


def enter_ns(nsname: str):
    fd = os.open(f"/var/run/netns/{nsname}", os.O_RDONLY)
    os.setns(fd, CLONE_NEWNET)
    os.close(fd)


def leave_ns():
    os.setns(ROOT_NS_FD, CLONE_NEWNET)


def sh(cmd: str):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def setup_sec_fq():
    enter_ns("sec")
    try:
        sh("tc qdisc replace dev eth0 root fq")
        sh("tc qdisc replace dev eth0 clsact")  # to host your TC egress BPF
    finally:
        leave_ns()


def setup_insec_ingress_netem(loss_pct, delay_ms, jitter_ms, rate_mbit, reorder_pct):
    enter_ns("insec")
    try:
        # sh("modprobe ifb")
        # sh("ip link add ifb0 type ifb || true")
        # sh("ip link set ifb0 up")
        # sh("tc qdisc del dev eth0 ingress 2>/dev/null || true")
        # # ingress is special: no parent/handle
        # add_ing = sh("tc qdisc add dev eth0 ingress")
        # if add_ing.returncode != 0 and "File exists" not in add_ing.stderr:
        #     print("Failed to add ingress:", add_ing.stderr)
        #
        # sh("tc filter replace dev eth0 ingress prio 1 matchall "
        #    "action mirred egress redirect dev ifb0")

        netem = (f"tc qdisc replace dev ifb0 root netem "
                 f"loss {loss_pct}% delay {delay_ms}ms {jitter_ms}ms "
                 f"rate {rate_mbit}mbit reorder {reorder_pct}%")
        r = sh(netem)
        if r.returncode != 0:
            print("Failed to set netem on insec/ifb0:", r.stderr)
            exit(1)
    finally:
        leave_ns()


def capture_in_insec(interface="eth0", n=200):
    enter_ns("insec")
    try:
        return capture_packets(interface=interface, n=n)
    finally:
        leave_ns()


def run_in_sec(cmd_list):
    enter_ns("sec")
    try:
        return subprocess.run(cmd_list, capture_output=True, text=True)
    finally:
        leave_ns()


def capture_packets(interface="eth0", n=200):
    # capture exactly n TCP packets and return them
    def collect_ts(packets):
        ts = []
        for packet in packets:
            if TCP in packet:
                opts = packet[TCP].options
                for opt in opts:
                    if opt[0] == "Timestamp":
                        tsval, _ = opt[1]
                        ts.append(tsval)
        return ts
    pkts = sniff(iface=interface, filter="tcp and ip dst host 10.0.0.2", count=n, store=True)
    duration = pkts[-1].time - pkts[0].time
    return duration, collect_ts(pkts)


def set_netem(loss, delay, rate, reorder):
    jitter = round(delay * 0.1, 2)
    setup_insec_ingress_netem(loss, delay, jitter, rate, reorder)


setup_sec_fq()
res = {}
for l in LOSS_RANGE:
    for d in DELAY_RANGE:
        for r in CHANNEL_CAP:
            for o in REORDER:
                set_netem(l, d, r, o)
                sleep(0.1)
                for t in RUN_TYPE:
                    for i in range(REPETITION):
                        run_name = f"loss_{l}_delay_{d}_rate_{r}_reorder_{o}_{t}_#{i}"
                        if t == "covert":
                            print("loading ebpf sender")
                            subprocess.run(
                                "head -c 10000 /dev/urandom | tr -cd '[:print:]' > input.txt",
                                shell=True,
                                check=True
                            )
                            run_in_sec(["./bpf_map_manager"])

                        sleep(0.1)
                        print(f"Running with loss={l}%, delay={d}ms, rate={r}mbit, reorder={o}%, type={t}")

                        print("capturing packets...")
                        dur, stamps = capture_in_insec(interface="ifb0", n=CAPTURE_COUNT)
                        print("capture took {} seconds".format(dur))

                        unload_res = None
                        if t == "covert":
                            print("unloading ebpf sender")
                            unload_res = run_in_sec(["./bpf_map_manager", "-d"])
                            print(unload_res.stdout)

                        # print("is monotonic:", all(stamps[i] <= stamps[i + 1] for i in range(len(stamps) - 1)))
                        # print(stamps[:1000])

                        dif = stamps[-1] - stamps[0]
                        run_res = {
                            "distinct_ratio": len(set(stamps)) / dif if dif > 0 else -1,
                            "dur": dur,
                            "packet_count": len(stamps),
                            "ebpf_stats": unload_res.stdout if unload_res else None,
                        }
                        res[run_name] = run_res
                        print()

subprocess.run(TC_DEL_COMMAND.split())
with open("experiment_data.json", "w") as f:
    json.dump(res, f, indent=4)

# print(stamps)
