#ifndef __MAPS_H
#define __MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MESSAGE_SIZE 32

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MESSAGE_SIZE * 8);
} tx_cnt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries,1);
} done_cnt SEC(".maps");
#endif // !__MAPS_H
