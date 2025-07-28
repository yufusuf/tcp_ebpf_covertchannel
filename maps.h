#ifndef __MAPS_H
#define __MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MESSAGE_SIZE 32

//every bits sent count is tracked with this map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64); 
    __uint(max_entries, MESSAGE_SIZE * 8);
} tx_cnt SEC(".maps");

// counter for how many bits have surpassed OCCUPATION
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} done_cnt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, char[MESSAGE_SIZE]);
    __uint(max_entries, 1024); // max message size 32kb
} message_map SEC(".maps");

// key 0: start or stop transmission
// key 1: total length of blocks
// key 2: current block index
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 3);
} state_map SEC(".maps");

#endif // !__MAPS_H
