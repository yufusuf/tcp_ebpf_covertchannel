#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <sys/cdefs.h>

#include "parsing_helpers.h"
#include "crc.h"
#include "maps.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10
#define MAX_OPT_LEN 12

#define get_key_bit(x) (((x) >> 8) & 1)
#define get_key_index(x) ((x) & 0xFF)

#define MESSAGE_SIZE 32
#define OCCUPATION 3

__u32 cur_idx = 0;

static __always_inline int get_tsval(struct tcphdr *tcph, __u32 **tsval, void *data_end) {
    // generally tsval is at the 23rd byte
    // [nop]=1 [nop]=1 [kind]=1 [len]=1 [tsval]=4 [tsecr]=4
    if (((void *)tcph) + sizeof(struct tcphdr) + MAX_OPT_LEN > data_end) {
        return -1;
    }
    __u8 *options = (void *)tcph + sizeof(struct tcphdr);
    __u8 kind = options[2];
    __u8 len = options[3];
    if (kind != TCPOPT_TIMESTAMP || len != TCPOLEN_TIMESTAMP) {
        return -1;
    }
    *tsval = (__u32 *)(options + 4);
    return 0;
}

static __always_inline void reset_tx_cnt(void) {
    for (__u32 i = 0; i < 256; i++) {
        __u32 k = i;
        __u64 *v = bpf_map_lookup_elem(&tx_cnt, &k);
        if (v)
            bpf_map_update_elem(&tx_cnt, &k, &((__u64){0}), BPF_ANY);
    }
}

static __always_inline void incr_tx_count(__u32 bit_index) {
    __u64 *tscount = bpf_map_lookup_elem(&tx_cnt, &bit_index);
    if (tscount) {
        __u64 old_val = __sync_fetch_and_add(tscount, 1);
        if (old_val != OCCUPATION)
            return;

        __u64 *done = bpf_map_lookup_elem(&done_cnt, &(__u32){0});
        if (!done) {
            bpf_printk("Failed to lookup done count map\n");
            return;
        }
        __u64 prev = __sync_fetch_and_add(done, 1);
        if (prev + 1 == MESSAGE_SIZE * 8) {
            __sync_fetch_and_add(&cur_idx, 1);
            *done = 0;
            reset_tx_cnt();
            bpf_printk("All bits transmitted successfully, next index:%u \n", cur_idx);

            __u64 *tot_len = bpf_map_lookup_elem(&state_map, &(__u32){1});
            if (tot_len && cur_idx < *tot_len)
                return;

            cur_idx = 0;
            bpf_printk("Transmission completed, restarting.\n");
        }
    }
    else {
        __u8 initial_value = 1;
        bpf_map_update_elem(&tx_cnt, &bit_index, &initial_value, BPF_ANY);
    }
}
static __always_inline void update_stats(__u64 start) {
    struct stats *s = bpf_map_lookup_elem(&stats_map, &(__u32){0});

    if (s) {
        s->total_time += bpf_ktime_get_ns() - start;
        s->packet_count += 1;
    }
}
SEC("classifier")
int tcp_processor(struct __sk_buff *skb) {
    __u64 time = bpf_ktime_get_ns();
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct hdr_cursor nh = {.pos = data};
    int eth_type, ip_type, ret = TC_ACT_OK;
    // update_stats(time);
    // return ret;

    struct iphdr *iphdr;
    struct tcphdr *tcph;
    struct ethhdr *eth;

    if (data + sizeof(*eth) > data_end)
        goto out;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0)
        goto out;

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
    }
    else {
        goto out;
    }

    if (ip_type == IPPROTO_TCP) {
        if (parse_tcphdr(&nh, data_end, &tcph) < 0)
            goto out;

        __u32 *tsval;
        if (get_tsval(tcph, &tsval, data_end) == 0) {
            __u8 tcpheader[20] = {0};
            memcpy(tcpheader, tcph, 20);

            // sets checksum to 0 before crc32
            // making header independent of the checksum
            memset(tcpheader + offsetof(struct tcphdr, check), 0, sizeof(tcph->check));

            __u32 crc = tcp_header_crc32(tcpheader);
            __u8 bit_index = get_key_index(crc);
            __u8 key_bit = get_key_bit(crc);
            __u32 key = cur_idx;
            __u8 *message = bpf_map_lookup_elem(&message_map, &key);
            if (!message) {
                bpf_printk("Failed to lookup message map\n");
                goto out;
            }
            __u8 plain_text_bit = message[bit_index / 8] >> (7 - (bit_index % 8)) & 0x01;
            __u8 hashed_bit = key_bit ^ plain_text_bit;

            if ((bpf_ntohl(*tsval) & 1) != hashed_bit) {
                *tsval = bpf_htonl(bpf_ntohl(*tsval) + 1);

                // delay packet for 1ms
                const __u64 delay = 1e6;
                __u64 now = bpf_ktime_get_ns();
                bpf_skb_set_tstamp(skb, now + delay, 1);
            }
            // update the transmission count map
            incr_tx_count(bit_index);
            update_stats(time);
        }
        else {
            bpf_printk("TCP timestamp option not found or invalid\n");
            goto out;
        }
    }

out:
    return ret;
}
char _license[] SEC("license") = "GPL";
