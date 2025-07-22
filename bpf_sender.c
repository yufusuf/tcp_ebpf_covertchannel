#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

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
#define OCCUPATION 2

const volatile char message[MESSAGE_SIZE] = "covert message";

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
static __always_inline void incr_tx_count(__u32 bit_index) {
    __u32 *tscount = bpf_map_lookup_elem(&tx_cnt, &bit_index);
    if (tscount) {
        __u32 new_value = ++(*tscount);
        if( new_value != OCCUPATION)
            return;
        
        __u32 key = 0;
        __u64 *done = bpf_map_lookup_elem(&done_cnt, &key);
        if (!done) {
            bpf_printk("Failed to lookup done count map\n");
            return;
        }
        __u64 prev = __sync_fetch_and_add(done, 1);
        if( prev + 1 == MESSAGE_SIZE * 8) {
            bpf_printk("All bits transmitted successfully, exiting...\n");
        }

    }
    else {
        __u8 initial_value = 1;
        bpf_map_update_elem(&tx_cnt, &bit_index, &initial_value, BPF_ANY);
    }
}
SEC("classifier")
int tcp_processor(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct hdr_cursor nh = {.pos = data};
    int eth_type, ip_type, ret = TC_ACT_OK;
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
            __u8 plain_text_bit = message[bit_index / 8] >> (7 - (bit_index % 8)) & 0x01;
            __u8 hashed_bit = key_bit ^ plain_text_bit;

            // // print packet source and destination ip's
            // bpf_printk("IP packet: src=%u, dst=%u\n", bpf_ntohl(iphdr->saddr), bpf_ntohl(iphdr->daddr));
            // // print sequence number only
            // bpf_printk("TCP packet: seq=%u\n", bpf_ntohl(tcph->seq));
            // bpf_printk("TCP header CRC32: %u\n", crc);
            // bpf_printk("TCP timestamp value: %u\n", bpf_ntohl(*tsval));
            // bpf_printk("Bit index: %u, Key bit: %u, Plain text bit: %u, Hashed bit: %u\n", bit_index, key_bit,
            //            plain_text_bit, hashed_bit);
            if ((bpf_ntohl(*tsval) & 1) != hashed_bit) {
                *tsval = bpf_htonl(bpf_ntohl(*tsval) + 1);
            }

            // update the transmission count map
            incr_tx_count(bit_index);
        }
        else {
            bpf_printk("TCP timestamp option not found or invalid\n");
            goto out;
        }
        // print packet info
        // bpf_printk("TCP packet: src=%u, dst=%u, seq=%u, ack_seq=%u\n", bpf_ntohs(tcph->source),
        // bpf_ntohs(tcph->dest),
        //            bpf_ntohl(tcph->seq), bpf_ntohl(tcph->ack_seq));
        // print 20 bytes
        // bpf_printk("TCP header: ");
        // for (int i = 0; i < 20; i++) {
        //     bpf_printk("%02x ", tcpheader[i]);
        // }
        // print second index of crc_tab

        // tcphdr->check += bpf_htons(-1);
        // if (!tcphdr->check)
        //     tcphdr->check += bpf_htons(-1);
    }

out:
    return ret;
}
char _license[] SEC("license") = "GPL";
