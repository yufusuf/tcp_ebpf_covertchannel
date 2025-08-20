#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

char message[32] = {0};

uint32_t crc32(const unsigned char *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            int mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

uint32_t *get_tsval(struct tcphdr *tcph) {
    // generally tsval is at the 23rd byte
    // [nop]=1 [nop]=1 [kind]=1 [len]=1 [tsval]=4 [tsecr]=4
    uint8_t *options = (void *)tcph + sizeof(struct tcphdr);
    uint8_t kind = options[2];
    uint8_t len = options[3];
    if (kind != TCPOPT_TIMESTAMP || len != TCPOLEN_TIMESTAMP) {
        return NULL;
    }
    return (uint32_t *)(options + 4);
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(bytes + sizeof(struct ethhdr) + ip->ihl * 4);
    if (tcph->syn || tcph->fin || tcph->rst)
        return;
    unsigned char bit_index;
    unsigned char key_bit;
    unsigned char plain_text_bit;
    unsigned char cipher_text_bit;
    uint32_t tsval;
    uint32_t crc;

    tcph->check = 0;
    uint32_t digest = crc32((unsigned char *)tcph, sizeof(struct tcphdr));
    bit_index = digest & 0xFF;
    key_bit = (digest >> 8) & 0x01;
    tsval = ntohl(*get_tsval(tcph));
    if (!tsval) {
        fprintf(stderr, "Failed to get timestamp value.\n");
        return;
    }
    cipher_text_bit = tsval & 0x01;
    plain_text_bit = key_bit ^ cipher_text_bit;
    size_t byte_idx = bit_index / 8;
    uint8_t bit_pos = 7 - (bit_index % 8);
    uint8_t mask = (1u << bit_pos);
    // printf("TCP packet: seq=%u\n", ntohl(tcph->seq));
    // printf("TCP header CRC32: %u\n", digest);
    // printf("TCP timestamp value: %u\n", tsval);
    // printf("Bit index: %u, Key bit: %u, Plain text bit: %u, Hashed bit: %u\n", bit_index, key_bit, plain_text_bit,
    //        cipher_text_bit);
    pthread_mutex_lock(&mutex);
    message[byte_idx] = (message[byte_idx] & ~mask) | ((plain_text_bit << bit_pos) & mask);
    pthread_mutex_unlock(&mutex);
    crc = crc32((unsigned char *)message, 28);
    if (crc != 0 && (memcmp((uint32_t *)(message + 28), &crc, sizeof(uint32_t)) == 0)) {
        printf("%.28s", message);
        fflush(stdout);
        memset(message, 0, sizeof(message));
    }
    // printf("Current message: %.28s\n", message);
}

int main(int argc, char *argv[]) {

    char *dev = "ifb0";
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    pcap_dumper_t *dumper;
    const char *outfile = "capture.pcap";

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    dumper = pcap_dump_open(handle, outfile);
    if (!dumper) {
        fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp and ip dst host 10.0.0.2";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter.\n");
        return 1;
    }

    printf("Listening on interface %s for TCP packets...\n", dev);
    pcap_loop(handle, -1, packet_handler, (u_char *)dumper);

    pcap_close(handle);
    return 0;
}
