#include <asm-generic/errno-base.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include "args.h"

#define MESSAGE_SIZE 32
#define CRC_SIZE 4
#define CRC_OFFSET 28
#define IF_INTERFACE "eth0"
struct stats
{
    __u64 packet_count;
    __u64 total_time;
};
const char *stat_map_pin_path = "/sys/fs/bpf/stats_map";
const char *obj_path = "bpf_sender.o";

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
unsigned char *prepare_payload(const char *str) {
    size_t msg_len = 28;
    unsigned char *buf = malloc(32);
    memcpy(buf, str, msg_len);

    uint32_t crc = crc32(buf, msg_len);
    // print message and crc
    // printf("Message: %.*s\n", (int)msg_len, buf);
    // printf("CRC32: %08x\n", crc);
    //
    // Append CRC32 little-endian
    buf[msg_len + 0] = (uint8_t)(crc & 0xFF);
    buf[msg_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    buf[msg_len + 2] = (uint8_t)((crc >> 16) & 0xFF);
    buf[msg_len + 3] = (uint8_t)((crc >> 24) & 0xFF);

    return buf;
}
int fill_message_map(int map_fd, const char *file_path) {
    FILE *fp = fopen(file_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Error opening file\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    int chunk_size = MESSAGE_SIZE;
    int msg_size = MESSAGE_SIZE - CRC_SIZE;
    int total_blocks = (file_size + msg_size - 1) / msg_size;

    for (int i = 0; i < total_blocks; i++) {
        char buf[chunk_size];
        size_t read_bytes = fread(&buf, 1, msg_size, fp);
        if (read_bytes < msg_size) {
            memset(buf + read_bytes, 0, msg_size - read_bytes);
        }
        unsigned char *payload = prepare_payload(buf);
        __u32 key = i;
        if (bpf_map_update_elem(map_fd, &key, payload, BPF_ANY) < 0) {
            perror("Failed to update map");
            free(payload);
            return -1;
        }
        free(payload);
    }

    fclose(fp);

    return total_blocks;
}
int get_map_fd(struct bpf_object *obj, const char *map_name) {
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, map_name);
    int map_fd = bpf_map__fd(map);
    return map_fd;
}
int attach_prog_to_tc(struct bpf_object *obj, const char *prog_name) {
    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "Failed to find BPF program %s\n", prog_name);
        return -1;
    }
    int prog_fd = bpf_program__fd(prog);

    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = if_nametoindex(IF_INTERFACE),
        .attach_point = BPF_TC_EGRESS,
    };

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        perror("Failed to create TC hook, hook might exists or an error occurred");
        return -1;
    }

    struct bpf_tc_opts opts = {
        .sz = sizeof(opts),
        .prog_fd = prog_fd,
        .flags = BPF_TC_F_REPLACE,
        .handle = 1,
        .priority = 1,
    };
    if (bpf_tc_attach(&hook, &opts) < 0) {
        perror("Failed to attach BPF program to TC hook");
        return -1;
    }
    return 0;
}
int main(int argc, char **argv) {

    struct args args;
    // todo: args are not used yet
    parse_args(argc, argv, &args);

    struct bpf_object *obj;

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        perror("Failed to open BPF object file");
        return 1;
    }
    if (args.show_help) {
        print_usage(argv[0]);
        return 0;
    }
    if (args.detach) {
        struct bpf_tc_hook hook = {
            .sz = sizeof(hook),
            .ifindex = if_nametoindex(IF_INTERFACE),
            .attach_point = BPF_TC_EGRESS,
        };
        struct bpf_tc_opts opts = {
            .prog_fd = 0,
            .flags = 0,
            .prog_id = 0,
            .handle = 1,
            .priority = 1,
            .sz = sizeof(opts),
        };

        if (bpf_tc_detach(&hook, &opts) < 0) {
            perror("Failed to detach BPF program from TC hook");
            return 1;
        }

        int fd = bpf_obj_get(stat_map_pin_path);
        if (fd < 0) {
            perror("Failed to get stats map file descriptor");
            return 1;
        }

        unsigned int nr_cpus = libbpf_num_possible_cpus();
        struct stats values[nr_cpus];
        __u64 packets = 0;
        __u64 total_time = 0;

        if (bpf_map_lookup_elem(fd, &(__u32){0}, values) < 0) {
            perror("Failed to lookup stats map");
            return 1;
        }

        for (unsigned int i = 0; i < nr_cpus; i++) {
            packets += values[i].packet_count;
            total_time += values[i].total_time;
        }

        printf("Total packets processed: %llu\n", packets);
        printf("Total time taken: %f ms\n", total_time / 1000000.0);
        printf("Average time per packet: %f ns\n", packets ? (total_time) / (double)packets : 0);

        struct bpf_map *stat_map = bpf_object__find_map_by_name(obj, "stats_map");
        if (bpf_map__unpin(stat_map, stat_map_pin_path) < 0) {
            perror("Failed to unpin stats_map");
            return 1;
        }
        return 0;
    }

    if (bpf_object__load(obj) < 0) {
        perror("Failed to load BPF object");
        return 1;
    }
    int map_fd = get_map_fd(obj, "message_map");
    if (map_fd < 0) {
        perror("Failed to get map file descriptor for message_map");
        return 1;
    }

    int mes_len = fill_message_map(map_fd, args.message_file);
    map_fd = get_map_fd(obj, "state_map");
    if (map_fd < 0) {
        perror("Failed to get map file descriptor for state_map");
        return 1;
    }
    __u32 key = 1;
    __u64 initial_value = mes_len;
    if (bpf_map_update_elem(map_fd, &key, &initial_value, BPF_ANY) < 0) {
        perror("Failed to update status map: mes len could not be set");
        return 1;
    }

    attach_prog_to_tc(obj, "tcp_processor");
    if (access(stat_map_pin_path, F_OK) != -1) {
        printf("unpinning maps...\n");
        if (bpf_object__unpin_maps(obj, "/sys/fs/bpf/") < 0) {
            perror("Failed to unpin maps");
            return 1;
        }
    }

    struct bpf_map *stat_map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!stat_map) {
        perror("Failed to find stats map");
        return 1;
    }
    if (bpf_map__pin(stat_map, stat_map_pin_path) == 0) {
        printf("Pinned stats map to %s\n", stat_map_pin_path);
    }

    return 0;
}
