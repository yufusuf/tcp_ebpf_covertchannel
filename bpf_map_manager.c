#include <asm-generic/errno-base.h>
#include <linux/bpf.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#define MESSAGE_SIZE 32
#define CRC_SIZE 4
#define CRC_OFFSET 28

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
    printf("Message: %.*s\n", (int)msg_len, buf);
    printf("CRC32: %08x\n", crc);

    // Append CRC32 little-endian
    buf[msg_len + 0] = (uint8_t)(crc & 0xFF);
    buf[msg_len + 1] = (uint8_t)((crc >> 8) & 0xFF);
    buf[msg_len + 2] = (uint8_t)((crc >> 16) & 0xFF);
    buf[msg_len + 3] = (uint8_t)((crc >> 24) & 0xFF);

    return buf;
}
int init_message_map(int map_fd, const char *file_path) {
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
    int total_blocks = (file_size + msg_size - 1) / chunk_size;

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

int main(int argc, char **argv) {
    const char *pin_path = "/sys/fs/bpf/message_map";
    const char *obj_path = "bpf_sender.o";

    struct bpf_object *obj;
    struct bpf_map *map;

    obj = bpf_object__open_file(obj_path, NULL);
    if (!obj) {
        perror("Failed to open BPF object file");
        return 1;
    }
    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        perror("Failed to get map file descriptor");
        return 1;
    }
    init_message_map(map_fd, "sonnet.txt");
    map = bpf_object__find_map_by_name(obj, "message_map");
    if (bpf_map__reuse_fd(map, map_fd) < 0) {
        perror("Failed to resize map");
        return 1;
    }
    if (bpf_object__load(obj) < 0) {
        perror("Failed to load BPF object");
        return 1;
    }

    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(obj, "tcp_processor");
    if (!prog) {
        perror("Failed to find BPF program");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    int ifindex = if_nametoindex("veth_sec");
    struct bpf_tc_hook hook = {
        .sz = sizeof(hook),
        .ifindex = ifindex,
        .attach_point = BPF_TC_EGRESS,
    };

    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) {
        perror("Failed to create TC hook");
        return 1;
    }

    struct bpf_tc_opts opts = {.sz = sizeof(opts), .prog_fd = prog_fd, .flags = BPF_TC_F_REPLACE};
    if (bpf_tc_attach(&hook, &opts) < 0) {
        perror("Failed to attach BPF program to TC hook");
        return 1;
    }
    return 0;
}
