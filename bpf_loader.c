#include <net/if.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bpf_sender.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct bpf_sender *skel;
    int ifindex = if_nametoindex("veth_sec");
    if (!ifindex) {
        fprintf(stderr, "Failed to find interface veth_sec\n");
        return 1;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = bpf_sender__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        goto cleanup;
    }

    struct bpf_tc_hook hook = {
        .attach_point = BPF_TC_EGRESS,
        .ifindex = ifindex,
    };
    if (bpf_tc_hook_create(&hook) < 0) {
        fprintf(stderr, "Failed to create TC hook\n");
        goto cleanup;
    }
    struct bpf_tc_opts opts = {
        .prog_fd = bpf_program__fd(skel->progs.tcp_processor),
        .handle = 1,
        .priority = 1,
    };
    if (bpf_tc_attach(&hook, &opts) < 0) {
        fprintf(stderr, "Failed to attach TC program\n");
        goto cleanup;
    }

    printf("Successfully started!\n");

    getchar();

    bpf_tc_detach(&hook, &opts);

cleanup:
    bpf_sender__destroy(skel);
}
