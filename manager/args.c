#include "args.h"
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

static const struct option long_opts[] = {
    {"obj", optional_argument, NULL, 'o'},      {"iface", optional_argument, NULL, 'i'},
    {"fill-map", optional_argument, NULL, 'f'}, {"detach", no_argument, NULL, 'd'},
    {"help", no_argument, NULL, 'h'},           {NULL, 0, NULL, 0}};
void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o, --obj <file>       BPF object file to load\n");
    fprintf(stderr, "  -i, --iface <name>     Network interface to attach to\n");
    fprintf(stderr, "  -d, --detach           Detach the BPF program\n");
    fprintf(stderr, "  -f, --fill-map <file>  Fill the message map from a file\n");
    fprintf(stderr, "  -h, --help             Show this help message\n");
}
int parse_args(int argc, char **argv, struct args *out) {
    *out = (struct args){
        .obj = "bpf_sender.o", .iface = "eth0", .message_file = "sonnet.txt", .detach = 0, .show_help = 0};
    int opt, idx;
    while ((opt = getopt_long(argc, argv, "o:f:i:dh", long_opts, &idx)) != -1) {
        switch (opt) {
        case 'o':
            out->obj = optarg;
            break;
        case 'f':
            out->message_file = optarg;
            break;
        case 'i':
            out->iface = optarg;
            break;
        case 'd':
            out->detach = 1;
            break;
        case 'h':
            out->show_help = 1;
            return 0; // Exit after showing help
        }
    }
    return 0;
}

