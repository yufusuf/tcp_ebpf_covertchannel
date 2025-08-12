#ifndef _ARGS_H
#define _ARGS_H

struct args {
    const char *obj;       
    const char *iface;   
    const char *message_file;  
    int detach;         
    int show_help;     
};

int parse_args(int argc, char **argv, struct args *out);
void print_usage(const char *prog);
#endif // !_ARGS_H
