#ifndef LOG_H
#define LOG_H

#include <stdio.h>

struct log_writer {
    FILE *fp;
    char path[256];
};

int log_open(struct log_writer *writer, const char *path);
void log_close(struct log_writer *writer);
int log_appendf(struct log_writer *writer, const char *fmt, ...);

#endif /* LOG_H */
