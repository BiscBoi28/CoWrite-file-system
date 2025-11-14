#define _POSIX_C_SOURCE 200809L

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static void iso_timestamp(char *buf, size_t buf_size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    snprintf(buf, buf_size, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000);
}

int log_open(struct log_writer *writer, const char *path) {
    if (!writer || !path) {
        return -1;
    }
    memset(writer, 0, sizeof(*writer));
    writer->fp = fopen(path, "a");
    if (!writer->fp) {
        return -1;
    }
    strncpy(writer->path, path, sizeof(writer->path) - 1);
    return 0;
}

void log_close(struct log_writer *writer) {
    if (!writer) {
        return;
    }
    if (writer->fp) {
        fclose(writer->fp);
        writer->fp = NULL;
    }
}

int log_appendf(struct log_writer *writer, const char *fmt, ...) {
    if (!writer || !writer->fp || !fmt) {
        return -1;
    }
    char ts[64];
    iso_timestamp(ts, sizeof(ts));
    if (fprintf(writer->fp, "[%s] ", ts) < 0) {
        return -1;
    }
    va_list ap;
    va_start(ap, fmt);
    int rc = vfprintf(writer->fp, fmt, ap);
    va_end(ap);
    if (rc < 0) {
        return -1;
    }
    if (fputc('\n', writer->fp) == EOF) {
        return -1;
    }
    fflush(writer->fp);
    return 0;
}
