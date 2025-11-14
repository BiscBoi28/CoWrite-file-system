#include "json_util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) {
        return -1;
    }
    char pattern[128];
    if (snprintf(pattern, sizeof(pattern), "\"%s\":\"", key) >= (int)sizeof(pattern)) {
        return -1;
    }
    const char *match = strstr(json, pattern);
    if (!match) {
        return -1;
    }
    const char *p = match + strlen(pattern);
    size_t pos = 0;
    while (*p) {
        char c = *p++;
        if (c == '\\') {
            char next = *p++;
            if (next == '\0') {
                return -1;
            }
            switch (next) {
                case 'n':
                    c = '\n';
                    break;
                case 'r':
                    c = '\r';
                    break;
                case 't':
                    c = '\t';
                    break;
                case '\\':
                    c = '\\';
                    break;
                case '"':
                    c = '"';
                    break;
                default:
                    c = next;
                    break;
            }
            if (pos + 1 >= out_size) {
                return -1;
            }
            out[pos++] = c;
            continue;
        }
        if (c == '"') {
            if (pos >= out_size) {
                return -1;
            }
            out[pos] = '\0';
            return 0;
        }
        if (pos + 1 >= out_size) {
            return -1;
        }
        out[pos++] = c;
    }
    return -1;
}

int json_get_string_alloc(const char *json, const char *key, char **out) {
    if (!json || !key || !out) {
        return -1;
    }
    *out = NULL;
    char pattern[128];
    if (snprintf(pattern, sizeof(pattern), "\"%s\":\"", key) >= (int)sizeof(pattern)) {
        return -1;
    }
    const char *match = strstr(json, pattern);
    if (!match) {
        return -1;
    }
    const char *p = match + strlen(pattern);
    const char *scan = p;
    size_t len = 0;
    while (*scan) {
        char c = *scan;
        if (c == '\\') {
            scan++;
            if (*scan == '\0') {
                return -1;
            }
            scan++;
            len++;
            continue;
        }
        if (c == '"') {
            break;
        }
        scan++;
        len++;
    }
    if (*scan != '"') {
        return -1;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        return -1;
    }
    size_t pos = 0;
    while (*p) {
        char c = *p++;
        if (c == '\\') {
            char next = *p++;
            if (next == '\0') {
                free(buf);
                return -1;
            }
            switch (next) {
                case 'n':
                    c = '\n';
                    break;
                case 'r':
                    c = '\r';
                    break;
                case 't':
                    c = '\t';
                    break;
                case '\\':
                    c = '\\';
                    break;
                case '"':
                    c = '"';
                    break;
                default:
                    c = next;
                    break;
            }
            buf[pos++] = c;
            continue;
        }
        if (c == '"') {
            buf[pos] = '\0';
            *out = buf;
            return 0;
        }
        buf[pos++] = c;
    }
    free(buf);
    return -1;
}

int json_get_int(const char *json, const char *key, int *out_value) {
    if (!json || !key || !out_value) {
        return -1;
    }
    char pattern[128];
    if (snprintf(pattern, sizeof(pattern), "\"%s\":", key) >= (int)sizeof(pattern)) {
        return -1;
    }
    const char *start = strstr(json, pattern);
    if (!start) {
        return -1;
    }
    start += strlen(pattern);
    while (isspace((unsigned char)*start)) {
        start++;
    }
    char *end = NULL;
    long val = strtol(start, &end, 10);
    if (start == end) {
        return -1;
    }
    *out_value = (int)val;
    return 0;
}

static int escape_value(char *dst, size_t dst_size, const char *src) {
    size_t pos = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; ++p) {
        char c = (char)*p;
        const char *replacement = NULL;
        switch (c) {
            case '\"':
                replacement = "\\\"";
                break;
            case '\\':
                replacement = "\\\\";
                break;
            case '\n':
                replacement = "\\n";
                break;
            case '\r':
                replacement = "\\r";
                break;
            case '\t':
                replacement = "\\t";
                break;
            default:
                break;
        }
        if (replacement) {
            size_t need = strlen(replacement);
            if (pos + need >= dst_size) {
                return -1;
            }
            memcpy(dst + pos, replacement, need);
            pos += need;
        } else {
            if (pos + 1 >= dst_size) {
                return -1;
            }
            dst[pos++] = c;
        }
    }
    if (pos >= dst_size) {
        return -1;
    }
    dst[pos] = '\0';
    return 0;
}

int json_escape_string(char *buf, size_t buf_size, const char *value) {
    return escape_value(buf, buf_size, value);
}

static size_t escape_length(const char *src) {
    size_t len = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p; ++p) {
        switch (*p) {
            case '\"':
            case '\\':
            case '\n':
            case '\r':
            case '\t':
                len += 2;
                break;
            default:
                len += 1;
                break;
        }
    }
    return len;
}

char *json_escape_dup(const char *value) {
    if (!value) {
        return NULL;
    }
    size_t needed = escape_length(value);
    char *buf = malloc(needed + 1);
    if (!buf) {
        return NULL;
    }
    if (escape_value(buf, needed + 1, value) < 0) {
        free(buf);
        return NULL;
    }
    return buf;
}

int json_format_string(char *buf, size_t buf_size, const char *key, const char *value) {
    if (!buf || !key || !value) {
        return -1;
    }
    char key_escaped[128];
    char value_escaped[1024];
    if (escape_value(key_escaped, sizeof(key_escaped), key) < 0) {
        return -1;
    }
    if (escape_value(value_escaped, sizeof(value_escaped), value) < 0) {
        return -1;
    }
    int written = snprintf(buf, buf_size, "{\"%s\":\"%s\"}", key_escaped, value_escaped);
    if (written < 0 || (size_t)written >= buf_size) {
        return -1;
    }
    return 0;
}
