#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <stddef.h>

int json_get_string(const char *json, const char *key, char *out, size_t out_size);
int json_get_string_alloc(const char *json, const char *key, char **out);
int json_get_int(const char *json, const char *key, int *out_value);

/* Convenience helper to format a simple JSON string key/value pair object. */
int json_format_string(char *buf, size_t buf_size, const char *key, const char *value);
int json_escape_string(char *buf, size_t buf_size, const char *value);
char *json_escape_dup(const char *value);

#endif /* JSON_UTIL_H */
