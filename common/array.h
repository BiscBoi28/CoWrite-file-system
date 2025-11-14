#ifndef ARRAY_H
#define ARRAY_H

#include <stddef.h>

struct array {
    void *data;
    size_t len;
    size_t cap;
    size_t elem_size;
};

void array_init(struct array *arr, size_t elem_size);
void array_free(struct array *arr);
void *array_get(struct array *arr, size_t index);
int array_reserve(struct array *arr, size_t capacity);
int array_push(struct array *arr, const void *value);
int array_insert(struct array *arr, size_t index, const void *value);
void array_remove(struct array *arr, size_t index);

#endif /* ARRAY_H */
