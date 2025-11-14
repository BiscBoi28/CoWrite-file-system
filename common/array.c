#include "array.h"

#include <stdlib.h>
#include <string.h>

void array_init(struct array *arr, size_t elem_size) {
    arr->data = NULL;
    arr->len = 0;
    arr->cap = 0;
    arr->elem_size = elem_size;
}

void array_free(struct array *arr) {
    if (!arr) {
        return;
    }
    free(arr->data);
    arr->data = NULL;
    arr->len = 0;
    arr->cap = 0;
}

static int array_grow(struct array *arr, size_t min_capacity) {
    if (arr->cap >= min_capacity) {
        return 0;
    }
    size_t new_cap = arr->cap ? arr->cap * 2 : 8;
    while (new_cap < min_capacity) {
        new_cap *= 2;
    }
    void *new_data = realloc(arr->data, new_cap * arr->elem_size);
    if (!new_data) {
        return -1;
    }
    arr->data = new_data;
    arr->cap = new_cap;
    return 0;
}

int array_reserve(struct array *arr, size_t capacity) {
    return array_grow(arr, capacity);
}

void *array_get(struct array *arr, size_t index) {
    if (!arr || index >= arr->len) {
        return NULL;
    }
    return (char *)arr->data + index * arr->elem_size;
}

int array_push(struct array *arr, const void *value) {
    if (array_grow(arr, arr->len + 1) < 0) {
        return -1;
    }
    memcpy((char *)arr->data + arr->len * arr->elem_size, value, arr->elem_size);
    arr->len++;
    return 0;
}

int array_insert(struct array *arr, size_t index, const void *value) {
    if (index > arr->len) {
        return -1;
    }
    if (array_grow(arr, arr->len + 1) < 0) {
        return -1;
    }
    void *dest = (char *)arr->data + index * arr->elem_size;
    memmove((char *)dest + arr->elem_size, dest, (arr->len - index) * arr->elem_size);
    memcpy(dest, value, arr->elem_size);
    arr->len++;
    return 0;
}

void array_remove(struct array *arr, size_t index) {
    if (!arr || index >= arr->len) {
        return;
    }
    void *dest = (char *)arr->data + index * arr->elem_size;
    memmove(dest, (char *)dest + arr->elem_size, (arr->len - index - 1) * arr->elem_size);
    arr->len--;
}
