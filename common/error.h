#ifndef ERROR_H
#define ERROR_H

typedef enum {
    ERR_OK = 0,
    ERR_NOAUTH = 1,
    ERR_NOTFOUND = 2,
    ERR_LOCKED = 3,
    ERR_BADREQ = 4,
    ERR_CONFLICT = 5,
    ERR_UNAVAILABLE = 6,
    ERR_INTERNAL = 7,
    ERR_EXISTS = 8,
    ERR_PERM = 9,
    ERR_TIMEOUT = 10
} error_code_t;

const char *error_code_name(error_code_t code);
const char *error_code_message(error_code_t code);

#endif /* ERROR_H */
