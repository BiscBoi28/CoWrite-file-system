#include "error.h"

const char *error_code_name(error_code_t code) {
    switch (code) {
        case ERR_OK:
            return "OK";
        case ERR_NOAUTH:
            return "ERR_NOAUTH";
        case ERR_NOTFOUND:
            return "ERR_NOTFOUND";
        case ERR_LOCKED:
            return "ERR_LOCKED";
        case ERR_BADREQ:
            return "ERR_BADREQ";
        case ERR_CONFLICT:
            return "ERR_CONFLICT";
        case ERR_UNAVAILABLE:
            return "ERR_UNAVAILABLE";
        case ERR_INTERNAL:
            return "ERR_INTERNAL";
        case ERR_EXISTS:
            return "ERR_EXISTS";
        case ERR_PERM:
            return "ERR_PERM";
        case ERR_TIMEOUT:
            return "ERR_TIMEOUT";
        default:
            return "ERR_UNKNOWN";
    }
}

const char *error_code_message(error_code_t code) {
    switch (code) {
        case ERR_OK:
            return "success";
        case ERR_NOAUTH:
            return "authentication or authorization failure";
        case ERR_NOTFOUND:
            return "resource not found";
        case ERR_LOCKED:
            return "resource is locked";
        case ERR_BADREQ:
            return "invalid request";
        case ERR_CONFLICT:
            return "conflict";
        case ERR_UNAVAILABLE:
            return "service unavailable";
        case ERR_INTERNAL:
            return "internal error";
        case ERR_EXISTS:
            return "resource already exists";
        case ERR_PERM:
            return "operation not permitted";
        case ERR_TIMEOUT:
            return "operation timed out";
        default:
            return "unknown error";
    }
}
