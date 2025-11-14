#define _POSIX_C_SOURCE 200112L

#include "net_proto.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static int send_all(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t sent = send(fd, p + total, len - total, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            return -1;
        }
        total += (size_t)sent;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len) {
    unsigned char *p = buf;
    size_t total = 0;
    while (total < len) {
        ssize_t recvd = recv(fd, p + total, len - total, 0);
        if (recvd < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (recvd == 0) {
            return -1;
        }
        total += (size_t)recvd;
    }
    return 0;
}

int net_send_json(int fd, const char *json) {
    uint32_t len = (uint32_t)strlen(json);
    uint32_t len_be = htonl(len);
    if (send_all(fd, &len_be, sizeof(len_be)) < 0) {
        return -1;
    }
    if (send_all(fd, json, len) < 0) {
        return -1;
    }
    return 0;
}

int net_recv_json(int fd, char **out_json) {
    uint32_t len_be = 0;
    if (recv_all(fd, &len_be, sizeof(len_be)) < 0) {
        return -1;
    }
    uint32_t len = ntohl(len_be);
    char *buf = malloc(len + 1);
    if (!buf) {
        return -1;
    }
    if (recv_all(fd, buf, len) < 0) {
        free(buf);
        return -1;
    }
    buf[len] = '\0';
    *out_json = buf;
    return 0;
}

int net_listen(const char *port, int backlog) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *res = NULL;
    int err = getaddrinfo(NULL, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    int listen_fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        listen_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listen_fd < 0) {
            continue;
        }
        int opt = 1;
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (bind(listen_fd, p->ai_addr, p->ai_addrlen) == 0) {
            if (listen(listen_fd, backlog) == 0) {
                break;
            }
        }
        net_close(listen_fd);
        listen_fd = -1;
    }

    freeaddrinfo(res);
    return listen_fd;
}

int net_connect(const char *host, const char *port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    int fd = -1;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        net_close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

int net_close(int fd) {
    int ret;
    do {
        ret = close(fd);
    } while (ret < 0 && errno == EINTR);
    return ret;
}
