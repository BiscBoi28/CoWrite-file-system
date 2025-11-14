#ifndef NET_PROTO_H
#define NET_PROTO_H

#include <stddef.h>

/* Establish a listening socket bound to INADDR_ANY on the given port. */
int net_listen(const char *port, int backlog);

/* Establish a TCP connection to host:port. */
int net_connect(const char *host, const char *port);

/* Send a length-prefixed JSON payload. Returns 0 on success. */
int net_send_json(int fd, const char *json);

/* Receive a length-prefixed JSON payload. Allocates buffer in *out_json. */
int net_recv_json(int fd, char **out_json);

/* Close helper that retries on EINTR. */
int net_close(int fd);

#endif /* NET_PROTO_H */
