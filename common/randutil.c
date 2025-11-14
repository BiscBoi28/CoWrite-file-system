#define _POSIX_C_SOURCE 200809L

#include "randutil.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

static int seeded = 0;

void randutil_seed(void) {
    if (seeded) {
        return;
    }
    int fd = open("/dev/urandom", O_RDONLY);
    unsigned int seed = 0;
    if (fd >= 0) {
        if (read(fd, &seed, sizeof(seed)) != sizeof(seed)) {
            seed = (unsigned int)getpid() ^ (unsigned int)time(NULL);
        }
        close(fd);
    } else {
        seed = (unsigned int)getpid() ^ (unsigned int)time(NULL);
    }
    srand(seed);
    seeded = 1;
}

void randutil_token(char *buf, int length) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if (!buf || length <= 0) {
        return;
    }
    randutil_seed();
    for (int i = 0; i < length - 1; ++i) {
        buf[i] = alphabet[rand() % (int)(sizeof(alphabet) - 1)];
    }
    buf[length - 1] = '\0';
}
