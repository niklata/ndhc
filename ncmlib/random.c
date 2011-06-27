#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "log.h"
#include "io.h"

// Generate a 32-bit pseudorandom number using libc rand()
uint32_t libc_random_u32(void)
{
    static int initialized;
    if (initialized)
        return rand();

    uint32_t seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd != -1) {
        int r = safe_read(fd, (char *)&seed, sizeof seed);
        if (r == -1) {
            log_warning("Could not read /dev/urandom: %s", strerror(errno));
            close(fd);
            seed = time(0);
        }
    } else {
        log_warning("Could not open /dev/urandom: %s", strerror(errno));
        seed = time(0);
    }
    srand(seed);
    initialized = 1;
    return rand();
}


