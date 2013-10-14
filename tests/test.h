#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern int emulation;

static inline double time_ms(void) {
    struct timespec res;
    clock_gettime(CLOCK_MONOTONIC, &res);
    double result = 1000.0 * res.tv_sec + (double) res.tv_nsec / 1e6;
    return result;
}

