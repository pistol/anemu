#define EMU_BENCH
#include "test.h"
#include "matrix.h"
#include <anemu.h>
#include <unistd.h>
#include <pthread.h>

int emu = 0;

int test() {
    int a, b;
    a = 8;
    b = 2;
    return a * b;
}

int **x, **y, **o;
int dimension, runs;

void matrixLoop() {
    int i, j, k;
    for (i = 0; i < dimension; i++){
        for(j = 0; j < dimension; j++){
            // printf("x[%d][%d] %x\n", i, j, &x[i][j]);
            int dotProduct = 0;
            for(k = 0; k < dimension; k++){
                dotProduct += x[i][k] * y[k][j];
            }
            o[i][j] = dotProduct;
        }
    }
}

#define TAINT_CAMERA        ((uint32_t)0x00000080)

void matrix() {
    x = allocateMatrix(dimension, TAINT_CAMERA);
    y = allocateMatrix(dimension, 0);
    o = allocateMatrix(dimension, 0);

    int i, j;
    /* init matrix */
    for (i = 0; i < dimension; i++){
        for(j = 0; j < dimension; j++){
            x[i][j] = i + j;
            y[i][j] = i + j;
            o[i][j] = 0;
        }
    }

    // double start, end, delta;
    struct timespec start, end;

    if (emu) {
        // emu_set_protect(true);
        emu_mprotect_mem(true);
        emu_reset_stats();
        time_ns(&start);
        EMU_MARKER_START;
    } else {
        time_ns(&start);
    }

    for (i = 0; i < runs; i++) {
    // M(matrixLoop());
        matrixLoop();
    }

    if (emu) {
        EMU_MARKER_STOP;
        time_ns(&end);
        emu_unprotect_mem();
        emu_dump_stats();
        /* emu_dump_taintmaps(); */
        emu_dump_taintpages();
    } else {
        time_ns(&end);
    }

    printf("cycles = %lld\n", ns_to_cycles(diff_ns(&start, &end)) / runs);

    /* free matrix */
    freeMatrix(x, dimension);
    freeMatrix(y, dimension);
    freeMatrix(o, dimension);
}

// call with two arguments: <emu on/off> <size>
int main(int argc, char ** argv) {
    // printf("argc = %d\n", argc);
    if (argc != 4) return -1;
    emu = atoi(argv[1]);
    dimension = atoi(argv[2]);
    runs = atoi(argv[3]);
    printf("emu: %d dim: %d runs: %d\n", emu, dimension, runs);

    if (emu) {
        emu_set_target(getpid());
        emu_set_protect(false);
        emu_hook_thread_entry((void *)pthread_self());
    }

    matrix();

    return 0;
}
