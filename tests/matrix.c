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
int dimension;

void matrixLoop() {
    int i, j, k;
    for (i = 0; i < dimension; i++){
        for(j = 0; j < dimension; j++){
            int dotProduct = 0;
            for(k = 0; k < dimension; k++){
                dotProduct += x[i][k] * y[k][j];
            }
            o[i][j] = dotProduct;
            /* printf("%d\n", o[i][j]); */
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
    uint64_t start, end;
    start = end = 0;

    start = getticks();
    if (emu) EMU_MARKER_START;

    M(matrixLoop());

    if (emu) EMU_MARKER_STOP;
    end   = getticks();

    printf("ticks = %llu\n", end - start);

    /* free matrix */
    freeMatrix(x, dimension);
    freeMatrix(y, dimension);
    freeMatrix(o, dimension);
}

// call with two arguments: <emu on/off> <size>
int main(int argc, char ** argv) {
    // printf("argc = %d\n", argc);
    if (argc != 3) return -1;
    emu = atoi(argv[1]);
    dimension = atoi(argv[2]);
    printf("emu: %d dim: %d\n", emu, dimension);

    if (emu) {
        emu_set_target(getpid());
        emu_hook_thread_entry((void *)pthread_self());
    }

    matrix();

    return 0;
}
