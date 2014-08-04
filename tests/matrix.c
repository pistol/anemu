#define EMU_BENCH
#include "test.h"
#include "matrix.h"
#include <anemu.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>

int emu = 0;

int test() {
    int a, b;
    a = 8;
    b = 2;
    return a * b;
}

int **x, **y, **o;
int dimension, runs, taintcount;

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

void *alloc(size_t size) {
    void *ret = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                     -1, 0);
    if (ret == MAP_FAILED) {
        printf("error: mmap\n");
        exit(EXIT_FAILURE);
    }

    /* DEBUG */
    // printf("%s: %x - %x length: %5d\n", __func__, (intptr_t)ret, (intptr_t)ret + size, size);
    return ret;
}

void dealloc(int** mat, int size) {
    int rows = size;
    int i;
    for(i = 0; i < rows; i++) {
        munmap(mat[i], size);
    }
    munmap(mat, size);
}

int** allocMatrix(int size, int tag, int count) {
    int rows, cols;
    rows = cols = size;
    int **mat = (int **)malloc(rows * sizeof(int*));
    /* int **mat = (int **)alloc(rows * sizeof(int*)); */
    // printf("mat %p\n", mat);
    int i;
    for(i = 0; i < rows; i++) {
        mat[i] = (int *)malloc(cols * sizeof(int));
        /* mat[i] = (int *)alloc(cols * sizeof(int)); */
        // printf("mat[%d] %p %x\n", i, mat[i], &mat[i]);
        /* if (tag && count) {  */
        if (tag &&
            count &&
            ((i + 1) % (size / count)) == 0) {
            /* printf("tainting row %d\n", i); */
            emu_set_taint_array((intptr_t)mat[i], tag, cols * sizeof(int));
            /* emu_set_taint_array((intptr_t)mat[i], tag, 1 * sizeof(int)); */
            // count--;
        }
    }
    return mat;
}

void matrix(int taintcount) {
    x = allocMatrix(dimension, TAINT_CAMERA, taintcount);
    y = allocMatrix(dimension, 0, 0);
    o = allocMatrix(dimension, 0, 0);

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
    /* dealloc(x, dimension); */
    /* dealloc(y, dimension); */
    /* dealloc(o, dimension); */
    freeMatrix(x, dimension);
    freeMatrix(y, dimension);
    freeMatrix(o, dimension);
}

// call with two arguments: <emu on/off> <size>
int main(int argc, char ** argv) {
    // printf("argc = %d\n", argc);
    if (argc != 5) return -1;
    emu = atoi(argv[1]);
    dimension = atoi(argv[2]);
    runs = atoi(argv[3]);
    taintcount = atoi(argv[4]);
    printf("emu: %d dim: %d runs: %d taintcount: %d\n", emu, dimension, runs, taintcount);

    if (emu) {
        emu_set_target(getpid());
        emu_set_protect(false);
        emu_hook_thread_entry((void *)pthread_self());
    }

    matrix(taintcount);

    return 0;
}
