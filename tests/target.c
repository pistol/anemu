#include "test.h"
#include "matrix.h"
#include <anemu.h>

int emulation = 0;

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

void matrix() {
    x = allocateMatrix(dimension);
    y = allocateMatrix(dimension);
    o = allocateMatrix(dimension);
    
    int i, j;
    /* init matrix */
    for (i = 0; i < dimension; i++){
        for(j = 0; j < dimension; j++){
            x[i][j] = i + j;
            y[i][j] = i + j;
            o[i][j] = 0;
        }
    }

    double start, end, delta;
    start = end = delta = 0;

    if (emulation) {
        emu_target(matrixLoop);
    } else {
        start = time_ms();
        matrixLoop();
        end   = time_ms();
        delta = end - start;
        printf("time total (ms): %f\n", delta);        
    }

    /* free matrix */
    freeMatrix(x, dimension);
    freeMatrix(y, dimension);
    freeMatrix(o, dimension);
}

int main(int argc, char ** argv) {
    // printf("argc = %d\n", argc);
    if (argc != 3) return -1;
    emulation = atoi(argv[1]);
    dimension = atoi(argv[2]);

    matrix();

    return 0;
}
