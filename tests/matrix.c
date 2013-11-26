#include "test.h"
#include "matrix.h"
#include <anemu.h>

int emulation = 0;

int main(int argc, char ** argv) {
    // printf("argc = %d\n", argc);
    if (argc != 3) return -1;
    emulation = atoi(argv[1]);
    int dimension = atoi(argv[2]);
    // printf("emu = %d dimension = %d\n", emulation, dimension);
    double start, end, delta;
    start = end = delta = 0;
    if (emulation) {
        emu_register_handler();
    } else {
        start = time_ms();
    }

    matrixMulBasic(dimension);
    if (!emulation) {
        end   = time_ms();
        delta = end - start;
        printf("time total (ms): %f\n", delta);        
    }
    return 0;
}
