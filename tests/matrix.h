int** allocateMatrix(int size, int tag) {
    int rows, cols;
    rows = cols = size;
    int **mat = (int **)malloc(rows * sizeof(int*));
    // printf("mat %p\n", mat);
    int i;
    for(i = 0; i < rows; i++) {
        mat[i] = (int *)malloc(cols * sizeof(int));
        // printf("mat[%d] %p %x\n", i, mat[i], &mat[i]);
        if (tag) emu_set_taint_array((intptr_t)mat[i], tag, cols * sizeof(int));
    }
    return mat;
}

void freeMatrix(int** mat, int size) {
    int rows = size;
    int i;
    for(i = 0; i < rows; i++) {
        free(mat[i]);
    }
    free(mat);
}

#if 0
void matrixMulBasic(int dimension) {
    /* alloc matrix */
    int **x = allocateMatrix(dimension);
    int **y = allocateMatrix(dimension);
    int **o = allocateMatrix(dimension);

    int i, j, k;
    /* init matrix */
    for (i = 0; i < dimension; i++){
        for(j = 0; j < dimension; j++){
            x[i][j] = i + j;
            y[i][j] = i + j;
            o[i][j] = 0;
        }
    }

    double start, end;
    start = end = 0;
    if (emulation) {
        EMU_MARKER_START;
    } else {
        start = time_ms();
    }
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
    if (emulation) {
        EMU_MARKER_STOP;
    } else {
        end = time_ms();
        printf("time inner (ms): %f", end - start);
    }

    /* free matrix */
    freeMatrix(x, dimension);
    freeMatrix(y, dimension);
    freeMatrix(o, dimension);
}
#endif
