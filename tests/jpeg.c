#include <anemu.h>
#include <jhead.h>
#include <pthread.h>

int emu = 0;

int main(int argc, char ** argv) {
    // printf("argc = %d\n", argc);
    // if (argc != 3) return -1;
    emu = atoi(argv[1]);

    int iterations = atoi(argv[2]);
    int time = atoi(argv[3]);
    char* filename = argv[4];
    printf("file: %s\n", filename);

    uint64_t start, end;

    if (emu) {
        emu_set_target(getpid());
        emu_hook_thread_entry((void *)pthread_self());
        EMU_MARKER_START;
    }

    if (time) {
        start = getticks();
    }

    int i;
    for (i = 0; i < iterations; i++) {
        ResetJpgfile();
        ReadJpegFile(filename, READ_METADATA);        
    }

    if (time) {
        end = getticks();
        printf("ticks = %llu\n", end - start);
    }

    if (emu) { 
        EMU_MARKER_STOP;
    }

    return 0;
}
