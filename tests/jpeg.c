#include <anemu.h>
#include <jhead.h>
#include <pthread.h>

int emu = 0;

// emu-jpeg [emu: 0/1] [iterations] [time: 0/1] [filename]
int main(int argc, char ** argv) {
    if (argc != 5) {
        printf("invalid arguments (argc: %d)\n", argc);
        printf("emu-jpeg [emu: 0/1] [iterations] [time: 0/1] [filename]\n");
        return 0;
    }
    emu = atoi(argv[1]);

    int iterations = atoi(argv[2]);
    int time = atoi(argv[3]);
    char* filename = argv[4];
    printf("file: %s\n", filename);

    struct timespec start, end;

    if (emu) {
        emu_set_target(getpid());
        emu_hook_thread_entry((void *)pthread_self());
        time_ns(&start);
        EMU_MARKER_START;
    } else if (time) {
        time_ns(&start);
    }

    int i;
    for (i = 0; i < iterations; i++) {
        ResetJpgfile();
        ReadJpegFile(filename, READ_METADATA);        
    }

    if (emu) { 
        EMU_MARKER_STOP;
        // emu_unprotect_mem();
        time_ns(&end);
        printf("ticks = %"PRId64"\n", ns_to_cycles(diff_ns(&start, &end)));
        emu_dump_stats();
        emu_dump_taintpages();
    } else if (time) {
        time_ns(&end);
        printf("ticks = %"PRId64"\n", ns_to_cycles(diff_ns(&start, &end)));
    }

    return 0;
}
