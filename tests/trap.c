// #include <anemu.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/syscall.h>

#ifndef NDK
#include <linux/perf_event.h>
#else
#include "perf_event.h"
#include "ucontext.h"
#endif

#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <signal.h>
#ifdef __i386__
#include <ucontext.h>
#endif

#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

// #include <assert.h>

#ifndef NDEBUG
#define assert(x) if (!(x)) { printf("ASSERTION (%s) FAILED file: %s line: %d\n", #x, __FILE__, __LINE__); exit(EXIT_FAILURE); }
#else
#define assert(x) (void)(NULL)
#endif

#define PAGE_SIZE 4096

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)
#define ASM(opcode)      asm volatile(".inst " __stringify(opcode))
#define BREAKINST_ARM_SWI	0xef9f0001
#define BREAKINST_THUMB_SWI	0xdf00   // svc 0
#define BREAKINST_ARM	  0xe7f001f0 // udf #16
#define BREAKINST_THUMB	0xde01     // udf #1
#define GDB_BREAKINST   BREAKINST_ARM_SWI
#define KGDB_BREAKINST  0xe7ffdefe

uint64_t getticks(void)
{
    static int fd,init = 0;
    static struct perf_event_attr attr;
    static uint64_t buffer;

    if(!init) {
        attr.type = PERF_TYPE_HARDWARE;
        attr.config = PERF_COUNT_HW_CPU_CYCLES;
        fd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
        if(fd < 0) {
            fprintf(stderr,"ERROR - Cannot open perf event file descriptor:\n");
            if(errno == -EPERM || errno == -EACCES)
                fprintf(stderr,"  Permission denied.\n");
            else if(errno == ENOENT)
                fprintf(stderr,"  PERF_COUNT_HW_CPU_CYCLES event is not supported.\n");
            else
                fprintf(stderr,"  Attempting to open the file descriptor returned %d (%s).\n",errno, strerror(errno));
            exit(-1);
        }
        init = 1;
    }
    // TODO: change to __sread
    read(fd,&buffer,sizeof(uint64_t));
    return buffer;
}

#ifdef __arm__
#define REG(name) (((ucontext_t *)ucontext)->uc_mcontext.arm_##name)
#define BKPT ASM(BREAKINST_ARM)
#else
#define REG(name) (((ucontext_t *)ucontext)->uc_mcontext.gregs[name])
#define pc REG_EIP
#define BKPT asm volatile("int3")
#endif

const char *get_signame(int sig) {
    switch(sig) {
    case SIGSEGV:    return "SIGSEGV";
    case SIGTRAP:    return "SIGTRAP";
    case SIGILL:     return "SIGILL" ;
    case SIGABRT:    return "SIBABRT";
    default:         return "?";
    }
}

// time count
uint64_t start, end, delta;
uint64_t i, n;
uint64_t count;

void handler(int sig, siginfo_t *si, void *ucontext) {
    count++;
    // x86 auto increments EIP for SIGTRAP but not for SIGSEGV
    // ARM doesn't auto increment in either case
#ifndef NDEBUG
    printf("\n%s addr %lx\n", get_signame(sig), REG(pc));
#endif
#ifdef __i386__
    if (sig == SIGSEGV) REG(pc) += 10;
    if (sig == SIGILL)  {
        REG(pc) += 2;
        sleep(1);
    }
#else
    // GDB_BREAKINST automatically increments PC
    if (*(uint32_t*)(REG(pc)-4) == GDB_BREAKINST) {
#ifndef NDEBUG
        printf("GDB_BREAKINST not incrementing pc\n");
#endif
    } else {
#ifndef NDEBUG
        printf("incrementing pc from %lx to %lx\n", REG(pc), REG(pc) + 4);
#endif
        REG(pc) += 4;
    }
#endif
}

void handler_infinite(int sig) {
    static uint64_t count = 0;
    count++;
    if (count == n) exit(0);
}

#if 1
// assumes start, end, i, n are already defined
#define TEST(name, command, n, expect)                                  \
    count = 0;                                                          \
    start = getticks();                                                 \
    for (i = 0; i < n; i++) {                                           \
        command;                                                        \
    }                                                                   \
    end = getticks();                                                   \
    printf("%6"PRIu64" cycles \"%s\"\n",                                \
           ((end - start) / n), name);                                  \
    assert(count == expect);                                            \
    end = start = 0;
#else
#define TEST(name, command, n, expect)                                  \
    count = 0;                                                          \
    printf("n: %"PRIu64"\n", n);                                        \
    start = getticks();                                                 \
    for (i = 0; i < n; i++) {                                           \
        command;                                                        \
    }                                                                   \
    end = getticks();                                                   \
    printf("%6"PRIu64" cycles %s\n",                                    \
           ((end - start) / n), name);                                  \
    printf("start: %"PRIu64" end: %"PRIu64" count: %"PRIu64"\n\n", start, end, count); \
    assert(count == expect);                                            \
    end = start = 0;
#endif

#define __NR_null 376

int main(int argc, char ** argv) {
    end = start = delta = 0;
    // setup signal handler
#if 1
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = handler;
    if (sigaction (SIGSEGV, &sa, NULL) == -1) {
        printf("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction (SIGTRAP, &sa, NULL) == -1) {
        printf("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction (SIGILL, &sa, NULL) == -1) {
        printf("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction (SIGBUS, &sa, NULL) == -1) {
        printf("sigaction");
        exit(EXIT_FAILURE);
    }
    if (sigaction (SIGABRT, &sa, NULL) == -1) {
        printf("sigaction");
        exit(EXIT_FAILURE);
    }
#endif

    // number of iterations from command line
    n = atoll(argv[1]);

#if 1
#ifdef __arm__
    if(syscall(__NR_null) == 1337) {
        TEST("null syscall", syscall(__NR_null), n, 0);
    } else {
        printf("null syscall not implemented\n");
    }
#endif

    TEST("getpid()", getpid(), n, 0);
    // TEST("time()",   time(NULL), n, 0);

#define FILE "/dev/null"
#ifdef __arm__
    int fd = open(FILE, O_RDWR);
#else
    int fd = open(FILE, O_RDWR, S_IRWXU);
#endif
    int tmp[PAGE_SIZE];
    TEST("read(1B)",   read(fd, &tmp, 1), n, 0);
    // TEST("read(4K)",   read(fd, &tmp, PAGE_SIZE), n);
    TEST("write(1B)",  write(fd, &tmp, 1), n, 0);
    // TEST("write(4K)",  write(fd, &tmp, PAGE_SIZE), n);
    close(fd);

    TEST("clock_gettime()",  clock_gettime(CLOCK_REALTIME, NULL), n, 0);
    /* TEST("sleep(0)",    sleep(0), n, 0); */
    /* TEST("usleep(0)",  usleep(0), n, 0); */
    // TEST("nanosleep(0)",  nanosleep(NULL, NULL), n, 0);
#endif
    TEST("SIGSEGV",  *(volatile uint32_t *)0xdeadbeef = 0, n, n);
    // TEST("SIGTRAP",  BKPT, n, n);

    /* TEST("KGDB_BREAKINST", ASM(KGDB_BREAKINST), n, n); */
    /* TEST("GDB_BREAKINST",  ASM(GDB_BREAKINST),  n, n); */
    // SIGTRAP from udf #16
    TEST("SIGTRAP",        ASM(BREAKINST_ARM),  n, n);
    // TEST("bkpt",           asm volatile("bkpt"),  n, n);
    /* TEST("SIGILL",  asm volatile(".inst 0xe7f002f0"), n, n); */
    // SIGILL from udf 0xfdee (KGDB_BREAKINST)
    TEST("SIGILL",  ASM(KGDB_BREAKINST), n, n);

    /* TEST("__builtin_trap()",  __builtin_trap(), n, n); */

    const uint16_t size = 4096;
    void *taint_page = mmap(NULL, size,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                            -1, 0);
 
    *(uintptr_t *)taint_page = 0x1337;
    mprotect(taint_page, size, PROT_NONE);
    fd = open("/proc/self/mem", O_RDWR);
    
    uintptr_t offset  = (uintptr_t)taint_page;
    uintptr_t val;
 
    /* pread(fd, &val, sizeof(val), offset); */
    TEST("pread(4B)", pread(fd, &val, sizeof(val), offset), n, 0);
    /* printf("mem read: %x\n", val); */
 
    // write new value
    val = 0xdeadbeef;
    /* pwrite(fd, &val, sizeof(val), offset); */
    TEST("pwrite(4B)", pwrite(fd, &val, sizeof(val), offset), n, 0);

    // TODO: test lseek + read/write as well
 
    // enable loads and stores to page
    mprotect(taint_page, size, PROT_READ | PROT_WRITE);
    // taint page access will no longer SIGSEGV
    /* printf("load val: %lx\n", *(uintptr_t *)taint_page); */

    return 0;
}
