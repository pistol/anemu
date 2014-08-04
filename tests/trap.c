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

#include <anemu.h>              /* for timing functions */

#ifndef NDEBUG
#define assert(x) if (!(x)) { printf("ASSERTION (%s) FAILED file: %s line: %d\n", #x, __FILE__, __LINE__); exit(EXIT_FAILURE); }
#else
#define assert(x) (void)(NULL)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)
#define ASM(opcode)      asm volatile(".inst " __stringify(opcode))
#define BREAKINST_ARM_SWI	0xef9f0001
#define BREAKINST_THUMB_SWI	0xdf00   // svc 0
#define BREAKINST_ARM	  0xe7f001f0 // udf #16
#define BREAKINST_THUMB	0xde01     // udf #1
#define GDB_BREAKINST   BREAKINST_ARM_SWI
#define KGDB_BREAKINST  0xe7ffdefe

#ifdef __arm__
#define REG(name) (((ucontext_t *)ucontext)->uc_mcontext.arm_##name)
#define BKPT ASM(BREAKINST_ARM)
#else
#define REG(name) (((ucontext_t *)ucontext)->uc_mcontext.gregs[name])
#define pc REG_EIP
#define BKPT asm volatile("int3")
#endif

/*
const char *get_signame(int sig) {
    switch(sig) {
    case SIGSEGV:    return "SIGSEGV";
    case SIGTRAP:    return "SIGTRAP";
    case SIGILL:     return "SIGILL" ;
    case SIGABRT:    return "SIBABRT";
    default:         return "?";
    }
}
*/

// time count
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

struct timespec start, end;
int64_t diff;

#define MEASURE_START   time_ns(&start)
#define MEASURE_END     time_ns(&end)
#define DIFF            diff = ns_to_cycles(diff_ns(&start, &end));

#define PRE                                                             \
    assert(runs > 0);                                                   \
    count = 0;                                                          \
    MEASURE_START;                                                      \
    for (i = 0; i < runs; i++) {

#define POST(name)                                                      \
    }                                                                   \
    MEASURE_END;                                                    \
    DIFF;                                                               \
    printf("%6"PRId64" cycles \"%s\"\n",                                \
           (diff / runs / div), name);                                  \
    assert(i == runs);                                                  \
    assert(count == expect);                                            \
    count = 0;

#define TESTX(name, cmd)                        \
    PRE;                                        \
    cmd;                                        \
    POST(name);

#define TEST(name, cmd, co, ex)                  \
    expect = ex;                                \
    TESTX(name, cmd);


#define INIT_ARRAY(arr, bytes)                  \
    for (x = 0; x<bytes; x++) {                 \
        ((uint8_t*)arr)[x] += x;                \
    }

#define __NR_null 376

int main(int argc, char ** argv) {
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
    uint64_t runs, expect, div;
    div = 1;
    runs = n;

#if 1
#ifdef __arm__
    if(syscall(__NR_null) == 1337) {
        TESTX("null syscall", syscall(__NR_null));
    } else {
        printf("null syscall not implemented\n");
    }
#endif

    TESTX("getpid()", getpid());
    // TEST("time()",   time(NULL), n, 0);

#define FILE "/dev/null"
#ifdef __arm__
    int fd = open(FILE, O_RDWR);
#else
    int fd = open(FILE, O_RDWR, S_IRWXU);
#endif
    volatile int tmp[PAGE_SIZE];

    /* TEST("read(1B)",   read(fd, &tmp, 1), n, 0); */
    TESTX("read(1B)",   read(fd, &tmp, 1));
    // TEST("read(4K)",   read(fd, &tmp, PAGE_SIZE), n);
    /* TEST("write(1B)",  write(fd, &tmp, 1), n, 0); */
    TESTX("write(1B)",  write(fd, &tmp, 1));

    /* TEST("read+write(1B)", tmp[0]++; write(fd, &tmp, 1); read(fd, &tmp, 1), n, 0); */
    TESTX("read+write(1B)", tmp[0]++; write(fd, &tmp, 1); read(fd, &tmp, 1));

    // TEST("write(4K)",  write(fd, &tmp, PAGE_SIZE), n);
    close(fd);

    /* TEST("clock_gettime()",  clock_gettime(CLOCK_REALTIME, NULL), n, 0); */
    TESTX("clock_gettime()",  clock_gettime(CLOCK_REALTIME, NULL));
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

    uint32_t x;
    uint32_t size = n * PAGE_SIZE;

    void *taint_page = mmap(NULL, size,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                            -1, 0);
 
    *(uintptr_t *)taint_page = 0x1337;

    INIT_ARRAY(taint_page, size);
    mprotect(taint_page, size, PROT_NONE);

    signal(SIGSEGV, SIG_DFL);
    signal(SIGTRAP, SIG_DFL);

    mprotect(taint_page, size, PROT_NONE);

    TESTX("mprotect(RWX/N) toggle", mprotect(taint_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC); mprotect(taint_page, PAGE_SIZE, PROT_NONE));
    /* TEST("mprotect(RWX/N) toggle", mprotect(taint_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC); mprotect(taint_page, PAGE_SIZE, PROT_NONE), n/2, 0); */
    TESTX("mprotect(RWX/N) toggle sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC); mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
 
    TESTX("mprotect(RW/N) toggle", mprotect(taint_page, PAGE_SIZE, PROT_READ | PROT_WRITE); mprotect(taint_page, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RW/N) toggle sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE); mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));

    TESTX("mprotect(R/N) toggle", mprotect(taint_page, PAGE_SIZE, PROT_READ); mprotect(taint_page, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(R/N) toggle sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ); mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));

    runs = n;
    TESTX("mprotect(N)", mprotect(taint_page, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RW)", mprotect(taint_page, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RWX)", mprotect(taint_page, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    TESTX("mprotect(N) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RW) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RWX) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    TESTX("mprotect(N) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RW) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RWX) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    TESTX("mprotect(N) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RWX) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    TESTX("mprotect(N) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_NONE));
    TESTX("mprotect(RWX) sweep", mprotect(taint_page + i * PAGE_SIZE, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC));
    //    mprotect(taint_page, size, PROT_NONE);

    mprotect(taint_page, size, PROT_NONE);
    fd = open("/proc/self/mem", O_RDWR);
    
    uintptr_t offset  = (uintptr_t)taint_page;
    uintptr_t val;

    runs = n/2;
    TESTX("pread+pwrite(4B) loop",  val++; pwrite(fd, &val, sizeof(val), offset); pread(fd, &val, sizeof(val), offset));
    TESTX("pread+pwrite(4B) sweep", val++; pwrite(fd, &val, sizeof(val), offset + i * PAGE_SIZE); pread(fd, &val, sizeof(val), offset + i * PAGE_SIZE));
 
    /* TEST("pread+pwrite(4B) loop",  val++; pwrite(fd, &val, sizeof(val), offset); pread(fd, &val, sizeof(val), offset), n / 2, 0); */
    /* TEST("pread+pwrite(4B) sweep", val++; pwrite(fd, &val, sizeof(val), offset + i * PAGE_SIZE); pread(fd, &val, sizeof(val), offset + i * PAGE_SIZE), n / 2, 0); */

    runs = n;
    /* pread(fd, &val, sizeof(val), offset); */
    /* TESTX("pwrite(4B) loop", pwrite(fd, &val, sizeof(val), offset)); */
    /* TESTX("pread(4B) loop", pread(fd, &val, sizeof(val), offset)); */
    TESTX("pwrite(4B) sweep", pwrite(fd, &val, sizeof(val), offset + i * PAGE_SIZE));
    TESTX("pread(4B) sweep", pread(fd, &val, sizeof(val), offset + i * PAGE_SIZE));
    /* printf("mem read: %x\n", val); */


    char test[PAGE_SIZE];

    /* void *src = (void *)test; */

#if 1
    void *src = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    void *dst = mmap(NULL, size,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);
#else
    void *src = malloc(size);
    void *dst = malloc(size);
#endif

    INIT_ARRAY(src, size);
    INIT_ARRAY(dst, size);

    mprotect(src, size, PROT_NONE);
    mprotect(dst, size, PROT_NONE);

    /* ssize_t ret = pwrite(fd, src, PAGE_SIZE, (off_t)dst); */

    TESTX("pwrite(4K)", pwrite(fd, src, PAGE_SIZE, (off_t)dst));
    TESTX("pread(4K)", pread(fd, src, PAGE_SIZE, (off_t)dst));

    TESTX("pwrite(4K) sweep", pwrite(fd, src + i * PAGE_SIZE, PAGE_SIZE, (off_t)dst + i * PAGE_SIZE));
    TESTX("pread(4K) sweep", pread(fd, src + i * PAGE_SIZE, PAGE_SIZE, (off_t)dst  + i * PAGE_SIZE));

    off_t off;
    ssize_t ret;

    TESTX("lseek+read(4B)",
          off = lseek(fd, (uintptr_t)src + i, SEEK_SET);
          assert(off == (off_t)addr);
          ret = __read(fd, &val, sizeof(val));
          assert(ret = sizeof(val));
          );

    TESTX("lseek+write(4B)",
          off = lseek(fd, (uintptr_t)src + i, SEEK_SET);
          assert(off == (off_t)addr);
          ret = __write(fd, &val, sizeof(val));
          assert(ret = sizeof(val));
          );

    val = 0;
    mprotect(taint_page, size, PROT_READ | PROT_WRITE);
    *(uintptr_t *)taint_page = 0x1337;
    mprotect(taint_page, size, PROT_NONE);

    pread(fd, &val, sizeof(val), (uintptr_t)taint_page);
    printf("mem read: %x\n", val);

    val = 0xdeadbeef;
    // write new value
    pwrite(fd, &val, sizeof(val), offset);

    // enable loads and stores to page
    mprotect((uintptr_t *)offset, size, PROT_READ | PROT_WRITE);
    // taint page access will no longer SIGSEGV
    printf("load val: %x\n", *(uintptr_t *)offset);
 
    // enable loads and stores to page
    //    mprotect(taint_page, size, PROT_READ | PROT_WRITE);
    // taint page access will no longer SIGSEGV
    /* printf("load val: %lx\n", *(uintptr_t *)taint_page); */
    close(fd);
    return 0;
}
