#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <time.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#define MARKER_START_VAL    32
#define MARKER_STOP_VAL     0xfdee /* udf 0xfdee : KGDB_BREAKINST */

/* Lifted from $KERNEL/arch/arm/kernel/ptrace.c */
/*
 * Breakpoint SWI instruction: SWI &9F0001
 */
#define BREAKINST_ARM_SWI	  0xef9f0001

/*
 * New breakpoints - use an undefined instruction.  The ARM architecture
 * reference manual guarantees that the following instruction space
 * will produce an undefined instruction exception on all CPUs:
 *
 *  ARM:   xxxx 0111 1111 xxxx xxxx xxxx 1111 xxxx
 *  Thumb: 1101 1110 xxxx xxxx
 */
#define BREAKINST_ARM	  0xe7f001f0 // udf #16 - SIGTRAP

#define GDB_BREAKINST   BREAKINST_ARM_SWI // SIGTRAP
#define KGDB_BREAKINST  0xe7ffdefe        // udf #0xfdee - SIGILL

/* #define MARKER_START  GDB_BREAKINST */
#define MARKER_START  BREAKINST_ARM
#define MARKER_STOP  KGDB_BREAKINST
#define MARKER_BYPASS GDB_BREAKINST

#define ASM(opcode)      asm volatile(".inst " __stringify(opcode))

#define EMU_MARKER_START ASM(MARKER_START)
#define EMU_MARKER_STOP  ASM(MARKER_STOP)
#define EMU_MARKER_BYPASS ASM(MARKER_BYPASS)

#define unlikely(x) __builtin_expect(!!(x), 0)

/* Lifted from $KERNEL/include/linux/stringify.h */
/* Indirect stringification.  Doing two levels allows the parameter to be a
 * macro itself.  For example, compile with -DFOO=bar, __stringify(FOO)
 * converts to "bar".
 */

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)

/* Benchmarking */
#ifdef EMU_BENCH
int64_t __tick_start, __tick_end;
#define M(x)                                              \
    time_ns(&__tick_start);                               \
    x;                                                    \
    time_ns(&__tick_end);                                               \
    printf("[*] %s %6"PRId64" cycles.\n", #x, __tick_end - __tick_start);
#else
#define M(x) x
#endif

#include <sys/cdefs.h>
__BEGIN_DECLS
/* Public API */

/* syscalls used by trampolines */
extern ssize_t __read(int, void *, size_t);
extern ssize_t __write(int, void *, size_t);

/* Hooks */
void emu_hook_thread_entry(void *arg);
void emu_hook_pthread_internal_free(void *arg);
void emu_hook_bionic_clone_entry();
void emu_hook_bionic_atfork_run_child(void *arg);
void emu_hook_exit_thread(int ret);
void emu_hook_Zygote_forkAndSpecializeCommon(void *arg);

/* Trampolines */
ssize_t emu_trampoline_read(int fd, void *buf, size_t count);
ssize_t emu_trampoline_write(int fd, void *buf, size_t count);

/* check if current pid / app is targeted for emulation */
uint32_t emu_target();
void emu_set_target(pid_t pid);
void emu_set_standalone(bool status);
bool emu_set_protect(bool state);
void emu_mprotect_mem(bool state);

/* emulate starting at a given address (e.g. function) */
uint32_t emu_function(void (*fun)());

// TODO: change arguments to (addr, length, tag) for consistency with get
void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length);
// uint32_t emu_get_taint_array(uint32_t addr, uint32_t length);
uint32_t emu_get_taintpages();

uint32_t emu_dump_taintmaps();
uint32_t emu_dump_taintpages();

void emu_reset_stats();

void emu_mprotect_mem(bool state);
#define emu_protect_mem()   emu_mprotect_mem(true)
#define emu_unprotect_mem() emu_mprotect_mem(false)

bool emu_running();
uint8_t emu_disabled();
int32_t emu_get_trace_fd();
int emu_initialized();
void emu_dump_stats();

/* Debugging */
void gdb_wait();
// double time_ms();
// uint64_t getticks();
int time_ns(struct timespec *res);
int64_t diff_ns(struct timespec *start,
                struct timespec *end);
int64_t ns_to_cycles(int64_t ns);

const char *get_signame(int sig);
int __log_print(int prio, const char *tag, const char *fmt, ...);

#define LOG_TAG "anemu"
#define lprintf(...) __log_print(0, LOG_TAG, __VA_ARGS__)

__END_DECLS

#endif  /* _INCLUDE_ANEMU_H_ */
