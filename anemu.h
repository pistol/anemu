#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {  // only need to export C interface if
              // used by C++ source code
#endif

#define MARKER_START_VAL    0x100
#define MARKER_STOP_VAL     0x200

#define ASM_MARKER(val)  asm volatile("bkpt " #val)

// #define EMU_MARKER_START ASM_MARKER(MARKER_START_VAL)
// #define EMU_MARKER_STOP  ASM_MARKER(MARKER_STOP_VAL)

#define EMU_MARKER_START asm volatile("bkpt 0x100")
#define EMU_MARKER_STOP  asm volatile("bkpt 0x200")

#define unlikely(x) __builtin_expect(!!(x), 0)

/* Public API */
void
emu_init_handler(int sig,
                 void (*handler)(int, siginfo_t *, void *),
                 void *stack,
                 size_t stack_size);

void emu_handler_trap(int sig, siginfo_t *si, void *uc);
void emu_handler_segv(int sig, siginfo_t *si, void *uc);

/* Hooks */
void emu_hook_thread_entry(void *arg);
void emu_hook_pthread_internal_free(void *arg);
void emu_hook_bionic_clone_entry();
void emu_hook_bionic_atfork_run_child(void *arg);
void emu_hook_exit_thread(int ret);
void emu_hook_Zygote_forkAndSpecializeCommon(void *arg);

/* Trampolines */
int emu_trampoline_read(int fd, void *buf, size_t count);
int emu_trampoline_write(int fd, void *buf, size_t count);

/* check if current pid / app is targeted for emulation */
uint32_t emu_target();

/* emulate starting at a given address (e.g. function) */
uint32_t emu_function(void (*fun)());

void emu_get_taint_mem(uint32_t addr);
void emu_set_taint_mem(uint32_t addr, uint32_t tag);
void emu_set_taint_array(uint32_t addr, uint32_t tag, uint32_t length);
uint32_t emu_get_taint_array(uint32_t addr, uint32_t length);

bool emu_running();
uint8_t emu_disabled();
uint32_t emu_get_taint_pages();
int32_t emu_get_trace_fd();
int emu_initialized();

void emu_memcpy_safe(void *dest, const void *src, size_t n);

/* Debugging */
void gdb_wait();

#ifdef __cplusplus
}
#endif

#endif  /* _INCLUDE_ANEMU_H_ */
