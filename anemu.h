#ifndef _ANEMU_H
#define _ANEMU_H

#include "anemu.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <ucontext.h>
#include <assert.h>

#include <r_types.h>
#include <r_asm.h>

#if HAVE_SETRLIMIT
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif

#define SIGNAL SIGTRAP
#define SEGV_FAULT_ADDR (void *)0xdeadbeef
#define RETRY_COUNT 2

#define cpu(reg) (emu.current.uc_mcontext.arm_##reg)

static struct emu {
    ucontext_t original;
    ucontext_t current;
    int        initialized;     /* boolean */
    /* taint_t taint; */
} emu;

/* Internal state */
static struct r_asm_t *rasm;    /* rasm2 diassembler */

/*
 * Signal context structure - contains all info to do with the state
 * before the signal handler was invoked.  Note: only add new entries
 * to the end of the structure.
 */
/* 
struct sigcontext {
    unsigned long trap_no;
    unsigned long error_code;
    unsigned long oldmask;
    unsigned long arm_r0;
    unsigned long arm_r1;
    unsigned long arm_r2;
    unsigned long arm_r3;
    unsigned long arm_r4;
    unsigned long arm_r5;
    unsigned long arm_r6;
    unsigned long arm_r7;
    unsigned long arm_r8;
    unsigned long arm_r9;
    unsigned long arm_r10;
    unsigned long arm_fp;
    unsigned long arm_ip;
    unsigned long arm_sp;
    unsigned long arm_lr;
    unsigned long arm_pc;
    unsigned long arm_cpsr;
    unsigned long fault_address;
};
*/

/* API */

void emu_init();
void emu_start(ucontext_t *ucontext);
void emu_stop();

void emu_handler(int sig, siginfo_t *si, void *ucontext);
void emu_register_handler(void* sig_handler);

int emu_regs_clean();

const char* emu_disas(unsigned int pc);

/* Debugging / Internal only */
int test_c(int arg);
extern int test_asm(int arg);
static int execute_instr();
static void dbg_dump_ucontext(ucontext_t *uc);

#endif  /* _ANEMU_H */
