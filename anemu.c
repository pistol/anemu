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

/* #define TRAP_BKPT   1 */
/* #define TRAP_TRACE  2 */
/* #define TRAP_BRANCH 3 */
/* #define TRAP_HWBKPT 4 */

#if HAVE_SETRLIMIT
# include <sys/types.h>
# include <sys/time.h>
# include <sys/resource.h>
#endif

#define SIGNAL SIGPROF
/* #define SIGNAL SIGSEGV */
#define SEGV_FAULT_ADDR (void *)0xdeadbeef
#define SIGJMP_REG_COUNT 10
#define RETRY_COUNT 2

#define cpu(reg) (emu.current.uc_mcontext.arm_##reg)

static struct emu {
ucontext_t original;
ucontext_t current;
    int        initialized;     /* boolean */
    /* taint_t taint; */
} emu;

static struct r_asm_t *rasm;    /* rasm2 diassembler */

void dbg_dump_env(sigjmp_buf env) {
    static const char *sigjmp_buf_names[] = {"v1", "v2", "v3", "v4", "v5", "v6", 
                                             "sl", "fp", "sp", "lr"};

    int i;
    for (i = 0; i < SIGJMP_REG_COUNT; i++) {
        printf("dbg: %s = 0x%0x\n", sigjmp_buf_names[i], env->__jmpbuf[i]);
    }
}

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

#define SIGCONTEXT_REG_COUNT 21

void dbg_dump_ucontext(ucontext_t *uc) {
    static const char *sigcontext_names[] = {"trap_no", "error_code", "oldmask",
                                             "r0", "r1", "r2", "r3", "r4", "r5",
                                             "r6", "r7", "r8", "r9", "r10",
                                             "fp", "ip", "sp", "lr", "pc", "cpsr",
                                             "fault_address"};
    static int i;
    for (i = 0; i < SIGCONTEXT_REG_COUNT; i++) {
        printf("dbg: %-14s = 0x%0lx\n", 
               sigcontext_names[i],
               ((unsigned long *)&uc->uc_mcontext)[i]);
    }
}

int regs_clean() {
    return 0;                   /* TODO */
}

void emu_init() {
    if (emu.initialized == 1) return;

    printf("emu_init : initializing rasm2 diassembler ...\n");

    /* rasm2 configuration defaults */
    static const char arch[]    = {"arm"};   /* ARM ISA */
    static const int bits       = 32;        /* A32 instructions only */
    static const int big_endian = 0;         /* ARMv7 is little endian */

    rasm = r_asm_new();
    assert(rasm != NULL);
    /* R_API int r_asm_setup(RAsm *a, const char *arch, int bits, int big_endian); */
    r_asm_setup(rasm, arch, bits, big_endian);
    emu.initialized = 1;
    printf("emu_init : finished\n");
}

const char* disas(unsigned int pc) {
    /* printf("emu: %0lx: %0x\n", cpu(pc), *(unsigned int *)cpu(pc)); // if all else fails */
    static RAsmOp rop;

    static const int len = 4;         /* diassemble 4 bytes (A32) */
    r_asm_set_pc(rasm, pc);
    r_asm_disassemble(rasm, &rop, (const unsigned char *)pc, len);
    printf("disas: %x %08x %s\n", pc, *(const unsigned int *)pc, rop.buf_asm);

    return rop.buf_asm;
}

void emu_start(ucontext_t *ucontext) {
    printf("emu_start: saving original ucontext ...\n");
    dbg_dump_ucontext(ucontext);
    emu.current = emu.original = *ucontext;
    printf("emu_start: starting emulation ...\n");
    
    /* int n = 7; */
    /* printf("emu_start: emulating %d opcodes ...\n", n); */
    /* while(n-- && !regs_clean) { */
    
    /* const char special[] = {"mov pc, lr"}; */
    static const char special[] = {"bkpt 0x0002"};
    const char *assembly;
    while(1) {
        // 1. decode instr
        assembly = disas(cpu(pc));
        if (strncmp(assembly, special, strlen(special)) == 0) {
            printf("emu_start: special op %s being skipped\n", special);
            cpu(pc) += 4;
            break;
        }
        // 2. emu instr
        /* *(unsigned int *)(cpu(fp) - 12) = 0xbadcab1e; */
        cpu(pc) += 4;
    }
    printf("emu_start: finished\n");
}

void emu_stop() {
    printf("emu_stop : stopping emu...\n");

    printf("emu_stop : resuming exec pc old = 0x%0lx new = 0x%0lx\n", 
           emu.original.uc_mcontext.arm_pc, 
           emu.current.uc_mcontext.arm_pc);
    /* mainloop->__jmpbuf[9]); */

    /* siglongjmp(mainloop, ++count); */
    setcontext((const ucontext_t *)&emu.current);
    printf("emu_stop : this is never executed\n");
}

/* SIGTRAP handler used for single-stepping */
/* Mismatch breakpoint will re-trigger trap on each executed instruction */
static void ss_handler(int sig, siginfo_t *si, void *ucontext)
{
    printf("ss_handler: SIG %d with TRAP code: %d pc: 0x%lx addr: 0x%x\n", 
           sig, 
           si->si_code, 
           (*(ucontext_t *)ucontext).uc_mcontext.arm_pc, 
           (int) si->si_addr);

    emu_init();                 /* one time emu state initialization */
    emu_start((ucontext_t *)ucontext);
    emu_stop();
}

int execute_instr();

// Setup emulation handler.
void register_handler(void* sig_handler)
{
#if HAVE_SETRLIMIT
    /* Be recursion friendly */
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = 0x100000; /* 1 MB */
    setrlimit (RLIMIT_STACK, &rl);
#endif

    /* 1. setup alternate stack for handler */
    stack_t ss;
    static char stack[SIGSTKSZ];

    /* ss.ss_sp = malloc(SIGSTKSZ); */
    ss.ss_sp = stack;
    if (ss.ss_sp == NULL)
        /* Handle error */;
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) {
        /* Handle error */;
        perror("sigaltstack"); 
        exit(1);
    }

    /* 2. setup signal handler */
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sig_handler;
    /* sigaction (SIGSEGV, &sa, NULL); */
    sigaction (SIGPROF, &sa, NULL);
    sigaction (SIGTRAP, &sa, NULL);
}

extern int test(int a);

int test2(int arg) {
    int a = test(arg);
    printf("test a = %x\n", a);
        
    return a;
}

int main(int argc, char ** argv)
{
    register_handler(&ss_handler);

    /* execute_instr(); */
    int a = test2(0x1336);
    printf("test a = %x\n", a);
    
    return 0;
}

/* int __attribute__((aligned(0x1000))) execute_instr() */
int execute_instr()
{
    unsigned int a = 0x1337;

    asm volatile (
                  ".balign 0x1000,0\n\t"
                  /* "bkpt #1\n\t" */
                  "mov  r0, r0\n\t"
                  "movw r1, #0x6699\n\t"
                  "movt %[a], #0xdead\n\t"
                  "add  %[a], %[a], #1\n\t"
                  /* "ldr  %[a], [fp, #-12]" */
                  : [a] "=r" (a)     /* output */
                  : "0" (a)          /* input */
                  : "cc", "r0", "r1" /* clobbers */
                  );
    
    printf("a = 0x%x\n", a);
    /* asm volatile ("bkpt"); */
    printf("execute_instr: finished\n");
    /* assert(a != (0x1336 + RETRY_COUNT)); */
    printf("haxx0red!\n");

    return 0;
}
