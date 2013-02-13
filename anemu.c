#include "anemu.h"

int main(int argc, char ** argv) {
    emu_register_handler(&emu_handler);
    execute_instr();

    return 0;
}

/* int __attribute__((aligned(0x1000))) execute_instr() */
/* Simulate a native binary executing */
int execute_instr() {
    int val = 0x1337;

    int ret = test_asm(val);
    printf("ret = %x\n", ret);

    printf("execute_instr: finished\n");

    return ret;
}

int test_c(int arg) {
    int ret = test_asm(arg);
    printf("test_c ret = %x\n", ret);
        
    return ret;
}

int emu_regs_clean() {
    return 0;                   /* TODO */
}

/* SIGTRAP handler used for single-stepping */
void emu_handler(int sig, siginfo_t *si, void *ucontext) {
    printf("emu_handler: SIG %d with TRAP code: %d pc: 0x%lx addr: 0x%x\n", 
           sig, 
           si->si_code, 
           (*(ucontext_t *)ucontext).uc_mcontext.arm_pc, 
           (int) si->si_addr);

    emu_init();                 /* one time emu state initialization */
    emu_start((ucontext_t *)ucontext);
    emu_stop();
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

/* inline unsigned long emu_reg_value(const char* reg) { */
/*     return 0; */
/* } */

#define emu_reg_value(reg) cpu(reg)

/* inline void emu_reg_set(const char* reg, unsigned long val) { */
/*     cpu(*reg) = val; */
/* } */

#define emu_reg_set(reg, val) cpu(reg) = (val)

void emu_mathop() {
    /* const char Rd[] = "r0"; */
    /* const char Rn[] = "r0"; */
    /* const int  imm  = 0x1; */

    /* emu_reg_set(r0, emu_reg_value(r0) + imm); */
    /* int val = emu_reg_value(r0) + imm; */
    /* cpu(r0) = val; */
    /* emu_reg_set(r0, val); */
}

void emu_start(ucontext_t *ucontext) {
    printf("emu_start: saving original ucontext ...\n");
    dbg_dump_ucontext(ucontext);
    emu.current = emu.original = *ucontext;
    printf("emu_start: starting emulation ...\n");
    
    int n = 6;
    /* printf("emu_start: emulating %d opcodes ...\n", n); */
    /* while(n-- && !regs_clean) { */
    
    /* const char special[] = {"mov pc, lr"}; */
    static const char special[] = {"bkpt 0x0002"};
    const char *assembly;
    while(1) {
        // TODO: check if Thumb mode

        
        // 1. decode instr
        assembly = emu_disas(cpu(pc));
        emu_darm(cpu(pc));      /* testin darm */
        if (strncmp(assembly, special, strlen(special)) == 0) {
            printf("emu_start: special op %s being skipped\n", special);
            cpu(pc) += 4;
            break;
        }

        // 2. emu instr
        /* *(unsigned int *)(cpu(fp) - 12) = 0xbadcab1e; */

#define OT_MATH 0x1
        int op_type = OT_MATH;
        switch(op_type) {
        case OT_MATH:
            emu_mathop();
            break;
        default:
            printf("Unknown op type\n");
        }

        cpu(pc) += 4;
    }
    printf("emu_start: finished\n");
}

void emu_stop() {
    printf("emu_stop : resuming exec pc old = 0x%0lx new = 0x%0lx\n", 
           emu.original.uc_mcontext.arm_pc, 
           emu.current.uc_mcontext.arm_pc);

    setcontext((const ucontext_t *)&emu.current); /* never returns */
}

/* Setup emulation handler. */
void emu_register_handler(void* sig_handler) {
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

const char* emu_disas(unsigned int pc) {
    /* printf("emu: %0lx: %0x\n", cpu(pc), *(unsigned int *)cpu(pc)); // if all else fails */
    static RAsmOp rop;

    static const int len = 4;         /* diassemble 4 bytes (A32) */
    r_asm_set_pc(rasm, pc);
    r_asm_disassemble(rasm, &rop, (const unsigned char *)pc, len);
    printf("disas: %x %08x %s\n", pc, *(const unsigned int *)pc, rop.buf_asm);

    return rop.buf_asm;
}

void emu_darm(unsigned int pc) {
    static struct _darm darm;
    const unsigned int ins = *(const unsigned int *)pc;
    if (darm_dis(&darm, ins)) {
        printf("darm : %x %08x <invalid instruction>\n", pc, ins);
    } else {
        printf("darm : %x %08x %s\n", pc, ins, darm_str(&darm, pc));
    }

    return;
}

/* Debugging */

#define SIGCONTEXT_REG_COUNT 21
static void dbg_dump_ucontext(ucontext_t *uc) {
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
