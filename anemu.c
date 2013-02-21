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

    /* init darm */
    printf("emu_init : initializing darm diassembler ...\n");
    darm = malloc(sizeof(darm_t));

    emu.initialized = 1;
    printf("emu_init : finished\n");
}

void emu_op_alu(const darm_t * d) {
    switch(d->instr) {
    case I_ADD: {
        EMU(Rd, Rn, +, imm);
        break;
    }
    case I_SUB: {
        EMU(Rd, Rn, -, imm);
        break;
    }
    default:
        printf("emu_op_alu: unsupported op %d\n", d->instr);
    }
}

void emu_op_move(const darm_t * d) {
    printf("emu_op_move: not implemented\n");
}

void emu_type_arith_shift(const darm_t * d) {

    switch(d->instr) {
    case I_ADD:
    case I_ADC:
    case I_SUB: {
        emu_op_alu(d);
        break;
    }
    case I_IVLD: {
        printf("emu_type_arith_shift: darm unsupported op type\n");
        break;
    }
    default:
        printf("emu_type_arith_shift: unhandled instr %d\n", d->instr);
    }
}

void emu_type_arith_imm(const darm_t * d) {
    printf("emu_type_arith_imm:\n");
    switch(d->instr) {
    case I_ADD: {
        EMU(Rd, Rn, +, imm);
        break;
    }
    case I_ADC: {
        REG(d->Rd) = REG(d->Rn) + d->imm + cpsr.C;
        break;
    }
    case I_SUB: {
        EMU(Rd, Rn, -, imm);
        break;
    }
    case I_IVLD: {
        printf("emu_type_arith_imm: darm unsupported op type\n");
        break;
    }
    default:
        printf("emu_type_arith_imm: unhandled instr %d\n", d->instr);
    }
}

void emu_type_branch_syscall(const darm_t * d) {
    printf("emu_type_branch_syscall: not implemented\n");
}

void emu_type_branch_misc(const darm_t * d) {
    printf("emu_type_branch_misc: not implemented\n");
}

void emu_type_move_imm(const darm_t * d) {
    printf("emu_type_move_imm:\n");
    switch((uint32_t) d->instr) {
    case I_MOV: {
        REG(d->Rd) = d->imm;
        break;
    }
    case I_MOVT: {
        REG(d->Rd) = (REG(d->Rd) & 0x0000ffff) | (d->imm << 16);
        break;
    }
    case I_MOVW: {
        REG(d->Rd) = (REG(d->Rd) & 0xffff0000) | (d->imm);
        break;
    }
    case I_IVLD: {
        printf("emu_type_move_imm: darm unsupported op type\n");
        break;
    }
    default:
        printf("emu_type_move_imm: unhandled instr %d\n", d->instr);

    }
}

void emu_type_cmp_op(const darm_t * d) {
    printf("emu_type_cmp_op: not implemented\n");
}

void emu_type_cmp_imm(const darm_t * d) {
    printf("emu_type_cmp_imm: not implemented\n");
}

void emu_type_opless(const darm_t * d) {
    printf("emu_type_opless: not implemented\n");
}

void emu_start(ucontext_t *ucontext) {
    printf("emu_start: saving original ucontext ...\n");
    dbg_dump_ucontext(ucontext);
    emu.current = emu.original = *ucontext;
    printf("emu_start: starting emulation ...\n");
    
    cpu(pc) += 4;           /* skip first instr (bkpt) */

    static const char *assembly;
    static const darm_t *d;
    while(1) {
        // TODO: check if Thumb mode

        // 1. decode instr
        assembly = emu_disas(cpu(pc)); /* rasm2 with libopcodes backend */
        d = emu_darm(cpu(pc));  /* d */

        /* char * s = d->S ? "S" : ""; */
        printf("darm : cond: %x, S: %d, Rd: %2d, Rm: %2d, Rn: %2d, imm: 0x%x, Rs: %2d\n",
               d->cond, d->S,
               d->Rd, d->Rn, d->Rm, d->imm, d->Rs);

        if (emu_stop_trigger(assembly)) break;

        emu_dump();

        // 2. emu instr by type
        switch(d->instr_type) {
        case T_ARITH_SHIFT: {
            emu_type_arith_shift(d);
            break;
        }
        case T_ARITH_IMM: {
            emu_type_arith_imm(d);
            break;
        }
        case T_BRNCHSC: {
            emu_type_branch_syscall(d);
            break;
        }
        case T_BRNCHMISC: {
            emu_type_branch_misc(d);
            break;
        }
        case T_MOV_IMM: {
            emu_type_move_imm(d);
            break;
        }
        case T_CMP_IMM: {
            emu_type_cmp_imm(d);
            break;
        }
        case T_CMP_OP: {
            emu_type_cmp_op(d);
            break;
        }
        case T_OPLESS: {
            emu_type_opless(d);
            break;
        }
        default:
            printf("emu_start: unhandled type %d\n", d->type);
        }

        cpu(pc) += 4;
        emu_dump();
        printf("\n");
    }
    printf("emu_start: finished\n");
}

void emu_stop() {
    printf("emu_stop : resuming exec pc old = 0x%0lx new = 0x%0lx\n", 
           emu.original.uc_mcontext.arm_pc, 
           emu.current.uc_mcontext.arm_pc);

    setcontext((const ucontext_t *)&emu.current); /* never returns */
}

int emu_stop_trigger(const char *assembly) {
    static const char special[] = {"bkpt 0x0002"};
    /* static const char special[] = {"mov pc, lr"}; */

    if (strncmp(assembly, special, strlen(special)) == 0) {
        printf("emu_stop_trigger: special op %s being skipped\n", special);
        cpu(pc) += 4;
        return 1;
    }
    return 0;
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
    if (ss.ss_sp == NULL) {
        perror("ss.ss_sp == NULL");
        exit(1);
    }
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) == -1) {
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

const darm_t* emu_darm(unsigned int pc) {
    const unsigned int ins = *(const unsigned int *)pc;

    if (armv7_disassemble(darm, ins)) {
        printf("darm : %x %08x <invalid instruction>\n", pc, ins);
    } else {
        /* printf("d : %x %08x %s\n", pc, ins, darm_str(d, pc)); */
        printf("darm : %x %08x %s\n", pc, ins, "[darm_str not implemented]");
    }

    return darm;
}

/* map register number (0-15) to ucontext reg entry (r0-r10, fp, ip, sp, lr pc) */
/*
static inline unsigned long REG(int reg) {
    assert(reg >= 0 && reg <= 15);
    return ((unsigned long)uc->uc_mcontext)[reg + UCONTEXT_REG_OFFSET]);
}

static inline unsigned long * WREG(int reg) {
    assert(reg >= 0 && reg <= 15);
    return ((unsigned long *)&uc->uc_mcontext)[reg + UCONTEXT_REG_OFFSET]);
}
*/

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

static void emu_dump() {
    dbg_dump_ucontext(&emu.current);
}
