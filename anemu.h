#ifndef _INCLUDE_ANEMU_H_
#define _INCLUDE_ANEMU_H_

#ifdef ANDROID
/* #include <sys/cdefs.h> */
#include <sys/ucontext.h>
/* #include "ucontext.h" */
#else
#include <ucontext.h>
#endif

/* darm disassembler */
#include <darm.h>

#define SIGNAL SIGTRAP
#define SEGV_FAULT_ADDR (void *)0xdeadbeef
#define UCONTEXT_REG_OFFSET 3   /* skip first 3 fields (trap_no, error_code, oldmask) of uc_mcontext */

#define CPU(reg) (emu.current.uc_mcontext.arm_##reg)

#define EMU(stmt)                                 \
    printf("EMU: %s\n", #stmt);                   \
    stmt;                                         \

#define emu_printf(...) printf("%s: ", __PRETTY_FUNCTION__); printf(__VA_ARGS__)
#define EMU_ENTRY emu_printf("\n")

#define SWITCH_COMMON                                                  \
    case I_INVLD: {                                                    \
        emu_printf("darm unsupported op type\n");                      \
        break;                                                         \
    }                                                                  \
    default:                                                           \
    emu_printf("unhandled instr %s\n", darm_mnemonic_name(d->instr));

typedef struct _cpsr_t {
    uint8_t N;                  /* Negative result */
    uint8_t Z;                  /* Zero result */
    uint8_t C;                  /* Carry from operation */
    uint8_t V;                  /* oVerflowed operation */
} cpsr_t;

#define CPSR_N_BIT 31
#define CPSR_Z_BIT 30
#define CPSR_C_BIT 29
#define CPSR_V_BIT 28

#define CPSR_UPDATE_BITS                                \
    cpsr.N = (CPU(cpsr) >> CPSR_N_BIT) & 1;             \
    cpsr.Z = (CPU(cpsr) >> CPSR_Z_BIT) & 1;             \
    cpsr.C = (CPU(cpsr) >> CPSR_C_BIT) & 1;             \
    cpsr.V = (CPU(cpsr) >> CPSR_V_BIT) & 1;

typedef struct _emu_t {
    ucontext_t current;         /* present process emulated state */
    ucontext_t previous;        /* used for diff-ing two contexts */
    ucontext_t original;        /* process state when trap occured */
    uint8_t    initialized;     /* boolean */
    uint8_t    branched;        /* branch taken? */
    uint32_t  *regs;            /* easy access to ucontext regs */
    /* taint_t taint; */
} emu_t;

/* read/write register by number */
#define RREGN(reg) emu_read_reg(reg)
#define WREGN(reg) *emu_write_reg(reg)
/* read/write register by darm specifier (e.g. Rd, Rm, Rn, Rt) */
#define RREG(reg) emu_read_reg(d->reg)
#define WREG(reg) *emu_write_reg(d->reg)

/* read/write memory */
#define WMEM(addr) *(uint32_t *)(addr)
#define RMEM(addr) WMEM(addr)   /* identical pointer cast */

/* process two operands according to instr type */
#define OP(a, b) emu_dataop(d, a, b)

/*
emulating instr{S} requires saving and restoring CPSR

instructions having S:

ADC, ADD, AND, ASR, BIC, EOR, LSL, LSR, MLA, MOV, MUL, MVN,
ORR, ROR, RRX, RSB, RSC, SBC, SUB,
SMLAL, SMULL, UMLAL, UMULL

formats for S instructions:

<Rd> #<const>
<Rd> <Rm>
<Rd> <Rm> #<shift>
<Rd> <Rm> <type>
<Rd> <Rm>{ <shift>}
<Rd> <Rn> #<const>
<Rd> <Rn> <Rm>
<Rd> <Rn> <Rm> <Ra>
<Rd> <Rn> <Rm> <type>
<Rd> <Rn> <Rm>{ <shift>}
<RdLo> <RdHi> <Rn> <Rm>
*/

#define EMU_FLAGS_RdImm(instr)                                          \
    asm volatile (#instr "s %[Rd], %[imm]\n\t" /* updates flags */      \
                  "mrs %[cpsr], CPSR\n\t"           /* save new cpsr */ \
                  : [Rd] "=r" (WREG(Rd)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [imm] "r" (d->imm) /* input */                      \
                  : "cc" /* clobbers condition codes */                 \
                  );                                                    \
    CPSR_UPDATE_BITS;

#define EMU_FLAGS_RdRm(instr)                                           \
    asm volatile (#instr "s %[Rd], %[Rm]\n\t" /* updates flags */       \
                  "mrs %[cpsr], CPSR\n\t"           /* save new cpsr */ \
                  : [Rd] "=r" (WREG(Rd)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [Rm] "r" (RREG(Rm)) /* input */ \
                  : "cc" /* clobbers condition codes */                 \
                  );                                                    \
    CPSR_UPDATE_BITS;

#define EMU_FLAGS_RdRnImm(instr)                                        \
    asm volatile (#instr "s %[Rd], %[Rn], %[imm]\n\t" /* updates flags */ \
                  "mrs %[cpsr], CPSR\n\t"           /* save new cpsr */ \
                  : [Rd] "=r" (WREG(Rd)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [Rn] "r" (RREG(Rn)), [imm] "r" (d->imm) /* input */ \
                  : "cc" /* clobbers condition codes */                 \
                  );                                                    \
    CPSR_UPDATE_BITS;

#define EMU_FLAGS_RdRnRm(instr)                                         \
    asm volatile (#instr "s %[Rd], %[Rn], %[Rm]\n\t" /* updates flags */ \
                  "mrs %[cpsr], CPSR\n\t"           /* save new cpsr */ \
                  : [Rd] "=r" (WREG(Rd)), [cpsr] "=r" (CPU(cpsr)) /* output */ \
                  : [Rn] "r" (RREG(Rn)), [Rm] "r" (RREG(Rm)) /* input */ \
                  : "cc" /* clobbers condition codes */                 \
                  );                                                    \
    CPSR_UPDATE_BITS;

/* switch case helper for EMU_FLAGS_* */
#define CASE(instr, handler) case I_##instr: { EMU_FLAGS_##handler(instr); break; }

#define BitCount(x) __builtin_popcount(x)
#define TrailingZerosCount(x) __builtin_ctz(x)
#define LeadingZerosCount(x) __builtin_clz(x)

#define LSL(val, shift) (val << shift)
#define LSR(val, shift) (val >> shift)
#define ASR(val, shift) (val  / shift) /* expensive, need better alternative */
#define ROR(val, rotate) (((val) >> (rotate)) | ((val) << (32 - (rotate))))

#define SIGCONTEXT_REG_COUNT 21
static const char *sigcontext_names[] = {"trap_no", "error_code", "oldmask",
                                         "r0", "r1", "r2", "r3", "r4", "r5",
                                         "r6", "r7", "r8", "r9", "r10",
                                         "fp", "ip", "sp", "lr", "pc", "cpsr",
                                         "fault_address"};

/* Internal state */
emu_t emu;                      /* emulator state */
cpsr_t cpsr;                    /* cpsr NZCV flags */
darm_t *darm;                   /* darm  disassembler */

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

void emu_init(ucontext_t *ucontext);
void emu_start();
void emu_stop();
uint8_t emu_stop_trigger();

void emu_handler(int sig, siginfo_t *si, void *ucontext);
void emu_register_handler(void* sig_handler);

int emu_regs_clean();

extern const char* emu_disas_ref(unsigned int pc);
const darm_t* emu_disas(unsigned int pc);

void emu_type_arith_shift(const darm_t * d);
void emu_type_arith_imm(const darm_t * d);
void emu_type_branch_syscall(const darm_t * d);
void emu_type_branch_misc(const darm_t * d);
void emu_type_move_imm(const darm_t * d);
void emu_type_cmp_imm(const darm_t * d);
void emu_type_cmp_op(const darm_t * d);
void emu_type_opless(const darm_t * d);
void emu_type_dst_src(const darm_t * d);

inline uint32_t emu_dataop(const darm_t *d, const uint32_t a, const uint32_t b);
inline uint32_t emu_regshift(const darm_t *d);

/* Debugging / Internal only */
int test_c(int arg);
extern int test_asm(int arg);
static int execute_instr();
static void dbg_dump_ucontext(ucontext_t *uc);
static void emu_dump();
static void emu_dump_diff();
void armv7_dump(const darm_t *d);
static inline uint32_t emu_read_reg(darm_reg_t reg);
static inline uint32_t *emu_write_reg(darm_reg_t reg);

#endif  /* _INCLUDE_ANEMU_H_ */
