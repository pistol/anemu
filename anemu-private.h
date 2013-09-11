#ifndef _INCLUDE_ANEMU_PRIVATE_H_
#define _INCLUDE_ANEMU_PRIVATE_H_

#include "anemu.h"

#ifdef ANDROID
/* #include <sys/cdefs.h> */
#include <sys/ucontext.h>
#include <android/log.h>
#define LOG_TAG "anemu"
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define printf LOGI
#else
#include <ucontext.h>
#endif

/* darm disassembler */
#include <darm.h>

/* TODO: guard based on NDEBUG or DEBUG */
#define assert(x) if (!(x)) { emu_abort("ASSERTION (%s) FAILED in %s line %d", #x, __FILE__, __LINE__); }

#define UNUSED __attribute__((unused))

#define SIGNAL SIGTRAP
#define SEGV_FAULT_ADDR (void *)0xdeadbeef
#define UCONTEXT_REG_OFFSET 3   /* skip first 3 fields (trap_no, error_code, oldmask) of uc_mcontext */

#define CPU(reg) (emu.current.uc_mcontext.arm_##reg)

#define EMU(stmt)                                 \
    printf("EMU: %s\n", #stmt);                   \
    stmt;                                         \

#define emu_printf(...) printf("%s: ", __PRETTY_FUNCTION__); printf(__VA_ARGS__)
#define EMU_ENTRY emu_printf("\n")
#define emu_abort(...) emu_printf(__VA_ARGS__);             \
    printf("\n");                                           \
    printf("dumping taintmaps:\n");                         \
    emu_dump_taintmaps();                                   \
    printf("\n");                                           \
    printf("*********************************\n");          \
    printf("FATAL ERROR! ABORTING EMU!\n");                 \
    printf("*********************************\n\n");        \
    exit(1);

#define SWITCH_COMMON                                                  \
    case I_INVLD: {                                                    \
        emu_abort("darm invalid op type\n");                           \
        break;                                                         \
    }                                                                  \
    default:                                                           \
    emu_abort("unhandled instr %s\n", darm_mnemonic_name(d->instr));

/*
CPSR bits
N: Negative result
Z: Zero result
C: Carry from operation
V: oVerflowed operation

I: IRQ
T: Thumb mode
*/

#define CPSR_N ((CPU(cpsr) & PSR_N_BIT) >> 31)
#define CPSR_Z ((CPU(cpsr) & PSR_Z_BIT) >> 30)
#define CPSR_C ((CPU(cpsr) & PSR_C_BIT) >> 29)
#define CPSR_V ((CPU(cpsr) & PSR_V_BIT) >> 28)
#define CPSR_I ((CPU(cpsr) & PSR_I_BIT) >>  7)
#define CPSR_T ((CPU(cpsr) & PSR_T_BIT) >>  5)

/* update NZCV bits given a temp CPSR value (from MRS) */
#define CPSR_UPDATE(temp) (CPU(cpsr) = (CPU(cpsr) & ~(b1111 << 28)) | (temp & (b1111 << 28)))

#define MAX_MAPS 4096           /* number of memory map entries */
#define MAX_TAINTMAPS 2         /* libs + stack (heap part of libs) */
#define MAX_TAINTPAGES 32       /* number of distinct tainted pages */
#define TAINTMAP_LIB   0        /* taintmap index for libs */
#define TAINTMAP_STACK 1        /* taintmap index for stack */

typedef struct _map_t {
    uint32_t vm_start;
    uint32_t vm_end;
    uint32_t pgoff;
    uint32_t major, minor;
    char r, w, x, s;
    uint32_t ino;
    char name[256];
    uint32_t pages;
} map_t;

#define N_REGS 16               /* r0-r15 */

typedef struct _taintmap_t {
    uint32_t *data;             /* mmap-ed data */
    uint32_t  start;            /* address range start */
    uint32_t  end;              /* address range end */
    uint32_t  bytes;            /* (end - start) bytes */
} taintmap_t;

typedef struct _emu_t {
    ucontext_t current;         /* present process emulated state */
    ucontext_t previous;        /* used for diff-ing two contexts */
    ucontext_t original;        /* process state when trap occured */
    uint8_t    initialized;     /* boolean */
    uint8_t    branched;        /* branch taken? */
    uint32_t  *regs;            /* easy access to ucontext regs */
    uint16_t   nr_maps;
    map_t      maps[MAX_MAPS];
    taintinfo_t *tinfo;          /* trap tainted data (addr + tag) */
    uint32_t   taintreg[N_REGS]; /* taint storage for regs */
    taintmap_t taintmaps[MAX_TAINTMAPS]; /* taint storage for memory */
    uint32_t   taintpages[MAX_TAINTPAGES]; /* unique taint pages */
    bool      *enabled;          /* shared VM enabled flag */
    uint32_t   handled_instr;     /* number of ops seen so far */
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
#define WMEMB(addr, data) WMEM(addr) = (RMEM(addr) & ~instr_mask(d->instr)) | (data & instr_mask(d->instr))
#define RMEMB(addr) (RMEM(addr) & instr_mask(d->instr))

/* taint register by darm specifier */
#define RTREG(reg) emu_get_taint_reg(d->reg)
#define RTREGN(reg) emu_get_taint_reg(reg)

#define WTREG1(dest, a)    emu_set_taint_reg(d->dest, emu_get_taint_reg(d->a))
#define WTREG2(dest, a, b) emu_set_taint_reg(d->dest, emu_get_taint_reg(d->a) & emu_get_taint_reg(d->b))
#define WTREG(dest, tag)   emu_set_taint_reg(d->dest, tag)
#define WTREGN(dest, tag)  emu_set_taint_reg(dest, tag)

/* taint memory */
#define RTMEM(addr)      emu_get_taint_mem(addr)
#define WTMEM(addr, tag) emu_set_taint_mem(addr, tag)

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

/* IS: imm / shift */
#define ASM_RI(instr, R1, IS)                                           \
    uint32_t temp;                                                      \
    asm volatile (#instr "s %[reg1], %[imm]\n"             /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (temp)    /* output */ \
                  : [imm] "r"   (d->IS)         /* input */             \
                  : "cc"                        /* clobbers condition codes */ \
                  );                                                    \
    CPSR_UPDATE(temp);

#define ASM_RR(instr, R1, R2)                                           \
    uint32_t temp;                                                      \
    asm volatile (#instr "s %[reg1], %[reg2]\n"            /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (temp)    /* output */ \
                  : [reg2] "r"  (RREG(R2))      /* input */             \
                  : "cc"                        /* clobbers condition codes */ \
                  );                                                    \
    CPSR_UPDATE(temp);

#define ASM_RRI(instr, R1, R2, IS)                                      \
    uint32_t temp;                                                      \
    asm volatile (#instr "s %[reg1], %[reg2], %[imm]\n"    /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [reg1] "=r" (WREG(R1)), [cpsr] "=r" (temp)    /* output */ \
                  : [reg2] "r"  (RREG(R2)), [imm]  "r"  (d->IS)    /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );                                                    \
    CPSR_UPDATE(temp);

#define ASM_RI_CMP(instr, R1, IS)                                       \
    uint32_t temp;                                                      \
    asm volatile (#instr "  %[reg1], %[imm]\n"             /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [cpsr] "=r" (temp)                     /* output */ \
                  : [reg1] "r"  (RREG(R1)), [imm] "r"  (d->IS)     /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );                                                    \
    CPSR_UPDATE(temp);

#define ASM_RR_CMP(instr, R1, R2)                                       \
    uint32_t temp;                                                      \
    asm volatile (#instr "  %[reg1], %[reg2]\n"            /* updates flags */ \
                  "mrs %[cpsr], cpsr\n"                    /* save new cpsr */ \
                  : [cpsr] "=r" (temp)                     /* output */ \
                  : [reg1] "r"  (RREG(R1)), [reg2] "r"  (RREG(R2)) /* input */ \
                  : "cc"                        /* clobbers condition codes */ \
                  );                                                    \
    CPSR_UPDATE(temp);

/* switch case helper for ASM */
#define CASE_RR( instr, R1, R2)      case I_##instr: { ASM_RR (instr, R1, R2);      break; }
#define CASE_RRI(instr, R1, R2, imm) case I_##instr: { ASM_RRI(instr, R1, R2, imm); break; }

#define BitCount(x)           __builtin_popcount(x)
#define TrailingZerosCount(x) __builtin_ctz(x)
#define LeadingZerosCount(x)  __builtin_clz(x)
#define BitCheck(x, pos)      ((x) & (1 << (pos)))

#define Align(x,a)            __ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)  (((x)+(mask))&~(mask))

#define LSL(val, shift) (val << shift)
#define LSR(val, shift) (val >> shift)
#define ASR(val, shift) (val  / shift) /* expensive, need better alternative */
#define ROR(val, rotate) (((val) >> (rotate)) | ((val) << (32 - (rotate))))

#define ISB(option) asm volatile ("isb " #option : : : "memory")
#define DSB(option) asm volatile ("dsb " #option : : : "memory")
#define DMB(option) asm volatile ("dmb " #option : : : "memory")
#define SVC(option) asm volatile ("svc " #option)

#define PLD(regname) asm volatile("pld [%[reg]]" :: [reg] "r" (d->regname));

#define MARKER_START_VAL    0
#define MARKER_STOP_VAL  1337

#define SIGCONTEXT_REG_COUNT 21
static const char *sigcontext_names[] = {"trap_no", "error_code", "oldmask",
                                         "r0", "r1", "r2", "r3", "r4", "r5",
                                         "r6", "r7", "r8", "r9", "r10",
                                         "fp", "ip", "sp", "lr", "pc", "cpsr",
                                         "fault_address"};

typedef enum _cpumode_t {
    M_ARM, M_THUMB
} cpumode_t;

/* Internal state */
emu_t emu;                      /* emulator state */
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
void emu_singlestep(uint32_t pc);

uint8_t emu_regs_tainted();

extern const char* emu_disasm_ref(uint32_t pc, uint8_t bits);
const darm_t* emu_disasm(uint32_t pc);
const darm_t* emu_disasm_internal(darm_t * d, uint32_t pc);

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

static void dbg_dump_ucontext(ucontext_t *uc);
static void emu_dump();
static void emu_dump_diff();
static void emu_dump_cpsr();
void armv7_dump(const darm_t *d);
static inline uint32_t emu_read_reg(darm_reg_t reg);
static inline uint32_t *emu_write_reg(darm_reg_t reg);
static inline uint8_t emu_thumb_mode();

static void emu_map_dump(map_t *m);
static void emu_map_parse();
static map_t* emu_map_lookup(uint32_t addr);

static void emu_advance_pc();
static uint32_t emu_dump_taintmaps();
void emu_set_taint_mem(uint32_t addr, uint32_t tag);
static uint32_t emu_get_taint_mem(uint32_t addr);
static inline void emu_set_taint_reg(uint32_t reg, uint32_t tag);
static inline uint32_t emu_get_taint_reg(uint32_t reg);
static void mmap_init();

static inline uint32_t instr_mask(darm_instr_t instr);

/* Page Protections */

static int32_t getPageSize();
static uint32_t getAlignedPage(uint32_t addr);
static void mprotectHandler(int sig, siginfo_t *si, void *ucontext);
static void mprotectInit();
static void mprotectPage(uint32_t addr, uint32_t flags);

static void emu_protect_mem();
static void emu_unprotect_mem();
static int emu_mark_page(uint32_t addr);
static int emu_unmark_page(uint32_t addr);
static void emu_clear_taintpages();

/* ARM manual util functions */
void SelectInstrSet(cpumode_t mode);
cpumode_t CurrentInstrSet();
cpumode_t TargetInstrSet(uint32_t instr);
void BranchWritePC(uint32_t addr);
void BXWritePC(uint32_t addr);

#endif  /* _INCLUDE_ANEMU_PRIVATE_H_ */
